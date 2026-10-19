package ctransport

// ShadowTLS v3 client.
//
// The client borrows a real site's TLS handshake through the shadow server and
// then switches to a tagged record layer. The proof lives in the last four bytes
// of the 32-byte ClientHello session id: HMAC-SHA256(password, hello[5:72])[:4]
// (verifyClientHello @0xac5f60). crypto/tls already emits a 32-byte session id,
// so a small wrapper rewrites those four bytes on the first write instead of
// hand-rolling a TLS stack.
//
// UNVERIFIED: the record HMAC covers the payload only in this implementation.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// DialShadowTLS connects to the shadow server at addr, performs the borrowed
// TLS handshake for host and switches to the tagged record layer.
func DialShadowTLS(ctx context.Context, network, addr, host, password string) (net.Conn, error) {
	if network == "" {
		network = "tcp"
	}
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	sni := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		sni = h
	}
	key := []byte(password)
	session := make([]byte, 32)
	if _, err := rand.Read(session); err != nil {
		raw.Close()
		return nil, err
	}
	spec := &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS13,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       []uint16{utls.TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{0},
		GetSessionID: func([]byte) [32]byte {
			var out [32]byte
			copy(out[:], session)
			return out
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: sni},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.Ed25519, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
		},
	}
	cfg := &utls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: utls.VersionTLS13, MaxVersion: utls.VersionTLS13}
	uc := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uc.ApplyPreset(spec); err != nil {
		raw.Close()
		return nil, err
	}
	if err := uc.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, err
	}
	if err := uc.MarshalClientHelloNoECH(); err != nil {
		raw.Close()
		return nil, err
	}
	hello := uc.HandshakeState.Hello
	if len(hello.Raw) < 72 || len(hello.SessionId) != 32 {
		raw.Close()
		return nil, errors.New("shadow-tls: unexpected ClientHello shape")
	}
	// Record header + handshake bytes; the proof covers record[5:72].
	record := make([]byte, 5+len(hello.Raw))
	record[0], record[1], record[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(hello.Raw)))
	copy(record[5:], hello.Raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(record[5:72])
	sum := mac.Sum(nil)
	copy(record[72:76], sum[:4])
	// Keep the marshaled form and the field view in sync.
	copy(hello.Raw[67:71], sum[:4])
	copy(hello.SessionId[28:32], sum[:4])

	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	// Switch record: an empty tagged application-data record.
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x04}
	mac = hmac.New(sha256.New, key)
	mac.Write(nil)
	sum = mac.Sum(nil)
	if _, err := raw.Write(append(hdr, sum[:4]...)); err != nil {
		raw.Close()
		return nil, err
	}
	return &shadowClientConn{Conn: raw, tag: key}, nil
}

type shadowClientConn struct {
	net.Conn
	tag []byte
	buf []byte
}

func (c *shadowClientConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > 0x4000 {
			n = 0x4000
		}
		if err := shadowWrite(c.Conn, p[:n], c.tag); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *shadowClientConn) CloseWrite() error {
	_, _ = c.Conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00})
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *shadowClientConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c.Conn, hdr); err != nil {
			return 0, err
		}
		if hdr[0] == 0x15 {
			return 0, io.EOF
		}
		if hdr[0] != 0x17 {
			return 0, errors.New("shadow-tls: unexpected record type")
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		if n < 4 || n > 0x4004 {
			return 0, errors.New("shadow-tls: short record")
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.Conn, payload); err != nil {
			return 0, err
		}
		mac := hmac.New(sha256.New, c.tag)
		mac.Write(payload[4:])
		sum := mac.Sum(nil)
		if !hmac.Equal(sum[:4], payload[:4]) {
			return 0, errors.New("shadow-tls: record does not verify")
		}
		c.buf = payload[4:]
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func shadowWrite(w io.Writer, data, key []byte) error {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sum := mac.Sum(nil)
	hdr := []byte{0x17, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(data)+4))
	buf := make([]byte, 0, 5+4+len(data))
	buf = append(buf, hdr...)
	buf = append(buf, sum[:4]...)
	buf = append(buf, data...)
	_, err := w.Write(buf)
	return err
}

var _ = strings.TrimSpace
