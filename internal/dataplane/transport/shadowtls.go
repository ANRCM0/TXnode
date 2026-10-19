package transport

// ShadowTLS v3 (server side).
//
// Evidence recovered from the sample:
//   - ParseShadowTLS @0xac5960 accepts only version=3 and requires host= and
//     password= in the plugin options ("shadow-tls needs host= and password= in
//     the plugin options", "shadow-tls version %s is not supported; kaze serves
//     version 3, so set version=3").
//   - (*ShadowTLS).verifyClientHello @0xac5f60 requires len>=0x4c, b[0]=0x16,
//     b[5]=1 (ClientHello) and b[0x2b]=0x20 (32-byte session id), then compares
//     HMAC-SHA256(password, hello[5:72])[:4] with hello[72:76].
//   - (*ShadowTLS).Wrap @0xac6720 verifies the hello, dials host and relays the
//     handshake (5 s timeout).
//   - (*shadowTLSConn).Read @0xac7b60 accepts records of type 0x15/0x17 only
//     and reports "shadow-tls: short record" / "unexpected record type" /
//     "record does not verify"; Write @0xac80a0 emits type 0x17, version 0x0303,
//     and a 4-byte tag followed by the payload.
//
// UNVERIFIED: the exact bytes covered by the record HMAC (we tag the payload
// only) and whether the key is the raw password or its SHA-256. Self-interop is
// covered by tests; third-party ShadowTLS clients may differ.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

const (
	shadowRecordApp   = 0x17
	shadowRecordAlert = 0x15
	shadowMaxRecord   = 0x4000 + 4
	shadowTagLen      = 4
)

// ShadowTLS is the server-side plugin state.
type ShadowTLS struct {
	host     string
	password []byte
}

// ParseShadowTLS parses "host=…;password=…;version=3" (the plugin options).
func ParseShadowTLS(opts string) (*ShadowTLS, error) {
	vals := map[string]string{}
	for _, part := range strings.Split(opts, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		vals[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	if v := vals["version"]; v != "" && v != "3" {
		return nil, fmt.Errorf("shadow-tls version %s is not supported; kaze serves version 3, so set version=3", v)
	}
	host := vals["host"]
	password := vals["password"]
	if host == "" || password == "" {
		return nil, errors.New("shadow-tls needs host= and password= in the plugin options")
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	return &ShadowTLS{host: host, password: []byte(password)}, nil
}

// Host returns the borrowed site address.
func (s *ShadowTLS) Host() string { return s.host }

// Handler wraps the protocol handler: every connection is authenticated and
// switched to the record layer before the inner protocol sees it.
func (s *ShadowTLS) Handler(next core.Handler) core.Handler {
	return core.HandlerFunc(func(ctx context.Context, conn net.Conn) (*core.Session, error) {
		sc, err := s.Wrap(conn)
		if err != nil {
			return nil, &core.Stranger{Conn: conn, Err: err, Quiet: true}
		}
		return next.Handle(ctx, sc)
	})
}

// Wrap performs the ShadowTLS handshake on conn and returns the inner stream.
func (s *ShadowTLS) Wrap(conn net.Conn) (net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr, payload, err := readShadowRecord(conn)
	if err != nil {
		return nil, fmt.Errorf("shadow-tls: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	if !s.verifyClientHello(append(hdr, payload...)) {
		return nil, errors.New("shadow-tls: not a shadow-tls client")
	}
	host, err := net.DialTimeout("tcp", s.host, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("shadow-tls: %w", err)
	}
	// Relay the ClientHello and the rest of the handshake to the borrowed site.
	if _, err := host.Write(append(hdr, payload...)); err != nil {
		host.Close()
		return nil, err
	}
	// host -> client copier, stopped at the switch.
	stop := make(chan struct{})
	go func() {
		for {
			h, p, err := readShadowRecord(host)
			if err != nil {
				select {
				case <-stop:
				default:
					conn.Close()
				}
				return
			}
			if _, err := conn.Write(append(h, p...)); err != nil {
				return
			}
		}
	}()
	var first []byte
	for {
		h, p, err := readShadowRecord(conn)
		if err != nil {
			close(stop)
			host.Close()
			return nil, err
		}
		if h[0] == shadowRecordApp && len(p) >= shadowTagLen && s.tagOK(p[shadowTagLen:], p[:shadowTagLen]) {
			first = p[shadowTagLen:]
			break
		}
		if _, err := host.Write(append(h, p...)); err != nil {
			close(stop)
			host.Close()
			return nil, err
		}
	}
	close(stop)
	_ = host.Close()
	return &shadowTLSConn{Conn: conn, r: bytes.NewReader(first), tag: s.password}, nil
}

// verifyClientHello mirrors (*ShadowTLS).verifyClientHello @0xac5f60.
func (s *ShadowTLS) verifyClientHello(b []byte) bool {
	if len(b) < 0x4c || b[0] != 0x16 || b[5] != 1 || b[0x2b] != 0x20 {
		return false
	}
	mac := hmac.New(sha256.New, s.password)
	mac.Write(b[5:72])
	sum := mac.Sum(nil)
	return hmac.Equal(sum[:shadowTagLen], b[72:76])
}

func (s *ShadowTLS) tagOK(data, tag []byte) bool {
	mac := hmac.New(sha256.New, s.password)
	mac.Write(data)
	sum := mac.Sum(nil)
	return hmac.Equal(sum[:shadowTagLen], tag)
}

// shadowTLSConn is the record layer after the switch (shadowTLSConn @0xad30xx).
type shadowTLSConn struct {
	net.Conn
	r   io.Reader
	tag []byte
}

func (c *shadowTLSConn) CloseWrite() error {
	_, _ = c.Conn.Write([]byte{shadowRecordAlert, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00})
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *shadowTLSConn) Read(p []byte) (int, error) {
	if c.r != nil {
		n, err := c.r.Read(p)
		if err == nil && n > 0 {
			return n, nil
		}
		c.r = nil
	}
	for {
		hdr, payload, err := readShadowRecord(c.Conn)
		if err != nil {
			return 0, err
		}
		if hdr[0] == shadowRecordAlert {
			return 0, io.EOF
		}
		if len(payload) < shadowTagLen {
			return 0, errors.New("shadow-tls: short record")
		}
		if !tagEqual(c.tag, payload[shadowTagLen:], payload[:shadowTagLen]) {
			return 0, errors.New("shadow-tls: record does not verify")
		}
		data := payload[shadowTagLen:]
		n := copy(p, data)
		if n < len(data) {
			c.r = bytes.NewReader(data[n:])
		}
		return n, nil
	}
}

func (c *shadowTLSConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > 0x4000 {
			n = 0x4000
		}
		if err := writeShadowRecord(c.Conn, p[:n], c.tag); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func tagEqual(key, data, tag []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sum := mac.Sum(nil)
	return hmac.Equal(sum[:shadowTagLen], tag)
}

// readShadowRecord reads a 5-byte TLS record header and its payload.
func readShadowRecord(r io.Reader) (hdr, payload []byte, err error) {
	hdr = make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, nil, err
	}
	switch hdr[0] {
	case 0x14, shadowRecordAlert, 0x16, shadowRecordApp: // CCS, alert, handshake, app data
	default:
		return nil, nil, errors.New("shadow-tls: unexpected record type")
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n < 1 || n > shadowMaxRecord {
		return nil, nil, errors.New("shadow-tls: short record")
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, err
	}
	return hdr, payload, nil
}

// writeShadowRecord emits [0x17 0x03 0x03 len][tag4][data].
func writeShadowRecord(w io.Writer, data, key []byte) error {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sum := mac.Sum(nil)
	hdr := []byte{shadowRecordApp, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(data)+shadowTagLen))
	buf := make([]byte, 0, 5+shadowTagLen+len(data))
	buf = append(buf, hdr...)
	buf = append(buf, sum[:shadowTagLen]...)
	buf = append(buf, data...)
	_, err := w.Write(buf)
	return err
}
