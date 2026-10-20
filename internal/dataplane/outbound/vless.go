package outbound

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// VLESS command bytes (REPORT.md §17.3.3): 1 TCP, 2 raw UDP, 3 mux.
const (
	vlessCmdTCP = 1
	vlessCmdUDP = 2
)

// visionFlow is the only flow the outbound accepts
// ("vless outbound: flow %q is not supported; use %s or leave it empty").
const visionFlow = "xtls-rprx-vision"

// newVLESS builds the VLESS client. Its request header is
// outbound.(*Proxy).vlessRequest @0xb76ea0; the address block is
// outbound.appendVAddr @0xb77040.
func newVLESS(s settings, o opt.Opt) (*Proxy, error) {
	addr, err := serverAddr(s, "vless")
	if err != nil {
		return nil, err
	}
	uuidStr := strings.TrimSpace(s.str(keysUUID...))
	if uuidStr == "" {
		return nil, errors.New("vless outbound needs a UUID")
	}
	uuid, err := parseUUID(uuidStr)
	if err != nil {
		return nil, fmt.Errorf("vless outbound: %w", err)
	}
	flow := strings.TrimSpace(s.str(keysFlow...))
	if enc := strings.ToLower(strings.TrimSpace(s.str("encryption"))); enc != "" && enc != "none" {
		return nil, errors.New(`vless outbound: VLESS encryption is not supported; set encryption to none and use flow instead`)
	}
	st, err := readStream(o)
	if err != nil {
		return nil, fmt.Errorf("vless outbound: %w", err)
	}
	if flow != "" {
		if flow != visionFlow {
			return nil, fmt.Errorf("vless outbound: flow %q is not supported; use %s or leave it empty", flow, visionFlow)
		}
		if st.network != "tcp" {
			return nil, fmt.Errorf("vless outbound: flow %s works on network tcp only, not %s; remove the flow or the transport", flow, st.network)
		}
		if st.security != "tls" && st.security != "reality" {
			return nil, fmt.Errorf("vless outbound: flow %s needs TLS or REALITY: set tls=true (or security to tls/reality)", flow)
		}
	}

	p := &Proxy{
		protocol: "vless",
		opt:      o,
		stream:   st,
		addr:     addr,
		uuid:     uuid,
		flow:     flow,
	}
	via, err := readVia(o)
	if err != nil {
		return nil, err
	}
	p.via = via
	return p, nil
}

// parseUUID accepts the canonical 8-4-4-4-12 form (vless.ParseUUID @0xb3c640
// strips the dashes and requires exactly 16 bytes).
func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return out, fmt.Errorf("%q is not a UUID (16 bytes in hex)", s)
	}
	copy(out[:], b)
	return out, nil
}

// vlessRequest writes the VLESS request header:
//
//	[version=0][uuid 16][addonLen=0][command][port BE16][ATYP][address]
//
// (REPORT.md §17.3.3, rev-proto-tcp.md §1.2; the server's response header is
// the two bytes [0][addonLen] with no command, §1.5).
func (p *Proxy) vlessRequest(w io.Writer, dest socks.Addr, cmd byte) error {
	// Addons are a protobuf message: field 1 (flow) as length-delimited bytes.
	var addons []byte
	if p.flow != "" {
		addons = append(addons, 0x0a, byte(len(p.flow)))
		addons = append(addons, p.flow...)
	}
	buf := make([]byte, 0, 1+16+1+len(addons)+1+2+1+len(dest.Host))
	buf = append(buf, 0) // version
	buf = append(buf, p.uuid[:]...)
	buf = append(buf, byte(len(addons)))
	buf = append(buf, addons...)
	buf = append(buf, cmd)
	var err error
	buf, err = appendVAddr(buf, dest)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// vlessStream opens the transport, writes the request and returns the conn the
// session can use.
func (p *Proxy) vlessStream(c net.Conn, dest socks.Addr) (net.Conn, error) {
	if err := p.vlessRequest(c, dest, vlessCmdTCP); err != nil {
		return nil, fmt.Errorf("vless outbound: %w", err)
	}
	// The response header is consumed lazily before the first payload byte.
	rc := &vlessRespConn{Conn: c}
	if p.flow != visionFlow {
		return rc, nil
	}
	// Vision needs the TLS record layer directly on TCP (§17.3.2); the
	// transport is either our own crypto/tls conn or ctransport's wrapper,
	// which exposes the negotiated version through TLSConn.
	if tc, ok := findTLS(c); ok && tc.ConnectionState().Version != tls.VersionTLS13 {
		c.Close()
		return nil, fmt.Errorf("vless outbound: flow %s needs TLS 1.3, and the server negotiated an older version", p.flow)
	}
	return newVisionConn(rc, p.uuid), nil
}

// findTLS unwraps to the *tls.Conn when the transport is TLS. It mirrors
// ctransport.FindTLS @0xb645c0, which vlessStream calls to decide Vision.
func findTLS(c net.Conn) (*tls.Conn, bool) {
	type unwrapper interface{ Unwrap() net.Conn }
	for i := 0; i < 8; i++ {
		if tc, ok := c.(*tls.Conn); ok {
			return tc, true
		}
		u, ok := c.(unwrapper)
		if !ok {
			return nil, false
		}
		c = u.Unwrap()
	}
	return nil, false
}

// vlessRespConn skips the two-byte VLESS response header on the first read.
type vlessRespConn struct {
	net.Conn //nolint:embedded
	once     bool
}

func (v *vlessRespConn) Read(p []byte) (int, error) {
	if !v.once {
		v.once = true
		var hdr [2]byte
		if _, err := io.ReadFull(v.Conn, hdr[:]); err != nil {
			return 0, err
		}
		if hdr[0] != 0 {
			return 0, fmt.Errorf("vless outbound: the server answered version %d", hdr[0])
		}
		if hdr[1] != 0 {
			addon := make([]byte, int(hdr[1]))
			if _, err := io.ReadFull(v.Conn, addon); err != nil {
				return 0, err
			}
		}
	}
	return v.Conn.Read(p)
}

func (v *vlessRespConn) CloseWrite() error { return core.CloseWrite(v.Conn) }

// ---------------------------------------------------------------------------
// Vision (REPORT.md §17.3.2)

// Vision frame commands. The data command is the only one the client streams;
// the end command closes the stream.
// UNVERIFIED: the sample's appendFrame writes the command from a register
// (0xb3b7dc) and endFrame's mode 1 writes 0; the exact client-side numeric
// values are not pinned by instructions, so 1/0 follow Xray Vision.
const (
	visionCmdData = 0x01
	visionCmdEnd  = 0x00
)

const (
	visionMaxPayload = 8192 // the server clamps padding to 8171-n; frames stay small
	visionPadBase    = 900
	visionPadJitter  = 500
)

// visionConn frames the payload after the VLESS header:
//
//	[cmd][len BE16][padLen high][padLen low][payload][padding]
//
// Padding is 900 + (rand16 % 500) - len when the payload is shorter than 900,
// otherwise a single random byte; the padding content is crypto/rand bytes
// (appendFrame @0xb3b620, rev-proto-tcp.md §1.4).
type visionConn struct {
	net.Conn //nolint:embedded
	uuid     [16]byte

	rerr   error
	rbuf   []byte
	rmu    bool
	closed bool
}

func newVisionConn(c net.Conn, uuid [16]byte) *visionConn {
	return &visionConn{Conn: c, uuid: uuid}
}

func (v *visionConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > visionMaxPayload {
			n = visionMaxPayload
		}
		if err := v.writeFrame(visionCmdData, p[:n], n < visionPadBase); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (v *visionConn) writeFrame(cmd byte, payload []byte, pad bool) error {
	var rnd [2]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	rv := int(binary.BigEndian.Uint16(rnd[:]))
	padLen := 0
	if pad {
		padLen = visionPadBase + rv%visionPadJitter - len(payload)
	}
	if padLen < 0 {
		padLen = 0
	}
	frame := make([]byte, 0, 5+len(payload)+padLen)
	frame = append(frame, cmd)
	frame = append(frame, byte(len(payload)>>8), byte(len(payload)))
	frame = append(frame, byte(padLen>>8), byte(padLen))
	frame = append(frame, payload...)
	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := rand.Read(padding); err != nil {
			return err
		}
		frame = append(frame, padding...)
	}
	_, err := v.Conn.Write(frame)
	return err
}

func (v *visionConn) Read(p []byte) (int, error) {
	for len(v.rbuf) == 0 {
		if v.rerr != nil {
			return 0, v.rerr
		}
		if err := v.readFrame(); err != nil {
			v.rerr = err
			return 0, err
		}
	}
	n := copy(p, v.rbuf)
	v.rbuf = v.rbuf[n:]
	return n, nil
}

func (v *visionConn) readFrame() error {
	var hdr [5]byte
	if _, err := io.ReadFull(v.Conn, hdr[:]); err != nil {
		return err
	}
	cmd := hdr[0]
	n := int(binary.BigEndian.Uint16(hdr[1:3]))
	pad := int(binary.BigEndian.Uint16(hdr[3:5]))
	if cmd == visionCmdEnd {
		return io.EOF
	}
	if cmd != visionCmdData {
		return errors.New("vless outbound: unknown Vision command")
	}
	buf := make([]byte, n+pad)
	if _, err := io.ReadFull(v.Conn, buf); err != nil {
		return err
	}
	v.rbuf = buf[:n]
	return nil
}

func (v *visionConn) CloseWrite() error {
	if v.closed {
		return nil
	}
	v.closed = true
	if err := v.writeFrame(visionCmdEnd, nil, false); err != nil {
		return err
	}
	return core.CloseWrite(v.Conn)
}
