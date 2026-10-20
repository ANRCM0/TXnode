package core

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// PROXY protocol v1/v2 support (notes/rev-core.md §5.4):
//
//	core.looksLikeProxy   @0x7a8920
//	core.peekProxyHeader  @0x7a8a60   non-blocking peek
//	core.readProxyHeader  @0x7a8d20   consume the header, return the source
//
// A connection carries the header only when the peer is listed in
// trusted_proxies (features/realip). The parser is deliberately wrapped in a
// buffered conn so that a peek can never eat the first protocol bytes: whatever
// is not consumed stays readable for the inbound protocol.

var proxyV2Sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// proxyConn buffers reads so the PROXY header can be peeked and, if absent, the
// original bytes still reach the protocol handler.
type proxyConn struct {
	net.Conn
	br      *bufio.Reader
	src     net.Addr
	hasHead bool
}

func newProxyConn(c net.Conn) *proxyConn {
	return &proxyConn{Conn: c, br: bufio.NewReaderSize(c, 4096)}
}

func (p *proxyConn) Read(b []byte) (int, error) { return p.br.Read(b) }

func (p *proxyConn) RemoteAddr() net.Addr {
	if p.src != nil {
		return p.src
	}
	return p.Conn.RemoteAddr()
}

func (p *proxyConn) CloseWrite() error { return CloseWrite(p.Conn) }

func (p *proxyConn) LocalAddr() net.Addr { return p.Conn.LocalAddr() }

// looksLikeProxy reports whether b starts with a PROXY v1 prefix or a v2
// signature (core.looksLikeProxy @0x7a8920).
func looksLikeProxy(b []byte) bool {
	if len(b) >= len(proxyV2Sig) && bytes.Equal(b[:len(proxyV2Sig)], proxyV2Sig) {
		return true
	}
	return bytes.HasPrefix(b, []byte("PROXY "))
}

// peekProxyHeader reports whether c starts with a PROXY header without consuming
// anything (core.peekProxyHeader @0x7a8a60). The returned wrapper must be used
// for all later reads: it owns the buffered bytes.
func peekProxyHeader(c net.Conn) (*proxyConn, bool) {
	pc := newProxyConn(c)
	return pc, pc.peekProxyHeader()
}

// readProxyHeader consumes a v1/v2 header from c and returns the wrapper plus
// the claimed source address (core.readProxyHeader @0x7a8d20).
func readProxyHeader(c net.Conn) (net.Conn, netip.Addr, bool, error) {
	pc := newProxyConn(c)
	src, found, err := pc.readProxyHeader()
	return pc, src, found, err
}

// peekProxyHeader reports whether a PROXY header is present without consuming
// it. It waits at most a few milliseconds for the first bytes, so a trusted
// client that speaks a normal protocol is not delayed.
func (p *proxyConn) peekProxyHeader() bool {
	b, err := p.peekN(len(proxyV2Sig))
	if len(b) >= len(proxyV2Sig) && bytes.Equal(b[:len(proxyV2Sig)], proxyV2Sig) {
		return true
	}
	if err != nil && len(b) < 6 {
		return false
	}
	return looksLikeProxy(b)
}

// peekN returns up to n buffered bytes. When fewer than n bytes are buffered it
// briefly lowers the read deadline; the caller restores the handshake deadline.
func (p *proxyConn) peekN(n int) ([]byte, error) {
	if p.br.Buffered() >= n {
		return p.br.Peek(n)
	}
	_ = p.Conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	b, err := p.br.Peek(n)
	_ = p.Conn.SetReadDeadline(time.Time{})
	if len(b) > 0 && err != nil {
		return b, err
	}
	return b, err
}

// readProxyHeader consumes a v1 or v2 header. found is false when the stream
// starts with ordinary protocol bytes; the returned conn keeps those bytes
// buffered.
func (p *proxyConn) readProxyHeader() (netip.Addr, bool, error) {
	b, _ := p.peekN(len(proxyV2Sig))
	if len(b) >= len(proxyV2Sig) && bytes.Equal(b[:len(proxyV2Sig)], proxyV2Sig) {
		src, err := p.readV2()
		return src, true, err
	}
	b6, _ := p.peekN(6)
	if len(b6) == 0 {
		return netip.Addr{}, false, nil
	}
	if !bytes.HasPrefix(b6, []byte("PROXY ")) {
		return netip.Addr{}, false, nil
	}
	line, err := p.readLine()
	if err != nil {
		return netip.Addr{}, false, err
	}
	ap, err := parseV1(line)
	if err != nil {
		return netip.Addr{}, true, err
	}
	if ap.IsValid() {
		p.src = net.TCPAddrFromAddrPort(ap)
		return ap.Addr(), true, nil
	}
	return netip.Addr{}, true, nil
}

// readLine reads one CRLF-terminated line, bounded to the v1 maximum.
func (p *proxyConn) readLine() (string, error) {
	var sb strings.Builder
	for i := 0; i < 108; i++ {
		c, err := p.br.ReadByte()
		if err != nil {
			return "", err
		}
		sb.WriteByte(c)
		if c == '\n' {
			return strings.TrimRight(sb.String(), "\r\n"), nil
		}
	}
	return "", errors.New("malformed PROXY header")
}

// parseV1 decodes "PROXY TCP4/TCP6/UNKNOWN src dst sport dport".
func parseV1(line string) (netip.AddrPort, error) {
	f := strings.Fields(line)
	if len(f) == 0 || strings.ToUpper(f[0]) != "PROXY" {
		return netip.AddrPort{}, errors.New("malformed PROXY header")
	}
	if len(f) == 2 && strings.EqualFold(f[1], "UNKNOWN") {
		return netip.AddrPort{}, nil
	}
	if len(f) != 6 {
		return netip.AddrPort{}, errors.New("malformed PROXY header")
	}
	proto := strings.ToUpper(f[1])
	if proto != "TCP4" && proto != "TCP6" {
		return netip.AddrPort{}, errors.New("malformed PROXY header")
	}
	src, err := netip.ParseAddr(f[2])
	if err != nil {
		return netip.AddrPort{}, errors.New("malformed PROXY header")
	}
	port, err := strconv.ParseUint(f[4], 10, 16)
	if err != nil {
		return netip.AddrPort{}, errors.New("malformed PROXY header")
	}
	if proto == "TCP4" && !src.Is4() {
		return netip.AddrPort{}, errors.New("malformed PROXY header")
	}
	return netip.AddrPortFrom(src, uint16(port)), nil
}

// readV2 consumes the 16-byte binary header plus its address block.
func (p *proxyConn) readV2() (netip.Addr, error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(p.br, hdr); err != nil {
		return netip.Addr{}, errors.New("malformed PROXY header")
	}
	verCmd := hdr[12]
	if verCmd>>4 != 2 {
		return netip.Addr{}, errors.New("malformed PROXY header")
	}
	fam := hdr[13]
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	body := make([]byte, n)
	if _, err := io.ReadFull(p.br, body); err != nil {
		return netip.Addr{}, errors.New("malformed PROXY header")
	}
	// LOCAL command: the addresses are the socket's own; keep the peer.
	if verCmd&0x0f == 0 {
		return netip.Addr{}, nil
	}
	switch fam {
	case 0x11: // AF_INET, STREAM
		if len(body) < 12 {
			return netip.Addr{}, errors.New("malformed PROXY header")
		}
		var a [4]byte
		copy(a[:], body[0:4])
		port := binary.BigEndian.Uint16(body[8:10])
		src := netip.AddrPortFrom(netip.AddrFrom4(a), port)
		p.src = net.TCPAddrFromAddrPort(src)
		return src.Addr(), nil
	case 0x21: // AF_INET6, STREAM
		if len(body) < 36 {
			return netip.Addr{}, errors.New("malformed PROXY header")
		}
		var a [16]byte
		copy(a[:], body[0:16])
		port := binary.BigEndian.Uint16(body[32:34])
		src := netip.AddrPortFrom(netip.AddrFrom16(a), port)
		p.src = net.TCPAddrFromAddrPort(src)
		return src.Addr(), nil
	case 0x00: // UNSPEC
		return netip.Addr{}, nil
	default:
		// Unknown family: header consumed, source unchanged.
		return netip.Addr{}, nil
	}
}
