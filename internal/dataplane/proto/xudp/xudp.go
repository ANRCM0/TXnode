// Package xudp implements kaze's UDP-over-stream framing.
//
// Frame layout (REPORT.md §17.3.1, addresses 0xb3200e/0xb84528):
//
//	LEN(2B BE) || BODY
//	BODY[0:2]  stream/echo port BE16 (0 on the first packet)
//	BODY[2]    cmd: 1=first, 2=continuation, 3=EOF, 4=continue
//	BODY[3]    flags (only bit0 is consumed)
//	BODY[4]    address-present marker, always 0x02
//	BODY[5:7]  destination port BE16   ┐ only when BODY[4]==2
//	BODY[7]    ATYP 1=IPv4 2=domain 3=IPv6 ├
//	BODY[8:]   address bytes            ┘
//
// This is not Xray's XUDP (no userUUID/globalID/padding): kaze speaks its own
// framing and does not interoperate with Xray clients.
package xudp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Command values.
const (
	CmdFirst        = 1
	CmdContinuation = 2
	CmdEOF          = 3
	CmdContinue     = 4
)

const (
	atypIPv4   = 1
	atypDomain = 2
	atypIPv6   = 3

	addrMarker = 0x02
	maxFrame   = 65535
)

// ErrTCPStream is returned when a multiplexed TCP stream is carried without an
// address: "xudp: multiplexed TCP streams are not supported".
var ErrTCPStream = errors.New("xudp: multiplexed TCP streams are not supported")

// Stream adapts an ordered byte stream to core.PacketStream.
type Stream struct {
	rw    io.ReadWriter
	conn  net.Conn // optional, for deadlines
	first bool
	last  socks.Addr
}

// New wraps rw. The first frame must carry an address.
func New(rw io.ReadWriter) *Stream {
	s := &Stream{rw: rw, first: true}
	if c, ok := rw.(net.Conn); ok {
		s.conn = c
	}
	return s
}

// ReadPacket reads one datagram into p and returns its source/destination
// address. It never returns more than len(p).
func (s *Stream) ReadPacket(p []byte) (int, socks.Addr, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(s.rw, hdr[:]); err != nil {
		return 0, socks.Addr{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 5 || n > maxFrame {
		return 0, socks.Addr{}, errors.New("xudp: bad frame length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(s.rw, body); err != nil {
		return 0, socks.Addr{}, err
	}
	cmd := body[2]
	if cmd == CmdEOF {
		return 0, socks.Addr{}, io.EOF
	}
	addr := s.last
	off := 5
	if body[4] == addrMarker {
		if n < 8 {
			return 0, socks.Addr{}, errors.New("xudp: truncated address")
		}
		a, used, err := readAddr(body[5:])
		if err != nil {
			return 0, socks.Addr{}, err
		}
		addr = a
		off = 5 + used
	} else if s.first {
		// A first frame without an address is a TCP stream marker.
		return 0, socks.Addr{}, ErrTCPStream
	}
	s.first = false
	s.last = addr
	payload := body[off:]
	if len(payload) > len(p) {
		payload = payload[:len(p)]
	}
	copy(p, payload)
	return len(payload), addr, nil
}

// WritePacket writes one datagram. The address is omitted for continuation
// packets after the first, matching the address marker rule.
func (s *Stream) WritePacket(p []byte, addr socks.Addr) error {
	body := make([]byte, 0, 5+1+2+16+len(p))
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], addr.Port)
	cmd := byte(CmdContinuation)
	if s.first {
		cmd = CmdFirst
		s.first = false
	}
	body = append(body, 0, 0) // stream port
	body = append(body, cmd, 0, 0)
	if addr.Host != "" {
		body[4] = addrMarker
		body = append(body, port[:]...)
		body = appendAddr(body, addr)
	}
	body = append(body, p...)
	if len(body) > maxFrame {
		return errors.New("xudp: packet too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(body)))
	if _, err := s.rw.Write(hdr[:]); err != nil {
		return err
	}
	_, err := s.rw.Write(body)
	return err
}

// Close closes the underlying conn when it is one.
func (s *Stream) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	if c, ok := s.rw.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// readAddr parses [port BE16][atyp][addr] and returns the consumed length.
func readAddr(b []byte) (socks.Addr, int, error) {
	if len(b) < 3 {
		return socks.Addr{}, 0, errors.New("xudp: short address")
	}
	port := binary.BigEndian.Uint16(b[0:2])
	atyp := b[2]
	switch atyp {
	case atypIPv4:
		if len(b) < 3+4 {
			return socks.Addr{}, 0, errors.New("xudp: short IPv4")
		}
		return socks.Addr{Host: net.IP(b[3:7]).String(), Port: port}, 3 + 4, nil
	case atypIPv6:
		if len(b) < 3+16 {
			return socks.Addr{}, 0, errors.New("xudp: short IPv6")
		}
		return socks.Addr{Host: net.IP(b[3:19]).String(), Port: port}, 3 + 16, nil
	case atypDomain:
		if len(b) < 4 {
			return socks.Addr{}, 0, errors.New("xudp: short domain")
		}
		l := int(b[3])
		if len(b) < 4+l {
			return socks.Addr{}, 0, errors.New("xudp: short domain")
		}
		return socks.Addr{Host: string(b[4 : 4+l]), Port: port}, 4 + l, nil
	}
	return socks.Addr{}, 0, errors.New("xudp: unknown address type")
}

func appendAddr(dst []byte, a socks.Addr) []byte {
	ip := a.IP()
	switch {
	case ip.Is4():
		dst = append(dst, atypIPv4)
		v := ip.As4()
		return append(dst, v[:]...)
	case ip.Is6():
		dst = append(dst, atypIPv6)
		v := ip.As16()
		return append(dst, v[:]...)
	default:
		dst = append(dst, atypDomain, byte(len(a.Host)))
		return append(dst, a.Host...)
	}
}
