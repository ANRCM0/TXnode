package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// UoT is the UDP-over-TCP packet stream used by the sp.udp-over-tcp.arpa
// destinations (core.NewUoT @0x7bcde0, (*uot).readAddr @0x7bd040,
// ReadPacket @0x7bd340, WritePacket @0x7bd5c0). notes/rev-core.md §7.3 and
// notes/rev-proto-tcp.md §B record the two v2 arpa names; the frame layout
// below is a reconstruction.
//
// UNVERIFIED: the exact v1/v2 framing was not decoded instruction by
// instruction. The implementation uses the sing-box shape the arpa names come
// from: a 2-byte big-endian length, then (v2 only) a one-byte is-connect
// marker, then a SOCKS address, then the datagram. v1 omits the marker.

var errUoTBadAddress = errors.New("udp over tcp: bad address")

// uotFrame addresses.
const (
	uotAtypIPv4   = 1
	uotAtypDomain = 3
	uotAtypIPv6   = 4
)

type uotStream struct {
	conn    net.Conn
	version int
	mu      sync.Mutex
	closed  bool
}

// NewUoT wraps conn as a PacketStream. version 2 is sp.v2.udp-over-tcp.arpa,
// version 1 is sp.udp-over-tcp.arpa.
func NewUoT(conn net.Conn, version int) PacketStream {
	if version != 2 {
		version = 1
	}
	return &uotStream{conn: conn, version: version}
}

func (u *uotStream) ReadPacket(p []byte) (int, socks.Addr, error) {
	var l [2]byte
	if _, err := io.ReadFull(u.conn, l[:]); err != nil {
		return 0, socks.Addr{}, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n == 0 {
		return 0, socks.Addr{}, fmt.Errorf("udp over tcp: empty packet")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(u.conn, body); err != nil {
		return 0, socks.Addr{}, err
	}
	if u.version == 2 {
		if len(body) < 1 || body[0] != 1 {
			return 0, socks.Addr{}, errUoTBadAddress
		}
		body = body[1:]
	}
	addr, off, err := uotReadAddr(body)
	if err != nil {
		return 0, socks.Addr{}, err
	}
	payload := body[off:]
	if len(payload) > len(p) {
		return 0, socks.Addr{}, fmt.Errorf("udp over tcp: packet too large (%d)", len(payload))
	}
	copy(p, payload)
	return len(payload), addr, nil
}

func (u *uotStream) WritePacket(p []byte, addr socks.Addr) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return net.ErrClosed
	}
	body := make([]byte, 0, len(p)+32)
	if u.version == 2 {
		body = append(body, 1) // is-connect
	}
	body = uotAppendAddr(body, addr)
	body = append(body, p...)
	if len(body) > 0xffff {
		return fmt.Errorf("udp over tcp: packet too large (%d)", len(body))
	}
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame, uint16(len(body)))
	copy(frame[2:], body)
	n, err := u.conn.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

func (u *uotStream) Close() error {
	// A writer holds mu while sending. Close the transport first to unblock it.
	err := u.conn.Close()
	u.mu.Lock()
	u.closed = true
	u.mu.Unlock()
	return err
}

// uotReadAddr decodes one SOCKS-style address and returns the bytes consumed.
func uotReadAddr(b []byte) (socks.Addr, int, error) {
	if len(b) < 1 {
		return socks.Addr{}, 0, errUoTBadAddress
	}
	switch b[0] {
	case uotAtypIPv4:
		if len(b) < 1+4+2 {
			return socks.Addr{}, 0, errUoTBadAddress
		}
		host := net.IP(b[1:5]).String()
		port := binary.BigEndian.Uint16(b[5:7])
		return socks.Addr{Host: host, Port: port}, 7, nil
	case uotAtypIPv6:
		if len(b) < 1+16+2 {
			return socks.Addr{}, 0, errUoTBadAddress
		}
		host := net.IP(b[1:17]).String()
		port := binary.BigEndian.Uint16(b[17:19])
		return socks.Addr{Host: host, Port: port}, 19, nil
	case uotAtypDomain:
		if len(b) < 2 {
			return socks.Addr{}, 0, errUoTBadAddress
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return socks.Addr{}, 0, errUoTBadAddress
		}
		host := string(b[2 : 2+l])
		port := binary.BigEndian.Uint16(b[2+l : 2+l+2])
		return socks.Addr{Host: host, Port: port}, 2 + l + 2, nil
	default:
		return socks.Addr{}, 0, errUoTBadAddress
	}
}

// uotAppendAddr encodes addr in SOCKS address form.
func uotAppendAddr(b []byte, addr socks.Addr) []byte {
	if ip := addr.IP(); ip.IsValid() {
		if ip.Is4() {
			a := ip.As4()
			b = append(b, uotAtypIPv4)
			b = append(b, a[:]...)
		} else {
			a := ip.As16()
			b = append(b, uotAtypIPv6)
			b = append(b, a[:]...)
		}
	} else {
		host := addr.Host
		if len(host) > 255 {
			host = host[:255]
		}
		b = append(b, uotAtypDomain, byte(len(host)))
		b = append(b, host...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], addr.Port)
	return append(b, port[:]...)
}

var _ = strconv.Itoa
