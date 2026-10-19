package shadowsocks

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// The RFC 1928 address codec, shared by the shadowsocks request header (the
// binary calls github.com/ANRCM0/TX-Node/internal/dataplane/socks.ReadAddr @0xb190a2) and the UDP datagrams.
// Copied per package so the protocols stay independent.

const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

var errBadAddr = errCorruptPayload

// ReadAddr reads ATYP + address + port from r.
func ReadAddr(r io.Reader) (socks.Addr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return socks.Addr{}, err
	}
	var host string
	switch atyp[0] {
	case atypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return socks.Addr{}, err
		}
		host = net.IP(ip[:]).String()
	case atypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return socks.Addr{}, err
		}
		host = net.IP(ip[:]).String()
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return socks.Addr{}, err
		}
		name := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return socks.Addr{}, err
		}
		host = string(name)
	default:
		return socks.Addr{}, errBadAddr
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return socks.Addr{}, err
	}
	return socks.Addr{Host: host, Port: binary.BigEndian.Uint16(port[:])}, nil
}

// ReadAddrFrom decodes an address from the front of b and reports how many bytes
// it consumed.
func ReadAddrFrom(b []byte) (socks.Addr, int, error) {
	if len(b) < 1 {
		return socks.Addr{}, 0, io.ErrUnexpectedEOF
	}
	switch b[0] {
	case atypIPv4:
		if len(b) < 7 {
			return socks.Addr{}, 0, io.ErrUnexpectedEOF
		}
		return socks.Addr{Host: net.IP(b[1:5]).String(), Port: binary.BigEndian.Uint16(b[5:7])}, 7, nil
	case atypIPv6:
		if len(b) < 19 {
			return socks.Addr{}, 0, io.ErrUnexpectedEOF
		}
		return socks.Addr{Host: net.IP(b[1:17]).String(), Port: binary.BigEndian.Uint16(b[17:19])}, 19, nil
	case atypDomain:
		if len(b) < 2 {
			return socks.Addr{}, 0, io.ErrUnexpectedEOF
		}
		n := int(b[1])
		if len(b) < 2+n+2 {
			return socks.Addr{}, 0, io.ErrUnexpectedEOF
		}
		return socks.Addr{
			Host: string(b[2 : 2+n]),
			Port: binary.BigEndian.Uint16(b[2+n : 2+n+2]),
		}, 2 + n + 2, nil
	}
	return socks.Addr{}, 0, errBadAddr
}

// appendAddr appends the wire form of a to dst.
func appendAddr(dst []byte, a socks.Addr) []byte {
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			v4 := ip.As4()
			dst = append(dst, atypIPv4)
			dst = append(dst, v4[:]...)
			return binary.BigEndian.AppendUint16(dst, a.Port)
		}
		v6 := ip.As16()
		dst = append(dst, atypIPv6)
		dst = append(dst, v6[:]...)
		return binary.BigEndian.AppendUint16(dst, a.Port)
	}
	if len(a.Host) > 255 {
		a.Host = a.Host[:255]
	}
	dst = append(dst, atypDomain, byte(len(a.Host)))
	dst = append(dst, a.Host...)
	return binary.BigEndian.AppendUint16(dst, a.Port)
}

// addrLen returns the wire length of an address.
func addrLen(a socks.Addr) int {
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			return 7
		}
		return 19
	}
	return 2 + len(a.Host) + 2
}
