package trojan

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// The RFC 1928 address codec. The binary shares one reader across protocols
// (github.com/ANRCM0/TX-Node/internal/dataplane/socks.ReadAddr is called from the Trojan handshake at
// @0xb30548 and from the shadowsocks handshake at @0xb190a2); proto packages keep
// their own copy so they stay independent.

const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

var errBadAddr = ErrMalformed

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
