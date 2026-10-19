package outbound

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// VLESS-style address types, used by VLESS requests, XUDP frames and the
// Trojan address block. Values are the ones read by the sample's
// outbound.appendVAddr @0xb77040 / parseVAddr @0xb84a00 and by xudp's readAddr
// (REPORT.md §17.3.1: "编码是 VLESS 风格 [port BE16][ATYP][addr]").
const (
	AtypIPv4   = 1
	AtypDomain = 2
	AtypIPv6   = 3
)

// SOCKS5 address types (RFC 1928) differ from VLESS: 0x03 is a domain.
const (
	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04
)

// appendVAddr appends port (BE16) + ATYP + address, the VLESS/XUDP layout.
func appendVAddr(b []byte, a socks.Addr) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, a.Port)
	return appendAddrBody(b, a)
}

// appendAddrBody appends ATYP + address (no port).
func appendAddrBody(b []byte, a socks.Addr) ([]byte, error) {
	ip := a.IP()
	switch {
	case ip.IsValid() && ip.Is4():
		b = append(b, AtypIPv4)
		v := ip.As4()
		return append(b, v[:]...), nil
	case ip.IsValid() && ip.Is6():
		b = append(b, AtypIPv6)
		v := ip.As16()
		return append(b, v[:]...), nil
	case a.Host == "":
		return nil, errors.New("address string too short")
	default:
		if len(a.Host) > 255 {
			return nil, errors.New("domain name too long")
		}
		b = append(b, AtypDomain, byte(len(a.Host)))
		return append(b, a.Host...), nil
	}
}

// parseVAddr reads port + ATYP + address from b and returns the address and
// the number of bytes consumed.
func parseVAddr(b []byte) (socks.Addr, int, error) {
	if len(b) < 3 {
		return socks.Addr{}, 0, errors.New("address string too short")
	}
	port := binary.BigEndian.Uint16(b)
	addr, n, err := parseAddrBody(b[2:])
	if err != nil {
		return socks.Addr{}, 0, err
	}
	addr.Port = port
	return addr, n + 2, nil
}

// parseAddrBody reads ATYP + address.
func parseAddrBody(b []byte) (socks.Addr, int, error) {
	if len(b) < 1 {
		return socks.Addr{}, 0, errors.New("address string too short")
	}
	switch b[0] {
	case AtypIPv4:
		if len(b) < 5 {
			return socks.Addr{}, 0, errors.New("IPv4 address too short")
		}
		var v [4]byte
		copy(v[:], b[1:5])
		return socks.Addr{Host: netip.AddrFrom4(v).String()}, 5, nil
	case AtypIPv6:
		if len(b) < 17 {
			return socks.Addr{}, 0, errors.New("missing IPv6 address")
		}
		var v [16]byte
		copy(v[:], b[1:17])
		return socks.Addr{Host: netip.AddrFrom16(v).String()}, 17, nil
	case AtypDomain:
		if len(b) < 2 {
			return socks.Addr{}, 0, errors.New("address string too short")
		}
		n := int(b[1])
		if len(b) < 2+n {
			return socks.Addr{}, 0, errors.New("address string too short")
		}
		return socks.Addr{Host: string(b[2 : 2+n])}, 2 + n, nil
	default:
		return socks.Addr{}, 0, fmt.Errorf("unknown address type %d", b[0])
	}
}

// appendSocksAddr appends a SOCKS5 destination (ATYP + address + port).
func appendSocksAddr(b []byte, a socks.Addr) ([]byte, error) {
	ip := a.IP()
	switch {
	case ip.IsValid() && ip.Is4():
		b = append(b, socksAtypIPv4)
		v := ip.As4()
		b = append(b, v[:]...)
	case ip.IsValid() && ip.Is6():
		b = append(b, socksAtypIPv6)
		v := ip.As16()
		b = append(b, v[:]...)
	case a.Host == "":
		return nil, errors.New("address string too short")
	default:
		if len(a.Host) > 255 {
			return nil, errors.New("domain name too long")
		}
		b = append(b, socksAtypDomain, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// parseSocksAddr reads a SOCKS5 destination and returns it with the consumed
// length.
func parseSocksAddr(b []byte) (socks.Addr, int, error) {
	if len(b) < 1 {
		return socks.Addr{}, 0, errors.New("address string too short")
	}
	var (
		addr socks.Addr
		n    int
	)
	switch b[0] {
	case socksAtypIPv4:
		if len(b) < 7 {
			return socks.Addr{}, 0, errors.New("IPv4 address too short")
		}
		var v [4]byte
		copy(v[:], b[1:5])
		addr.Host = netip.AddrFrom4(v).String()
		addr.Port = binary.BigEndian.Uint16(b[5:7])
		n = 7
	case socksAtypIPv6:
		if len(b) < 19 {
			return socks.Addr{}, 0, errors.New("missing IPv6 address")
		}
		var v [16]byte
		copy(v[:], b[1:17])
		addr.Host = netip.AddrFrom16(v).String()
		addr.Port = binary.BigEndian.Uint16(b[17:19])
		n = 19
	case socksAtypDomain:
		if len(b) < 2 {
			return socks.Addr{}, 0, errors.New("address string too short")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return socks.Addr{}, 0, errors.New("address string too short")
		}
		addr.Host = string(b[2 : 2+l])
		addr.Port = binary.BigEndian.Uint16(b[2+l:])
		n = 2 + l + 2
	default:
		return socks.Addr{}, 0, fmt.Errorf("unknown address type %d", b[0])
	}
	return addr, n, nil
}
