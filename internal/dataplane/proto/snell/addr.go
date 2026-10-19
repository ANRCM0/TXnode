package snell

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Address encoding for the CONNECT first chunk and for UDP packet chunks:
// SOCKS5 type numbers (1 IPv4, 3 domain, 4 IPv6) plus a big-endian port.
// UNVERIFIED: the sample's address codec inside the chunk was not decoded
// (notes/rev-proto-udp.md §7 item 6).

func encodeAddr(a socks.Addr) []byte {
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			v4 := ip.As4()
			out := append([]byte{1}, v4[:]...)
			return binary.BigEndian.AppendUint16(out, a.Port)
		}
		v6 := ip.As16()
		out := append([]byte{4}, v6[:]...)
		return binary.BigEndian.AppendUint16(out, a.Port)
	}
	out := append([]byte{3, byte(len(a.Host))}, a.Host...)
	return binary.BigEndian.AppendUint16(out, a.Port)
}

var errBadAddr = errors.New("snell: bad destination address")

func decodeAddr(b []byte) (socks.Addr, int, error) {
	if len(b) < 1 {
		return socks.Addr{}, 0, errBadAddr
	}
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return socks.Addr{}, 0, errBadAddr
		}
		return socks.Addr{Host: net.IP(b[1:5]).String(), Port: binary.BigEndian.Uint16(b[5:7])}, 7, nil
	case 4:
		if len(b) < 19 {
			return socks.Addr{}, 0, errBadAddr
		}
		return socks.Addr{Host: net.IP(b[1:17]).String(), Port: binary.BigEndian.Uint16(b[17:19])}, 19, nil
	case 3:
		if len(b) < 2 || len(b) < 2+int(b[1])+2 {
			return socks.Addr{}, 0, errBadAddr
		}
		l := int(b[1])
		return socks.Addr{Host: string(b[2 : 2+l]), Port: binary.BigEndian.Uint16(b[2+l : 2+l+2])}, 2 + l + 2, nil
	}
	return socks.Addr{}, 0, fmt.Errorf("snell: unknown address type %d", b[0])
}
