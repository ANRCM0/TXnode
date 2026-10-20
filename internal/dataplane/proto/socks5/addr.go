package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// The SOCKS5 address codec. The binary calls github.com/ANRCM0/TX-Node/internal/dataplane/socks.ReadAddr from
// every address-bearing handshake (trojan @0xb30548, shadowsocks @0xb190a2), so
// the wire form is the RFC 1928 one: ATYP then ADDR then a big-endian port.
//
// socks.ReadAddr is a shared helper the kernel owns; this package keeps its own
// copy of the codec so proto packages stay independent of each other.

// ReadAddr reads ATYP + address + port from r.
func ReadAddr(r io.Reader) (socks.Addr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return socks.Addr{}, err
	}
	var host string
	switch atyp[0] {
	case AtypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return socks.Addr{}, err
		}
		host = net.IP(ip[:]).String()
	case AtypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return socks.Addr{}, err
		}
		host = net.IP(ip[:]).String()
	case AtypDomain:
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
	case AtypIPv4:
		if len(b) < 7 {
			return socks.Addr{}, 0, io.ErrUnexpectedEOF
		}
		return socks.Addr{Host: net.IP(b[1:5]).String(), Port: binary.BigEndian.Uint16(b[5:7])}, 7, nil
	case AtypIPv6:
		if len(b) < 19 {
			return socks.Addr{}, 0, io.ErrUnexpectedEOF
		}
		return socks.Addr{Host: net.IP(b[1:17]).String(), Port: binary.BigEndian.Uint16(b[17:19])}, 19, nil
	case AtypDomain:
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

// appendAddr appends the RFC 1928 wire form of a to dst.
func appendAddr(dst []byte, a socks.Addr) []byte {
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			v4 := ip.As4()
			dst = append(dst, AtypIPv4)
			dst = append(dst, v4[:]...)
			return binary.BigEndian.AppendUint16(dst, a.Port)
		}
		v6 := ip.As16()
		dst = append(dst, AtypIPv6)
		dst = append(dst, v6[:]...)
		return binary.BigEndian.AppendUint16(dst, a.Port)
	}
	if len(a.Host) > 255 {
		a.Host = a.Host[:255]
	}
	dst = append(dst, AtypDomain, byte(len(a.Host)))
	dst = append(dst, a.Host...)
	return binary.BigEndian.AppendUint16(dst, a.Port)
}

// reply writes the SOCKS5 reply (socks5.reply @0xb2e4a0):
// VER REP RSV ATYP BND.ADDR BND.PORT.
func reply(w io.Writer, rep byte, bnd socks.Addr) error {
	if bnd.Host == "" {
		// RFC 1928 requires an address in every reply; the binary writes the
		// literal 0.0.0.0 (@0xf596d5) when it has nothing to report.
		bnd.Host = "0.0.0.0"
	}
	buf := make([]byte, 0, 22)
	buf = append(buf, Version, rep, 0x00)
	buf = appendAddr(buf, bnd)
	_, err := w.Write(buf)
	return err
}

// parseUDPRequest decodes an RFC 1928 UDP request datagram into p (the payload)
// and returns its destination.
func parseUDPRequest(p []byte, buf []byte) (int, socks.Addr, error) {
	addr, n, err := ReadAddrFrom(buf[udpHeaderLen:])
	if err != nil {
		return 0, socks.Addr{}, err
	}
	off := udpHeaderLen + n
	if off > len(buf) {
		return 0, socks.Addr{}, io.ErrUnexpectedEOF
	}
	payload := buf[off:]
	if len(payload) > len(p) {
		return 0, socks.Addr{}, errors.New("socks5: datagram larger than the buffer")
	}
	copy(p, payload)
	return len(payload), addr, nil
}
