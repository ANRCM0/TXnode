package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// SOCKS5 address header at the head of every mux stream.
//
// Evidence: notes/rev-transport.md §4.2: readStreamRequest 0x774de0 calls
// github.com/ANRCM0/TX-Node/internal/dataplane/socks.ReadAddr 0x771f80; the append side is
// socks.AppendAddr 0x772780. The transport packages keep their own copy (the
// shared socks package is owned by the kernel side).
const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// sing-mux caf09fe32475: UDP streams optionally carry an address per packet.
const (
	FlagUDP  = 1 << 0
	FlagAddr = 1 << 1
	FlagMux  = FlagAddr // Historical name retained for source compatibility.
)

// WriteStreamRequest writes [flags BE16][SOCKS5 address].
func WriteStreamRequest(w io.Writer, flags uint16, a socks.Addr) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], flags)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(AppendAddr(nil, a))
	return err
}

// ReadStreamRequest reads the two flag bytes and the address.
func ReadStreamRequest(r io.Reader) (flags uint16, a socks.Addr, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, socks.Addr{}, err
	}
	flags = binary.BigEndian.Uint16(hdr[:])
	if flags & ^uint16(FlagUDP|FlagAddr) != 0 || flags&FlagAddr != 0 && flags&FlagUDP == 0 {
		return 0, socks.Addr{}, fmt.Errorf("mux: invalid stream flags 0x%x", flags)
	}
	a, err = ReadAddr(r)
	return flags, a, err
}

// ReadAddr reads a SOCKS5 address from r.
func ReadAddr(r io.Reader) (socks.Addr, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return socks.Addr{}, err
	}
	var host string
	switch b[0] {
	case atypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return socks.Addr{}, err
		}
		host = netip.AddrFrom4(ip).String()
	case atypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return socks.Addr{}, err
		}
		host = netip.AddrFrom16(ip).String()
	case atypDomain:
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return socks.Addr{}, err
		}
		name := make([]byte, int(b[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return socks.Addr{}, err
		}
		host = string(name)
	default:
		return socks.Addr{}, fmt.Errorf("socks: malformed address")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return socks.Addr{}, err
	}
	return socks.Addr{Host: host, Port: binary.BigEndian.Uint16(port[:])}, nil
}

// AppendAddr appends the SOCKS5 encoding of a.
func AppendAddr(b []byte, a socks.Addr) []byte {
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			b = append(b, atypIPv4)
			v := ip.As4()
			b = append(b, v[:]...)
		} else {
			b = append(b, atypIPv6)
			v := ip.As16()
			b = append(b, v[:]...)
		}
	} else {
		name := a.Host
		if len(name) > 255 {
			name = name[:255]
		}
		b = append(b, atypDomain, byte(len(name)))
		b = append(b, name...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port)
}
