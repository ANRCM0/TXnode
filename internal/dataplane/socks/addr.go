// Package socks holds the address type shared by every protocol in kaze.
//
// Evidence: core.Session.Dest is socks.Addr (rev-core.md §2.1, offset +0x08),
// and proto packages read Host/Port from it. The binary's Addr keeps a domain
// as a string and only resolves it through Addr.IP() when a literal address is
// available.
package socks

import (
	"net"
	"net/netip"
	"strconv"
)

// Addr is a proxy destination. Host is either an IP literal or a domain.
type Addr struct {
	Host string
	Port uint16
}

// IsZero reports whether the address is unset.
func (a Addr) IsZero() bool { return a.Host == "" && a.Port == 0 }

// String renders host:port, bracketing IPv6 literals.
func (a Addr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

// IP returns the address as a netip.Addr when Host is an IP literal, otherwise
// the zero Addr. Mirrors socks.Addr.IP in the binary: parse, do not resolve.
func (a Addr) IP() netip.Addr {
	ip, err := netip.ParseAddr(a.Host)
	if err != nil {
		return netip.Addr{}
	}
	return ip
}

// IsDomain reports whether Host needs resolution.
func (a Addr) IsDomain() bool { return a.Host != "" && !a.IP().IsValid() }

// FromNetAddr converts a net.Addr (typically *net.TCPAddr / *net.UDPAddr).
func FromNetAddr(n net.Addr) Addr {
	switch v := n.(type) {
	case *net.TCPAddr:
		return Addr{Host: v.IP.String(), Port: uint16(v.Port)}
	case *net.UDPAddr:
		return Addr{Host: v.IP.String(), Port: uint16(v.Port)}
	}
	host, port, err := net.SplitHostPort(n.String())
	if err != nil {
		return Addr{Host: n.String()}
	}
	p, _ := strconv.ParseUint(port, 10, 16)
	return Addr{Host: host, Port: uint16(p)}
}

// FromAddrPort converts netip.AddrPort.
func FromAddrPort(ap netip.AddrPort) Addr {
	return Addr{Host: ap.Addr().String(), Port: ap.Port()}
}

// AddrPort returns the destination as netip.AddrPort when Host is a literal.
func (a Addr) AddrPort() netip.AddrPort {
	ip := a.IP()
	if !ip.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip, a.Port)
}
