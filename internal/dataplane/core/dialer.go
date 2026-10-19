package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Dialer is core.Dialer. DialTCPFrom @0x7a0c40, ResolveWith @0x79fbe0.
//
// ResolveWith's fifth argument is *core.Router (REPORT.md §21.5): every address
// returned by the resolver is passed through (*Router).IPAllowed before it is
// dialled, so domain rules and IP/CIDR rules are chained (resolve first, then
// filter by IP rules). The original calls the injected resolver as
// Fn(ctx, "ip", host) — see the indirect call at 0x79fe82 in
// notes/rev-round2b-core.md §1.3.

// Dialer carries the dial timeout. A nil Receiver still works with the zero
// timeout (no extra deadline beyond ctx).
type Dialer struct {
	timeout time.Duration
}

// NewDialer returns a dialer with the given timeout (zero = ctx only).
func NewDialer(timeout time.Duration) *Dialer {
	return &Dialer{timeout: timeout}
}

// ResolveWith resolves dest and keeps only the addresses Router.IPAllowed
// accepts. A literal destination address is returned as-is (still filtered).
//
// UNVERIFIED: the error text for "every answer was filtered" was not recovered;
// it is modelled after the other relay strings ("blocked", "dial failed").
func (d *Dialer) ResolveWith(ctx context.Context, dest socks.Addr, res Resolver, rt *Router) ([]netip.Addr, error) {
	if ip := dest.IP(); ip.IsValid() {
		if rt != nil && !rt.IPAllowed(ip) {
			return nil, fmt.Errorf("blocked: %s", ip)
		}
		return []netip.Addr{ip}, nil
	}
	host := strings.TrimSpace(dest.Host)
	if host == "" {
		return nil, fmt.Errorf("missing destination host")
	}
	if res == nil {
		res = net.DefaultResolver
	}
	ips, err := res.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		ip = ip.Unmap()
		if rt != nil && !rt.IPAllowed(ip) {
			continue
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no address for %s is allowed by the routing rules", host)
	}
	return out, nil
}

// DialTCPFrom dials dest, binding the node-side source address when local is
// valid (auto_out_ip). Candidates are tried in resolution order; the last dial
// error is returned when none works.
func (d *Dialer) DialTCPFrom(ctx context.Context, local netip.Addr, dest socks.Addr, res Resolver, rt *Router) (net.Conn, error) {
	ctx, cancel := d.withTimeout(ctx)
	if cancel != nil {
		defer cancel()
	}
	ips, err := d.ResolveWith(ctx, dest, res, rt)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		nd := net.Dialer{}
		if la := localAddr(local, ip, "tcp"); la != nil {
			nd.LocalAddr = la
		}
		conn, err := nd.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, dest.Port).String())
		if err != nil {
			last = err
			continue
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			KeepAlive(tc)
		}
		return conn, nil
	}
	if last == nil {
		last = fmt.Errorf("dial %s: no address", dest.String())
	}
	return nil, last
}

// DialUDPFrom dials a connected UDP socket to dest after the same resolve and
// IPAllowed filtering as DialTCPFrom. Used by the datagram relay when a session
// has no PacketStream of its own (QUIC/servePackets paths).
func (d *Dialer) DialUDPFrom(ctx context.Context, local netip.Addr, dest socks.Addr, res Resolver, rt *Router) (net.Conn, error) {
	ctx, cancel := d.withTimeout(ctx)
	if cancel != nil {
		defer cancel()
	}
	ips, err := d.ResolveWith(ctx, dest, res, rt)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		nd := net.Dialer{}
		if la := localAddr(local, ip, "udp"); la != nil {
			nd.LocalAddr = la
		}
		conn, err := nd.DialContext(ctx, "udp", netip.AddrPortFrom(ip, dest.Port).String())
		if err != nil {
			last = err
			continue
		}
		return conn, nil
	}
	if last == nil {
		last = fmt.Errorf("dial udp %s: no address", dest.String())
	}
	return nil, last
}

// localAddr builds the TCP/UDP local address for the candidate family.
func localAddr(local, dest netip.Addr, network string) net.Addr {
	if !local.IsValid() {
		return nil
	}
	if local.Is4() != dest.Is4() {
		return nil
	}
	ip := net.IP(local.AsSlice())
	if network == "udp" {
		return &net.UDPAddr{IP: ip}
	}
	return &net.TCPAddr{IP: ip}
}

// withTimeout applies the dialer timeout unless ctx already has an earlier
// deadline. The returned cancel is nil when no child context was created.
func (d *Dialer) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if d == nil || d.timeout <= 0 {
		return ctx, nil
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= d.timeout {
		return ctx, nil
	}
	return context.WithTimeout(ctx, d.timeout)
}
