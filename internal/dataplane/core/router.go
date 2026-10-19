package core

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Router implements core.(*Router) (type @0xec1b60, size 0x38) and the
// resolution order of (*Router).Route @0x7ad740:
//
//  1. BlockBitTorrent: a BitTorrent destination ("bittorrent" host marker, or the
//     sniffed protocol handed to RouteProto) is refused without any DNS or rule
//     lookup. REPORT.md §17.2.1/§24.3, notes/rev-core.md §3.2.
//  2. BlockPrivate: a private/loopback destination is refused with the reason
//     "private address" (REPORT.md §20.6, notes/rev-core.md §5.5).
//  3. Linear scan over Rules; the first match wins (no weights, no longest
//     match) — (*Router).route @0x7adbc0.
//  4. The requested name (sniffed SNI/Host, else the destination host) is
//     matched a second time against the same table — core.requestedName
//     @0x7adb60.
//  5. The default outbound, or direct when none is configured.

// NewRouter returns an empty rule table with an outbound map.
func NewRouter() *Router {
	return &Router{Outbounds: make(map[string]Outbound)}
}

// SetOutbound registers a named outbound. Keys are the values of
// "outbound = <name>" in routes files and the tags of custom_outbounds
// (notes/rev-round2b-core.md §2.2: four mapassign sites into Router+0x20).
func (r *Router) SetOutbound(name string, ob Outbound) {
	if r.Outbounds == nil {
		r.Outbounds = make(map[string]Outbound)
	}
	r.Outbounds[name] = ob
	if name == r.Default {
		r.fallbackDefault = ob
	}
}

// SetDefault sets the fallback outbound name. An empty name means direct.
// "[default] outbound=direct" is special-cased by node (it warns), so core only
// stores a name; a missing name makes Route report
// `default outbound %q is not defined` (features/routing).
func (r *Router) SetDefault(name string) {
	r.Default = name
	if name == "" {
		r.fallbackDefault = nil
		return
	}
	r.fallbackDefault = r.Outbounds[name]
}

// Route resolves a destination using the requested name derived from dest.Host
// and the sniffed domain. See RouteProto for protocol-aware matching.
func (r *Router) Route(network string, dest socks.Addr, domain string) (Decision, error) {
	return r.routeWith(network, "", dest, domain)
}

// RouteProto is Route with the sniffed protocol ("tls", "http", "quic",
// "bittorrent" or ""), which is what a "protocol:" match term needs.
//
// UNVERIFIED: the original (*Router).Route argument list was not fully
// recovered; the recon notes show Rule.match looking up a protocol-keyed map,
// so the sniffed protocol must reach the matcher somehow. Keeping it as an
// explicit argument leaves the contract signature (Route) untouched.
func (r *Router) RouteProto(network, proto string, dest socks.Addr, domain string) (Decision, error) {
	return r.routeWith(network, proto, dest, domain)
}

func (r *Router) routeWith(network, proto string, dest socks.Addr, domain string) (Decision, error) {
	if r == nil {
		return Decision{Action: ActionDirect}, nil
	}
	if r.BlockBitTorrent && (proto == "bittorrent" || strings.EqualFold(dest.Host, "bittorrent")) {
		return Decision{}, &ErrBlocked{Rule: "bittorrent"}
	}
	if r.BlockPrivate {
		if ip := dest.IP(); ip.IsValid() && isPrivate(ip) {
			return Decision{}, &ErrBlocked{Rule: "private address"}
		}
	}

	// First pass: the raw destination host (lower-cased).
	host := strings.ToLower(dest.Host)
	if d, ok, err := r.route(network, proto, dest, host); err != nil {
		return Decision{}, err
	} else if ok {
		if d.Action == ActionBlock {
			return Decision{}, &ErrBlocked{Rule: d.Name}
		}
		return d, nil
	}
	// Second pass: the requested name, i.e. the sniffed SNI/Host when present.
	name := RequestedName(dest.Host, domain)
	if name != "" && name != host {
		if d, ok, err := r.route(network, proto, dest, name); err != nil {
			return Decision{}, err
		} else if ok {
			if d.Action == ActionBlock {
				return Decision{}, &ErrBlocked{Rule: d.Name}
			}
			return d, nil
		}
	}
	if r.Default != "" {
		ob := r.Outbounds[r.Default]
		if ob == nil {
			ob = r.fallbackDefault
		}
		if ob == nil {
			return Decision{}, fmt.Errorf("default outbound %q is not defined", r.Default)
		}
		return Decision{Action: ActionProxy, Outbound: ob, Name: r.Default}, nil
	}
	return Decision{Action: ActionDirect}, nil
}

// route is the linear first-match scan (core.(*Router).route @0x7adbc0).
func (r *Router) route(network, proto string, dest socks.Addr, domain string) (Decision, bool, error) {
	for _, rule := range r.Rules {
		if rule == nil || !rule.matches(network, proto, dest, domain) {
			continue
		}
		switch rule.Action {
		case ActionBlock:
			return Decision{Action: ActionBlock, Name: rule.Name}, true, nil
		case ActionProxy:
			ob := r.Outbounds[rule.Outbound]
			if ob == nil {
				// The original reports the missing outbound instead of silently
				// going direct: "rule <name>: outbound '<x>' is not available"
				// (concatstring5 @0x7addf1).
				return Decision{}, false, fmt.Errorf("rule %s: outbound '%s' is not available", rule.Name, rule.Outbound)
			}
			return Decision{Action: ActionProxy, Outbound: ob, Name: rule.Name}, true, nil
		case ActionDNS:
			return Decision{Action: ActionDNS, Resolver: rule.Resolver, Name: rule.Name}, true, nil
		default:
			return Decision{Action: ActionDirect, Name: rule.Name}, true, nil
		}
	}
	return Decision{}, false, nil
}

// IPAllowed filters DNS answers before dialling (REPORT.md §21.5):
// (*Router).IPAllowed @0x7adf40 is called from Dialer.ResolveWith for every
// candidate address. Private destinations stay refused when BlockPrivate is on,
// and a matching blocking IP rule refuses the address.
func (r *Router) IPAllowed(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if r == nil {
		return true
	}
	if r.BlockPrivate && isPrivate(ip) {
		return false
	}
	for _, rule := range r.Rules {
		if rule == nil || len(rule.ranges.ranges) == 0 {
			continue
		}
		if !rule.ranges.contains(ip) {
			continue
		}
		if rule.Action == ActionBlock {
			return false
		}
		// A matching non-block rule decides the address; stop scanning.
		return true
	}
	return true
}

// isPrivate is core.isPrivate @0x7ae060: loopback, RFC1918, link-local, ULA,
// multicast and the unspecified address are all "private" for audit purposes
// (REPORT.md §20.6: 127.0.0.1 is blocked with reason "private address").
func isPrivate(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}
