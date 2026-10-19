package core

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// Trust is core.Trust (@0xe1cf40): a prefix table built from trusted_proxies.
// ParseTrust @0x7bc3a0, (*Trust).Allows @0x7bc980.
//
// The default value is "private,cloudflare" (REPORT.md §11.7, notes/rev-core.md
// §6.2): "private" covers RFC1918 / loopback / ULA / link-local, "cloudflare"
// the published Cloudflare edge ranges. Anything else is an IP or CIDR and must
// be listed explicitly by the operator.
type Trust struct {
	prefixes []netip.Prefix
}

// DefaultTrustedProxies is the documented default value.
const DefaultTrustedProxies = "private,cloudflare"

var privateTrustPrefixes = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// Cloudflare's published edge ranges (cloudflare.com/ips).
var cloudflareTrustPrefixes = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// ParseTrust compiles a trusted_proxies value. An empty value installs the
// default "private,cloudflare"; the parser accepts keyword aliases, bare IPs and
// CIDRs. Errors carry the key name so conf.validate can quote them.
func ParseTrust(s string) (*Trust, error) {
	if strings.TrimSpace(s) == "" {
		s = DefaultTrustedProxies
	}
	t := &Trust{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch strings.ToLower(part) {
		case "private":
			if err := t.appendAll(privateTrustPrefixes); err != nil {
				return nil, err
			}
		case "cloudflare":
			if err := t.appendAll(cloudflareTrustPrefixes); err != nil {
				return nil, err
			}
		default:
			p, err := parsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("trusted_proxies: %q is not an IP or a CIDR", part)
			}
			t.prefixes = append(t.prefixes, p)
		}
	}
	return t, nil
}

func (t *Trust) appendAll(list []string) error {
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return err
		}
		t.prefixes = append(t.prefixes, p.Masked())
	}
	return nil
}

// Allows reports whether addr is a trusted peer (core.(*Trust).Allows
// @0x7bc980). A nil Trust trusts nothing, which is the safe interpretation for
// a missing configuration.
func (t *Trust) Allows(addr netip.Addr) bool {
	if t == nil || !addr.IsValid() {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// AllowsAddrPort is the netip.AddrPort form used by the PROXY protocol path.
func (t *Trust) AllowsAddrPort(ap netip.AddrPort) bool {
	return t.Allows(ap.Addr())
}

// DefaultRealIPHeaders is the documented example for trusted_x_forwarded_for
// (features/realip): "CF-Connecting-IP,X-Forwarded-For", first non-empty wins.
// The actual list comes from configuration.
var DefaultRealIPHeaders = []string{"CF-Connecting-IP", "X-Forwarded-For"}

// RealIP resolves the client address from proxy headers. Headers are honoured
// only when peer is in the trusted_proxies table (features/realip: "headers and
// PROXY protocol are honoured only when the peer is in trusted_proxies").
//
// UNVERIFIED: REPORT.md §8.5 and notes/rev-core.md §6.3 record that
// trusted_x_forwarded_for has a configuration field but no consumer could be
// located in the binary's core/node packages. This helper is the natural
// consumer for the header-based transports; it is not called from the TCP
// kernel path, which only trusts the PROXY protocol.
func (t *Trust) RealIP(peer netip.Addr, h http.Header, names []string) netip.Addr {
	if h == nil || !t.Allows(peer) {
		return peer
	}
	for _, name := range names {
		v := strings.TrimSpace(h.Get(name))
		if v == "" {
			continue
		}
		// X-Forwarded-For is a list: the first element is the client.
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		if a, err := netip.ParseAddr(v); err == nil {
			return a
		}
	}
	return peer
}
