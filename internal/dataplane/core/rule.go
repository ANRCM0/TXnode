package core

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// This file implements core.(*Rule) as recovered in notes/rev-core.md §3.1-§3.2
// and notes/rev-round2-core.md §B.4:
//
//	Rule.AddMatchGeo  @0x7abec0   (parser for the "kind:value" tokens)
//	normDomain        @0x7acd60   (lowercase, strip trailing dot / "*.")
//	parsePrefix       @0x7acde0   (ParsePrefix, falling back to ParseAddr)
//	parsePortRange    @0x7acf80   (Cut("-") + two ParseUint(_,10,16))
//	Rule.matches      @0x7ad160   (network map, then match twice)
//	Rule.match        @0x7ad580   (domains, ipSet, ports)
//	Rule.matchDomain  @0x7ad2e0   (suffixes/fulls maps, keywords, regexps)
//	ipSet.add/seal/contains @0x7a3420/0x7a3700/0x7a3c40
//
// The nine match kinds are fixed by REPORT.md §17.2.2 and the dynamic correction
// in REPORT.md §20.6: full/domain/keyword/regexp/port/ip/network/protocol/
// geosite/geoip. "network" only accepts tcp/udp; a bare CIDR is equivalent to
// "ip:"; "cidr:" is not a keyword.

// NewRule builds an empty rule. Field layout follows core.Rule (REPORT.md §17.2.2
// type @0xf18380, size 0xd8); the maps are allocated lazily by AddMatch.
func NewRule(name string, action Action) *Rule {
	return &Rule{Name: name, Action: action}
}

// normDomain normalises a domain for the full/domain sets: lower case, no
// trailing dot, and a leading "*." is removed because the suffix set already
// covers subdomains (core.normDomain @0x7acd60).
func normDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	return s
}

// parsePrefix accepts "1.2.3.0/24", "1.2.3.4" or "::1" and returns a prefix.
// Bare addresses become a /32 or /128 (core.parsePrefix @0x7acde0).
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parsePortRange parses "N" or "N-M" with ParseUint(_, 10, 16), exactly as
// core.parsePortRange @0x7acf80 does (notes/rev-round2-core.md §B.4).
func parsePortRange(s string) (portRange, error) {
	s = strings.TrimSpace(s)
	lo, hi, ok := strings.Cut(s, "-")
	from, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return portRange{}, fmt.Errorf("bad port %q", s)
	}
	if !ok {
		return portRange{from: uint16(from), to: uint16(from)}, nil
	}
	to, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil {
		return portRange{}, fmt.Errorf("bad port %q", s)
	}
	if to < from {
		return portRange{}, fmt.Errorf("bad port range %q", s)
	}
	return portRange{from: uint16(from), to: uint16(to)}, nil
}

// AddMatchGeo is the original symbol name for AddMatch
// (core.(*Rule).AddMatchGeo @0x7abec0).
func (r *Rule) AddMatchGeo(expr string) error { return r.AddMatch(expr) }

// AddMatch parses one element of a "match" list ("kind:value", or a bare CIDR /
// bare domain). Errors are reported back to the caller, which logs them and
// ignores the token (node.localRoutes / prepareRouter); a rule whose tokens all
// fail is dropped with "%s: the rule has no usable match".
func (r *Rule) AddMatch(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("empty match")
	}
	kind, value, hasKind := strings.Cut(expr, ":")
	if !hasKind {
		// Bare term. A CIDR/IP literal is an ip match (REPORT.md §20.6: a bare
		// CIDR blocks); anything else is a substring term (features/audit:
		// "example.com # substring match anywhere in the domain").
		if p, err := parsePrefix(expr); err == nil {
			r.addRange(p)
			r.noMatch = false
			return nil
		}
		r.keywords = append(r.keywords, strings.ToLower(expr))
		r.noMatch = false
		return nil
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s: empty value", kind)
	}
	switch kind {
	case "full":
		d := normDomain(value)
		if d == "" {
			return fmt.Errorf("bad domain %q", value)
		}
		if r.fulls == nil {
			r.fulls = make(map[string]struct{})
		}
		r.fulls[d] = struct{}{}
	case "domain":
		d := normDomain(value)
		if d == "" {
			return fmt.Errorf("bad domain %q", value)
		}
		if r.suffixes == nil {
			r.suffixes = make(map[string]struct{})
		}
		r.suffixes[d] = struct{}{}
	case "keyword":
		r.keywords = append(r.keywords, strings.ToLower(value))
	case "regexp":
		re, err := regexp.Compile(value)
		if err != nil {
			return fmt.Errorf("bad regexp %q", value)
		}
		r.regexps = append(r.regexps, re)
	case "port":
		for _, part := range strings.Split(value, ",") {
			pr, err := parsePortRange(part)
			if err != nil {
				return err
			}
			r.ports = append(r.ports, pr)
		}
	case "ip":
		p, err := parsePrefix(value)
		if err != nil {
			return fmt.Errorf("bad IP or CIDR %q", value)
		}
		r.addRange(p)
	case "network":
		// Dynamic correction REPORT.md §20.6: network only accepts tcp/udp.
		// The exact error is observed in dyn/ logs.
		for _, part := range strings.Split(value, ",") {
			n := strings.ToLower(strings.TrimSpace(part))
			if n != "tcp" && n != "udp" {
				return fmt.Errorf("network must be tcp or udp, got %q", strings.TrimSpace(part))
			}
			if r.protos == nil {
				r.protos = make(map[string]struct{})
			}
			r.protos[n] = struct{}{}
		}
	case "protocol":
		for _, part := range strings.Split(value, ",") {
			p := strings.ToLower(strings.TrimSpace(part))
			switch p {
			case "tls", "http", "quic", "bittorrent":
			default:
				return fmt.Errorf("protocol %q is not one kaze detects", strings.TrimSpace(part))
			}
			if r.networks == nil {
				r.networks = make(map[string]bool)
			}
			r.networks[p] = true
		}
	case "geosite":
		if err := r.addGeoSite(value); err != nil {
			return err
		}
	case "geoip":
		if err := r.addGeoIP(value); err != nil {
			return err
		}
	default:
		// "cidr:" lands here on purpose: it is not a keyword (REPORT.md §20.6).
		return fmt.Errorf("unknown match kind %q", kind)
	}
	r.noMatch = false
	return nil
}

// addRange inserts a prefix into the rule's ipSet.
func (r *Rule) addRange(p netip.Prefix) {
	r.ranges.add(p.Masked())
}

// Usable reports whether at least one token of the rule was accepted.
func (r *Rule) Usable() bool { return !r.noMatch }

// Matches is the public form of Rule.matches: network is "tcp" or "udp", dest
// is the destination and domain is the sniffed SNI/Host (may be empty).
//
// Protocol rules are evaluated by Router.RouteProto, which supplies the sniffed
// protocol; Rule.Matches alone cannot see it.
func (r *Rule) Matches(network string, dest socks.Addr, domain string) bool {
	return r.matches(network, "", dest, domain)
}

// matches evaluates every dimension of the rule. Empty dimensions are ignored;
// present dimensions must all match (features/routing: comma-separated terms
// are AND-ed), values within one dimension are OR-ed.
func (r *Rule) matches(network, proto string, dest socks.Addr, domain string) bool {
	if r == nil {
		return false
	}
	if len(r.all) > 0 {
		for _, sub := range r.all {
			if sub.matches(network, proto, dest, domain) {
				return true
			}
		}
	}
	any := false
	if len(r.protos) > 0 {
		if _, ok := r.protos[strings.ToLower(network)]; !ok {
			return false
		}
		any = true
	}
	if len(r.networks) > 0 {
		if !r.networks[strings.ToLower(proto)] {
			return false
		}
		any = true
	}
	if len(r.ports) > 0 {
		ok := false
		for _, pr := range r.ports {
			if dest.Port >= pr.from && dest.Port <= pr.to {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
		any = true
	}
	if len(r.ranges.ranges) > 0 {
		ip := dest.IP()
		if !ip.IsValid() || !r.ranges.contains(ip) {
			return false
		}
		any = true
	}
	if r.hasDomains() {
		if domain == "" {
			return false
		}
		if !r.matchDomain(strings.ToLower(domain)) {
			return false
		}
		any = true
	}
	return any
}

func (r *Rule) hasDomains() bool {
	return len(r.fulls) > 0 || len(r.suffixes) > 0 || len(r.keywords) > 0 || len(r.regexps) > 0
}

// matchDomain mirrors core.matchDomain @0x7ad2e0: two map lookups (suffix and
// full), then keyword substring and regexp evaluation.
func (r *Rule) matchDomain(d string) bool {
	if d == "" {
		return false
	}
	if r.fulls != nil {
		if _, ok := r.fulls[d]; ok {
			return true
		}
	}
	if r.suffixes != nil {
		s := d
		for {
			if _, ok := r.suffixes[s]; ok {
				return true
			}
			i := strings.IndexByte(s, '.')
			if i < 0 || i+1 >= len(s) {
				break
			}
			s = s[i+1:]
		}
	}
	for _, kw := range r.keywords {
		if strings.Contains(d, kw) {
			return true
		}
	}
	for _, re := range r.regexps {
		if re.MatchString(d) {
			return true
		}
	}
	return false
}

// --- ipSet (core.ipSet, type @0xe58100: ranges []ipRange, sorted bool) --------

// add appends one interval; seal() sorts and merges on first lookup.
func (s *ipSet) add(p netip.Prefix) {
	p = p.Masked()
	s.ranges = append(s.ranges, ipRange{from: p.Addr(), to: lastAddr(p)})
	s.sorted = false
}

// lastAddr returns the last address of a prefix (core.lastAddr @0x7a35c0).
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr()
	bits := p.Bits()
	if a.Is4() {
		v := a.As4()
		n := uint32(0)
		for i := 0; i < 4; i++ {
			n = n<<8 | uint32(v[i])
		}
		host := 32 - bits
		if host <= 0 {
			return a
		}
		n |= (uint32(1) << uint(host)) - 1
		return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}
	v := a.As16()
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(v[i])
		lo = lo<<8 | uint64(v[8+i])
	}
	host := 128 - bits
	for host > 0 {
		if host >= 64 {
			lo = ^uint64(0)
			host -= 64
		} else {
			lo |= (uint64(1) << uint(host)) - 1
			host = 0
		}
	}
	var out [16]byte
	for i := 0; i < 8; i++ {
		out[i] = byte(hi >> uint(56-8*i))
		out[8+i] = byte(lo >> uint(56-8*i))
	}
	return netip.AddrFrom16(out)
}

// seal sorts and merges overlapping/adjacent intervals (core.(*ipSet).seal).
func (s *ipSet) seal() {
	if s.sorted {
		return
	}
	if len(s.ranges) > 1 {
		sort.Slice(s.ranges, func(i, j int) bool { return s.ranges[i].from.Less(s.ranges[j].from) })
		merged := s.ranges[:1]
		for _, cur := range s.ranges[1:] {
			last := &merged[len(merged)-1]
			if reaches(last.to, cur.from) {
				if last.to.Less(cur.to) {
					last.to = cur.to
				}
				continue
			}
			merged = append(merged, cur)
		}
		s.ranges = merged
	}
	s.sorted = true
}

// reaches reports whether interval end a reaches start b (core.reaches
// @0x7a3b80), so overlapping or adjacent intervals merge.
func reaches(a, b netip.Addr) bool {
	if a.Is4() != b.Is4() {
		return false
	}
	return !b.Less(a) || a.Next() == b
}

// contains searches the sealed interval list (core.(*ipSet).contains
// @0x7a3c40). Family mismatch never matches.
func (s *ipSet) contains(ip netip.Addr) bool {
	if !ip.IsValid() || len(s.ranges) == 0 {
		return false
	}
	s.seal()
	// First interval whose from is strictly greater than ip.
	i := sort.Search(len(s.ranges), func(i int) bool { return ip.Less(s.ranges[i].from) })
	if i < len(s.ranges) && s.ranges[i].from == ip {
		return true
	}
	if i == 0 {
		return false
	}
	prev := s.ranges[i-1]
	if prev.from.Is4() != ip.Is4() {
		return false
	}
	return !ip.Less(prev.from) && !prev.to.Less(ip)
}
