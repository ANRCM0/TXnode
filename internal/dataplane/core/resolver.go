package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolver constructors: core.NewResolver @0x7a9c80, core.newResolver @0x7a9fa0,
// core.withPort @0x7a9e60, core.chain.LookupNetIP @0x7aa6e0,
// core.(*dohResolver).query @0x7aa8e0 / LookupNetIP @0x7ab820.
//
// Accepted forms (REPORT.md §8.3, §20.6, §19.5-5; features/dns):
//
//	system                       -> the Go system resolver
//	8.8.8.8 / 8.8.8.8:5353       -> plain DNS over UDP (port 53 by default)
//	udp://8.8.8.8                -> plain DNS over UDP
//	tcp://8.8.8.8                -> plain DNS over TCP
//	tls://dns.google             -> DoT (also tcp-tls://)
//	https://dns.google/dns-query -> DoH, POST application/dns-message
//
// Unknown schemes report `DNS server %q: unknown scheme %q` (0xf9c... observed
// string). A comma-separated list is a serial failover chain
// (node.dnsResolver @0xca7c80 splits on "," then tail-calls NewResolver).

// DNS strategies (dns_strategy, default ipv4_first). The exact validation string
// lives in conf: "dns_strategy must be ipv4_first, ipv4_only, ipv6_first or
// ipv6_only, got %q".
const (
	StrategyIPv4First = "ipv4_first"
	StrategyIPv4Only  = "ipv4_only"
	StrategyIPv6First = "ipv6_first"
	StrategyIPv6Only  = "ipv6_only"
)

// dnsEntry is core.dnsEntry @0xe58240: ips []netip.Addr, expires time.Time.
type dnsEntry struct {
	ips     []netip.Addr
	expires time.Time
}

// NewResolver compiles a resolver spec. cacheTTL is dns_cache_time (the config
// value is in minutes; the caller converts). A zero/negative TTL uses the
// documented 10 minute default.
func NewResolver(spec, strategy string, cacheTTL time.Duration) (Resolver, error) {
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	switch strategy {
	case StrategyIPv4First, StrategyIPv4Only, StrategyIPv6First, StrategyIPv6Only:
	default:
		strategy = StrategyIPv4First
	}
	if cacheTTL <= 0 {
		cacheTTL = 10 * time.Minute
	}

	var parts []string
	for _, p := range strings.Split(spec, ",") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		// default_dns empty = system resolver (features/dns).
		parts = []string{"system"}
	}
	ch := make(chain, 0, len(parts))
	for _, part := range parts {
		r, err := newResolver(part)
		if err != nil {
			return nil, err
		}
		ch = append(ch, r)
	}
	var res Resolver = ch
	res = &strategyResolver{next: res, strategy: strategy}
	res = newCacheResolver(res, cacheTTL)
	return res, nil
}

// withPort adds the default port to a DNS server address; IPv6 literals are
// bracketed (core.withPort @0x7a9e60).
func withPort(host, port string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(a.String(), port)
	}
	// A bare IPv6 literal without a port, e.g. 2001:db8::1.
	if strings.Count(host, ":") > 1 {
		return net.JoinHostPort(host, port)
	}
	return host + ":" + port
}

// newResolver parses one server spec (core.newResolver @0x7a9fa0).
func newResolver(spec string) (Resolver, error) {
	s := strings.TrimSpace(spec)
	if s == "" || strings.EqualFold(s, "system") {
		return &systemResolver{}, nil
	}
	scheme, rest, hasScheme := strings.Cut(s, "://")
	if !hasScheme {
		return &dnsResolver{network: "udp", server: withPort(s, "53")}, nil
	}
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "udp":
		return &dnsResolver{network: "udp", server: withPort(rest, "53")}, nil
	case "tcp":
		return &dnsResolver{network: "tcp", server: withPort(rest, "53")}, nil
	case "tls", "tcp-tls", "dot":
		name := ""
		if i := strings.IndexByte(rest, '#'); i >= 0 {
			name = rest[i+1:]
			rest = rest[:i]
		}
		return &dnsResolver{network: "tcp-tls", server: withPort(rest, "853"), tlsName: name}, nil
	case "https":
		if !strings.Contains(rest, "/") {
			rest += "/dns-query"
		}
		return &dohResolver{url: "https://" + rest}, nil
	default:
		return nil, fmt.Errorf("DNS server %q: unknown scheme %q", s, scheme)
	}
}

// systemResolver uses net.DefaultResolver and therefore the host's resolv.conf.
type systemResolver struct{}

func (systemResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// dnsResolver is one plain DNS server over UDP or TCP (optionally DoT through
// the same code path, as miekg/dns supports "tcp-tls").
type dnsResolver struct {
	network string
	server  string
	tlsName string
}

func (r *dnsResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	qtypes := queryTypes(network)
	var out []netip.Addr
	for _, qt := range qtypes {
		ips, err := r.query(ctx, qt, host)
		if err != nil {
			if len(qtypes) > 1 {
				continue
			}
			return nil, err
		}
		out = append(out, ips...)
	}
	return out, nil
}

func (r *dnsResolver) query(ctx context.Context, qtype uint16, host string) ([]netip.Addr, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true

	client := &dns.Client{Net: r.network, Timeout: 5 * time.Second}
	if r.network == "tcp-tls" {
		name := r.tlsName
		if name == "" {
			if h, _, err := net.SplitHostPort(r.server); err == nil {
				name = h
			}
		}
		client.TLSConfig = &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}
	}
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 && d < client.Timeout {
			client.Timeout = d
		}
	}
	resp, _, err := client.ExchangeContext(ctx, msg, r.server)
	if err != nil {
		return nil, err
	}
	return answerAddrs(resp, qtype), nil
}

// dohResolver is core.dohResolver: POST application/dns-message to the URL.
type dohResolver struct {
	url    string
	client *http.Client // nil = default client (system trust store)
}

func (r *dohResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	qtypes := queryTypes(network)
	var out []netip.Addr
	for _, qt := range qtypes {
		ips, err := r.query(ctx, qt, host)
		if err != nil {
			if len(qtypes) > 1 {
				continue
			}
			return nil, err
		}
		out = append(out, ips...)
	}
	return out, nil
}

// query implements core.(*dohResolver).query @0x7aa8e0: a POST with
// Content-Type application/dns-message, as observed in REPORT.md §23.1.
func (r *dohResolver) query(ctx context.Context, qtype uint16, host string) ([]netip.Addr, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true
	body, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	client := r.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNS over HTTPS server answered %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(raw); err != nil {
		return nil, err
	}
	return answerAddrs(out, qtype), nil
}

// queryTypes maps a LookupNetIP network argument to the DNS qtypes, in the
// order the strategy wants them queried. REPORT.md §23.1 shows the default
// ipv4_first issuing AAAA first and A second; the returned order is used for
// result ordering (v4 first), which is what "ipv4_first" means.
func queryTypes(network string) []uint16 {
	switch network {
	case "ip4":
		return []uint16{dns.TypeA}
	case "ip6":
		return []uint16{dns.TypeAAAA}
	default:
		return []uint16{dns.TypeA, dns.TypeAAAA}
	}
}

func answerAddrs(msg *dns.Msg, qtype uint16) []netip.Addr {
	if msg == nil {
		return nil
	}
	var out []netip.Addr
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if qtype != dns.TypeA && qtype != 0 {
				continue
			}
			if a, ok := netip.AddrFromSlice(v.A); ok {
				out = append(out, a.Unmap())
			}
		case *dns.AAAA:
			if qtype != dns.TypeAAAA && qtype != 0 {
				continue
			}
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

// chain is core.chain: a serial failover list (core.chain.LookupNetIP
// @0x7aa6e0). The first resolver that answers with at least one address wins.
type chain []Resolver

func (c chain) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var lastErr error
	for _, r := range c {
		ips, err := r.LookupNetIP(ctx, network, host)
		if err != nil {
			lastErr = err
			continue
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

// strategyResolver applies dns_strategy: it decides which families are queried
// and in what order results are returned.
type strategyResolver struct {
	next     Resolver
	strategy string
}

func (s *strategyResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if network == "ip4" || network == "ip6" {
		return s.next.LookupNetIP(ctx, network, host)
	}
	switch s.strategy {
	case StrategyIPv4Only:
		return s.next.LookupNetIP(ctx, "ip4", host)
	case StrategyIPv6Only:
		return s.next.LookupNetIP(ctx, "ip6", host)
	case StrategyIPv6First:
		v4, err4 := s.next.LookupNetIP(ctx, "ip4", host)
		v6, err6 := s.next.LookupNetIP(ctx, "ip6", host)
		return joinAddrs(v6, v4, err6, err4)
	default: // ipv4_first
		v6, err6 := s.next.LookupNetIP(ctx, "ip6", host)
		v4, err4 := s.next.LookupNetIP(ctx, "ip4", host)
		return joinAddrs(v4, v6, err4, err6)
	}
}

func joinAddrs(first, second []netip.Addr, errFirst, errSecond error) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(first)+len(second))
	out = append(out, first...)
	out = append(out, second...)
	if len(out) == 0 {
		if errFirst != nil {
			return nil, errFirst
		}
		if errSecond != nil {
			return nil, errSecond
		}
	}
	return out, nil
}

// cacheResolver caches successful lookups for TTL (dns_cache_time).
type cacheResolver struct {
	next Resolver
	ttl  time.Duration
	mu   sync.Mutex
	m    map[string]dnsEntry
}

func newCacheResolver(next Resolver, ttl time.Duration) *cacheResolver {
	return &cacheResolver{next: next, ttl: ttl, m: make(map[string]dnsEntry)}
}

func (c *cacheResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	key := strings.ToLower(host) + "|" + network
	now := time.Now()
	c.mu.Lock()
	e, ok := c.m[key]
	c.mu.Unlock()
	if ok && now.Before(e.expires) {
		return append([]netip.Addr(nil), e.ips...), nil
	}
	ips, err := c.next.LookupNetIP(ctx, network, host)
	if err != nil || len(ips) == 0 {
		return ips, err
	}
	c.mu.Lock()
	c.m[key] = dnsEntry{ips: append([]netip.Addr(nil), ips...), expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return ips, nil
}
