package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Balancer is core.Balancer (type @0xef6220): an Outbound group with the four
// strategies observed in the panel/route configuration
// (features/routing#outbound-group, REPORT.md §8.4, notes/rev-core.md §3.5):
//
//	absent / round_robin  new connections rotate (next atomic.Uint32)
//	random                random per connection
//	failover              primary until it fails, then the next
//	least_ping            periodic probe, lowest latency first
//
// Probing: only while the group is in use, at most every probeEvery, 5 s per
// member; probe_url defaults to https://www.gstatic.com/generate_204. With a
// probe URL, dead members sort last even under the other strategies.
// core.(*Balancer).order @0x7a7220, look @0x7a7a20, ranked @0x7a8300,
// probeHTTP @0x7a7dc0.

// DefaultProbeURL is the documented probe endpoint.
const DefaultProbeURL = "https://www.gstatic.com/generate_204"

// DefaultProbeEvery is probe_interval's default (180 s, minimum 10 s).
const DefaultProbeEvery = 180 * time.Second

// Balancer implements Outbound and UDPOutbound.
type Balancer struct {
	name       string
	members    []Outbound
	strategy   string
	probeURL   string
	probeEvery time.Duration
	probeOn    bool
	next       atomic.Uint32

	mu      sync.Mutex
	rtt     []time.Duration // per member; 0 = dead/unknown
	at      time.Time
	running bool
}

// NewBalancer builds a group. strategy is one of random, round_robin,
// least_ping, failover (unknown values fall back to round_robin, matching
// "%s: unknown strategy %q, using round_robin" in node.localRoutes). An empty
// probe URL uses DefaultProbeURL and enables probing for least_ping.
func NewBalancer(name string, members []Outbound, strategy, probeURL string, every time.Duration) *Balancer {
	s := strings.ToLower(strings.TrimSpace(strategy))
	if s == "leastping" {
		s = "least_ping"
	}
	switch s {
	case "random", "round_robin", "least_ping", "failover":
	default:
		s = "round_robin"
	}
	explicitProbe := strings.TrimSpace(probeURL) != ""
	if !explicitProbe {
		probeURL = DefaultProbeURL
	}
	if every < 10*time.Second {
		if every <= 0 {
			every = DefaultProbeEvery
		} else {
			every = 10 * time.Second
		}
	}
	b := &Balancer{
		name:       name,
		members:    append([]Outbound(nil), members...),
		strategy:   s,
		probeURL:   probeURL,
		probeEvery: every,
		probeOn:    s == "least_ping" || explicitProbe,
		rtt:        make([]time.Duration, len(members)),
	}
	return b
}

// Name is the outbound tag.
func (b *Balancer) Name() string { return b.name }

// Members returns a copy of the group's members.
func (b *Balancer) Members() []Outbound { return append([]Outbound(nil), b.members...) }

// DialTCP tries the members in strategy order; a failed member is retried on the
// next one for that connection (features/routing).
func (b *Balancer) DialTCP(ctx context.Context, addr socks.Addr) (net.Conn, error) {
	if b == nil || len(b.members) == 0 {
		return nil, errors.New("the outbound group is empty")
	}
	b.lookIfDue()
	order := b.order()
	var last error
	for _, ob := range order {
		conn, err := ob.DialTCP(ctx, addr)
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("the outbound group is empty")
	}
	return nil, last
}

// DialPacket uses the first member that can carry UDP, in strategy order
// (features/routing: "UDP uses the first server in order that can carry UDP").
func (b *Balancer) DialPacket(ctx context.Context, addr socks.Addr) (PacketStream, error) {
	if b == nil || len(b.members) == 0 {
		return nil, errors.New("the outbound group is empty")
	}
	b.lookIfDue()
	for _, ob := range b.order() {
		uo, ok := ob.(UDPOutbound)
		if !ok {
			continue
		}
		st, err := uo.DialPacket(ctx, addr)
		if err == nil {
			return st, nil
		}
	}
	return nil, errors.New("no outbound in the group carries UDP")
}

// order applies the strategy (core.(*Balancer).order @0x7a7220).
func (b *Balancer) order() []Outbound {
	base := b.ranked()
	switch b.strategy {
	case "random":
		out := append([]Outbound(nil), base...)
		rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
		return out
	case "round_robin":
		if len(base) <= 1 {
			return base
		}
		n := int(b.next.Add(1)-1) % len(base)
		return append(append([]Outbound(nil), base[n:]...), base[:n]...)
	default: // failover, least_ping (ranked already puts the fastest first)
		return base
	}
}

// ranked sorts alive members by measured latency, dead members last
// (core.(*Balancer).ranked @0x7a8300). Order is preserved when nothing has been
// measured.
func (b *Balancer) ranked() []Outbound {
	b.mu.Lock()
	rtt := append([]time.Duration(nil), b.rtt...)
	b.mu.Unlock()
	out := append([]Outbound(nil), b.members...)
	measured := false
	for _, d := range rtt {
		if d > 0 {
			measured = true
			break
		}
	}
	if !measured {
		return out
	}
	idx := make([]int, len(out))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(i, j int) bool {
		a, c := rtt[idx[i]], rtt[idx[j]]
		if (a > 0) != (c > 0) {
			return a > 0 // alive first
		}
		if a > 0 && c > 0 {
			return a < c
		}
		return false
	})
	sorted := make([]Outbound, len(out))
	for i, k := range idx {
		sorted[i] = out[k]
	}
	return sorted
}

// lookIfDue starts one probe round when the group is used and the interval has
// elapsed (core.(*Balancer).lookIfDue @0x7a7780).
func (b *Balancer) lookIfDue() {
	if !b.probeOn || b.probeURL == "" {
		return
	}
	b.mu.Lock()
	if b.running || time.Since(b.at) < b.probeEvery {
		b.mu.Unlock()
		return
	}
	b.running = true
	b.mu.Unlock()
	go b.look()
}

// look probes every member in parallel and records RTTs (5 s each).
func (b *Balancer) look() {
	members := b.Members()
	rtts := make([]time.Duration, len(members))
	var wg sync.WaitGroup
	wg.Add(len(members))
	for i, ob := range members {
		go func(i int, ob Outbound) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			rtts[i] = b.probeHTTP(ctx, ob)
		}(i, ob)
	}
	wg.Wait()
	b.mu.Lock()
	b.rtt = rtts
	b.at = time.Now()
	b.running = false
	b.mu.Unlock()
}

// probeHTTP measures one member by requesting probeURL through it
// (core.(*Balancer).probeHTTP @0x7a7dc0). It returns 0 for a dead member.
func (b *Balancer) probeHTTP(ctx context.Context, ob Outbound) time.Duration {
	u, err := url.Parse(b.probeURL)
	if err != nil || u.Host == "" {
		return 0
	}
	host := u.Hostname()
	port := u.Port()
	useTLS := strings.EqualFold(u.Scheme, "https")
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	p, err := parsePort(port)
	if err != nil {
		return 0
	}
	start := time.Now()
	conn, err := ob.DialTCP(ctx, socks.Addr{Host: host, Port: p})
	if err != nil {
		return 0
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if useTLS {
		tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			return 0
		}
		conn = tc
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: kaze-probe\r\nConnection: close\r\n\r\n", path, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return 0
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[1], "2") && !strings.HasPrefix(fields[1], "3") {
		return 0
	}
	return time.Since(start)
}

func parsePort(s string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}
