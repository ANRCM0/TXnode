package shadowsocks

import (
	"sync"
	"time"
)

// saltCache is shadowsocks.(*saltCache) (@0xb1a1e0 add): the replay window for
// salts. notes/rev-proto-tcp.md §4.3 observes the TTL as "delta + 0x40", i.e. the
// timestamp window plus 64 s, and both handshakes consult it
// (handshake2022 @0xb18edf, handshakeClassic @0xb18591).
type saltCache struct {
	mu        sync.Mutex
	ttl       time.Duration
	origin    time.Time
	salts     map[saltKey]int64
	oversized map[string]int64
	timer     *time.Timer
}

// Length is part of the key: salts with a common zero-padded prefix must not
// alias. Uncommon methods with longer salts use the exact string fallback.
type saltKey [33]byte

func newSaltCache(ttl time.Duration) *saltCache {
	return &saltCache{ttl: ttl, origin: time.Now()}
}

// add records a salt and reports whether it was fresh. false means "replayed".
func (c *saltCache) add(salt []byte) bool {
	if len(salt) == 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// origin retains time.Now's monotonic reading. Neither wall-clock jumps
	// nor a clock adjustment can shorten the replay window.
	now := time.Since(c.origin).Nanoseconds()
	expires := now + int64(c.ttl)
	if len(salt) <= 32 {
		var key saltKey
		key[0] = byte(len(salt))
		copy(key[1:], salt)
		if exp, ok := c.salts[key]; ok && now < exp {
			return false
		}
		if c.salts == nil {
			c.salts = make(map[saltKey]int64, 256)
		}
		c.salts[key] = expires
	} else {
		key := string(salt)
		if exp, ok := c.oversized[key]; ok && now < exp {
			return false
		}
		if c.oversized == nil {
			c.oversized = make(map[string]int64)
		}
		c.oversized[key] = expires
	}
	if c.timer == nil {
		c.timer = time.AfterFunc(c.ttl, c.expire)
	}
	return true
}

// A shared cache owns at most one pending timer, not a goroutine per handler.
// It survives handler retirement while any replay history is still live, then
// releases the maps and stops scheduling itself when the final salt expires.
func (c *saltCache) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timer = nil
	now := time.Since(c.origin).Nanoseconds()
	if next := c.pruneLocked(now); next > now {
		delay := time.Duration(next - now)
		interval := c.ttl
		if interval > time.Second {
			interval = time.Second
		}
		// Salts can expire nanoseconds apart. Avoid a full-map scan for each
		// individual expiry; delayed reclamation never extends replay admission.
		if delay < interval {
			delay = interval
		}
		c.timer = time.AfterFunc(delay, c.expire)
	}
}

func (c *saltCache) pruneLocked(now int64) int64 {
	var next int64
	for key, expires := range c.salts {
		if expires <= now {
			delete(c.salts, key)
		} else if next == 0 || expires < next {
			next = expires
		}
	}
	for key, expires := range c.oversized {
		if expires <= now {
			delete(c.oversized, key)
		} else if next == 0 || expires < next {
			next = expires
		}
	}
	// Deleting entries alone retains the high-water map allocation.
	if len(c.salts) == 0 {
		c.salts = nil
	}
	if len(c.oversized) == 0 {
		c.oversized = nil
	}
	return next
}

// Timestamp window of SIP022. notes §4.3 reads three constants out of
// handshake2022 — 30 s, 60 s and ≈61 s — which decompose as "tolerance 30 s" and
// "cache TTL = tolerance + 60 s". §2.4 of notes/protocols.md states the documented
// tolerance as ±30 s.
const (
	TimestampWindow = 30 * time.Second
	saltCacheTTL    = TimestampWindow + 64*time.Second
)

// nowUnix is a variable so tests can pin the clock.
var nowUnix = func() int64 { return time.Now().Unix() }

func (h *Handler) checkTimestamp(ts int64) bool {
	now := nowUnix()
	delta := now - ts
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta)*time.Second <= h.window
}

// classicSearch is shadowsocks.classicSearch (@0xb13260 … @0xb13740): the
// multi-user identification policy for classic AEAD. The documented policy
// (notes/protocols.md §2.4) is:
//
//  1. try the user this peer was identified as last time,
//  2. then the users active in the last 15 minutes,
//  3. finally scan the whole table — but after 10 full scans fail for one peer
//     within a minute, further scans for that peer are rate limited to one per
//     second for 10 minutes.
//
// The binary's symbols (barred/failed/slots/seen @0xb13000–@0xb13740) match that
// shape; the exact thresholds below come from the documentation.
// UNVERIFIED: the numeric thresholds (they are documentation-sourced).
type classicSearch struct {
	mu     sync.Mutex
	last   map[string]int       // peer -> user index that worked last
	seen   map[string]time.Time // peer -> last success
	fails  map[string]*failures // peer -> full-scan failures
	maxAge time.Duration
}

type failures struct {
	count int
	first time.Time
	bar   time.Time
	last  time.Time
}

func newClassicSearch() *classicSearch {
	return &classicSearch{
		last:   make(map[string]int, 64),
		seen:   make(map[string]time.Time, 64),
		fails:  make(map[string]*failures, 64),
		maxAge: 15 * time.Minute,
	}
}

// order returns the candidate indices for a peer: last-known user first.
func (s *classicSearch) order(peer string, n int) []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, 0, n)
	used := make(map[int]bool, n)
	if idx, ok := s.last[peer]; ok && idx >= 0 && idx < n {
		out = append(out, idx)
		used[idx] = true
	}
	for i := 0; i < n; i++ {
		if !used[i] {
			out = append(out, i)
		}
	}
	return out
}

// allowFullScan reports whether a full-table scan is permitted for this peer.
func (s *classicSearch) allowFullScan(peer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.fails[peer]
	if !ok {
		return true
	}
	now := time.Now()
	if !f.bar.IsZero() && now.Before(f.bar) {
		return now.Sub(f.last) >= time.Second
	}
	return true
}

func (s *classicSearch) failed(peer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	f, ok := s.fails[peer]
	if !ok || now.Sub(f.first) > time.Minute {
		f = &failures{first: now}
		s.fails[peer] = f
	}
	f.count++
	f.last = now
	if f.count >= 10 {
		f.bar = now.Add(10 * time.Minute)
		f.count = 0
		f.first = now
	}
}

func (s *classicSearch) succeeded(peer string, idx int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last[peer] = idx
	s.seen[peer] = time.Now()
	delete(s.fails, peer)
}
