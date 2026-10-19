package core

import (
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// Guard is the invalid_access_* brute-force brake (REPORT.md §21.3,
// notes/rev-core.md §5.5):
//
//	invalid_access_enable          default false
//	invalid_access_count           default 30 failures
//	invalid_access_duration        default 60 s counting window
//	invalid_access_forbidden_time  default 600 s ban
//
// core.(*Guard).Blocked @0x7a2c40 and core.(*Guard).Fail @0x7a2e20 keep a
// per-key (failures, window) pair and delete the entry once the ban expires.
// The granularity is the source address; IPv6 is counted per prefix so rotating
// addresses inside a /64 does not reset the counter (features/limits), which is
// the same device_ipv6_prefix rule Tracker.deviceKey uses.

// GuardConfig is the invalid_access_* quartet. IPv6Prefix mirrors
// device_ipv6_prefix (default 64) for the ban key; zero means 64.
type GuardConfig struct {
	Enable     bool
	Count      int
	Duration   int // seconds, counting window
	Forbidden  int // seconds, ban duration
	IPv6Prefix int
}

type guardEntry struct {
	fails  int
	window time.Time // start of the current counting window
	until  time.Time // ban expiry; zero when not banned
}

// Guard implements the brute-force brake. The zero value is disabled.
type Guard struct {
	mu      sync.Mutex
	cfg     GuardConfig
	log     *slog.Logger
	entries map[string]*guardEntry
}

// NewGuard builds the brake. A nil logger falls back to slog.Default.
func NewGuard(cfg GuardConfig, log *slog.Logger) *Guard {
	if cfg.Count <= 0 {
		cfg.Count = 30
	}
	if cfg.Duration <= 0 {
		cfg.Duration = 60
	}
	if cfg.Forbidden <= 0 {
		cfg.Forbidden = 600
	}
	if cfg.IPv6Prefix <= 0 || cfg.IPv6Prefix > 128 {
		cfg.IPv6Prefix = 64
	}
	if log == nil {
		log = slog.Default()
	}
	return &Guard{cfg: cfg, log: log, entries: make(map[string]*guardEntry)}
}

// Enabled reports whether the brake is on.
func (g *Guard) Enabled() bool { return g != nil && g.cfg.Enable }

// key normalises the source address: IPv6 collapses to device_ipv6_prefix.
func (g *Guard) key(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	a := addr
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is6() {
		if p, err := a.Prefix(g.cfg.IPv6Prefix); err == nil {
			return p.String()
		}
	}
	return a.String()
}

// Blocked reports whether addr is currently banned (core.(*Guard).Blocked
// @0x7a2c40). Expired entries are deleted on the way out.
func (g *Guard) Blocked(addr netip.Addr) bool {
	if !g.Enabled() {
		return false
	}
	key := g.key(addr)
	if key == "" {
		return false
	}
	now := time.Now()
	window := time.Duration(g.cfg.Duration) * time.Second
	forbidden := time.Duration(g.cfg.Forbidden) * time.Second
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[key]
	if e == nil {
		return false
	}
	if !e.until.IsZero() {
		if now.Before(e.until) {
			return true
		}
		delete(g.entries, key)
		return false
	}
	// No ban: drop the counter once the counting window is over.
	if now.Sub(e.window) > window+forbidden {
		delete(g.entries, key)
	}
	return false
}

// Failed records one authentication failure (core.(*Guard).Fail @0x7a2e20). On
// reaching the threshold the address is banned and the observed warning is
// logged: "address banned after repeated authentication failures" ip=… for=…
func (g *Guard) Failed(addr netip.Addr) {
	if !g.Enabled() {
		return
	}
	key := g.key(addr)
	if key == "" {
		return
	}
	now := time.Now()
	window := time.Duration(g.cfg.Duration) * time.Second
	forbidden := time.Duration(g.cfg.Forbidden) * time.Second
	g.mu.Lock()
	e := g.entries[key]
	if e == nil {
		e = &guardEntry{window: now}
		g.entries[key] = e
	}
	if !e.window.IsZero() && now.Sub(e.window) > window {
		// Window elapsed: start a new one.
		e.fails = 0
		e.window = now
	}
	e.fails++
	banned := false
	if e.fails >= g.cfg.Count {
		e.fails = 0
		e.window = now
		e.until = now.Add(forbidden)
		banned = true
	}
	g.mu.Unlock()
	if banned {
		g.log.Warn("address banned after repeated authentication failures",
			"ip", key, "for", forbidden)
	}
}

// Succeeded clears the failure counter after a successful handshake.
func (g *Guard) Succeeded(addr netip.Addr) {
	if !g.Enabled() {
		return
	}
	key := g.key(addr)
	if key == "" {
		return
	}
	g.mu.Lock()
	delete(g.entries, key)
	g.mu.Unlock()
}

// Fail is the name used by the original symbol (core.(*Guard).Fail).
func (g *Guard) Fail(addr netip.Addr) { g.Failed(addr) }
