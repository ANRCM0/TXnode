package mieru

import (
	"sync"
	"time"
)

// scanGate is the probe-rate limiter that keeps an attacker from using the
// unhinted path as an oracle. Evidence: (*Handler).identify @0x7d8160 calls
// scanGate_allow @0x7d8b40 before an unhinted scan, and the type's methods are
// allow/refill/spent (notes/rev-proto-udp.md §3.2).
//
// UNVERIFIED: the budget's numbers were not extracted. The defaults below allow a
// short burst then one attempt per second, which bounds the work an unauthenticated
// peer can force.
const (
	defaultScanRate  = 1.0 // tokens per second
	defaultScanBurst = 8.0 // maximum accumulated tokens
)

// scanGate is a token bucket shared by every connection of the handler.
type scanGate struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

func newScanGate(rate, burst float64) scanGate {
	if rate <= 0 {
		rate = defaultScanRate
	}
	if burst <= 0 {
		burst = defaultScanBurst
	}
	return scanGate{tokens: burst, last: time.Now(), rate: rate, burst: burst}
}

// refill adds the tokens accrued since the last call.
func (g *scanGate) refill(now time.Time) {
	if g.last.IsZero() {
		g.last = now
		return
	}
	elapsed := now.Sub(g.last).Seconds()
	if elapsed <= 0 {
		return
	}
	g.tokens += elapsed * g.rate
	if g.tokens > g.burst {
		g.tokens = g.burst
	}
	g.last = now
}

// allow reports whether one scan may proceed and consumes a token if so.
func (g *scanGate) allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refill(time.Now())
	if g.tokens < 1 {
		return false
	}
	g.tokens--
	return true
}

// spent consumes a token after a scan that was not pre-authorized.
func (g *scanGate) spent() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refill(time.Now())
	if g.tokens > 0 {
		g.tokens--
	}
}

// available reports the current budget without consuming it (tests, logs).
func (g *scanGate) available() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refill(time.Now())
	return g.tokens
}
