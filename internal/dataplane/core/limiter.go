package core

import (
	"context"
	"sync"
	"time"
)

// Limiter is the token bucket recovered from (*Limiter).reserve (rev-core.md
// §4.2): tokens grow by elapsed*rate, burst capacity is 0.25*rate, and a
// negative balance converts to a wait duration.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	tokens float64
	last   time.Time
}

// NewLimiter returns a limiter at rate bytes/s. Rate 0 means unlimited.
func NewLimiter(rate int64) *Limiter {
	l := &Limiter{rate: float64(rate), last: time.Now()}
	if rate > 0 {
		l.tokens = 0.25 * float64(rate)
	}
	return l
}

// SetRate updates the rate; zero disables limiting. Existing burst is clamped
// to the new 0.25*rate ceiling exactly as reserve() does.
func (l *Limiter) SetRate(rate int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = float64(rate)
	if l.rate <= 0 {
		l.tokens = 0
		return
	}
	cap := 0.25 * l.rate
	if l.tokens > cap {
		l.tokens = cap
	}
	l.last = time.Now()
}

// Rate reports the configured bytes/s.
func (l *Limiter) Rate() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

// Reserve accounts n bytes and returns how long the caller must wait before
// sending them. The original returns a duration; callers sleep on it.
func (l *Limiter) Reserve(n int64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rate <= 0 {
		return 0
	}
	now := time.Now()
	if !l.last.IsZero() {
		dt := now.Sub(l.last).Seconds()
		if dt > 0 {
			l.tokens += dt * l.rate
		}
	}
	l.last = now
	cap := 0.25 * l.rate
	if l.tokens > cap {
		l.tokens = cap
	}
	l.tokens -= float64(n)
	if l.tokens >= 0 {
		return 0
	}
	wait := (-l.tokens / l.rate) * float64(time.Second)
	l.tokens = 0
	return time.Duration(wait)
}

// Wait blocks until n bytes may be sent, honouring ctx.
func (l *Limiter) Wait(ctx context.Context, n int64) error {
	d := l.Reserve(n)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// mbpsToBytes converts the panel's Mbps figure to bytes/s, matching
// core.mbpsToBytes (1024-based, 1/8).
func mbpsToBytes(mbps int) int64 {
	if mbps <= 0 {
		return 0
	}
	return int64(mbps) * 1024 * 1024 / 8
}
