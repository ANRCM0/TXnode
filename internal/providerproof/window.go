package providerproof

import (
	"errors"
	"sync"
	"time"
)

var ErrWindowUnavailable = errors.New("PROVIDER_OFFLINE_WINDOW_UNAVAILABLE")

// Window is process-local diagnostic state, not an authorization lease. Only a
// verifier can initialize it from an original signed statement. It owns no
// credential, grant, network client, timer, callback or persistent clock state.
// A failure or Close permanently terminates this instance.
type Window struct {
	mu       sync.Mutex
	proof    Proof
	key      TrustedKey
	clock    func() windowSample
	last     windowSample
	deadline time.Duration
	terminal bool
}

type windowSample struct {
	wall    time.Time
	elapsed time.Duration
}

// OpenWindow checks original signed bytes and the currently provisioned public
// trust. Its clock is private process time; callers cannot supply a UTC value or
// reuse a freely constructed Proof as authority. This never grants admission.
func (v *Verifier) OpenWindow(statement string) (*Window, error) {
	origin := time.Now()
	return v.openWindow(statement, func() windowSample {
		now := time.Now()
		return windowSample{wall: now, elapsed: now.Sub(origin)}
	})
}

func (v *Verifier) openWindow(statement string, clock func() windowSample) (*Window, error) {
	if clock == nil {
		return nil, ErrWindowUnavailable
	}
	before := clock()
	proof, err := v.VerifySignature(statement)
	if err != nil {
		return nil, err
	}
	key := v.keys[proof.KeyID].meta
	if !sampleValid(before) || key.Revoked || !insideWindow(proof, key, before.wall) {
		return nil, ErrWindowUnavailable
	}
	// The signed UTC window is at most 60 seconds. Preserve the subsecond
	// remainder; flooring now to seconds would incorrectly extend that deadline.
	remaining := time.Unix(proof.LeaseExpiresAt, 0).Sub(before.wall)
	if remaining <= 0 || remaining > 60*time.Second || before.elapsed > time.Duration(1<<63-1)-remaining {
		return nil, ErrWindowUnavailable
	}
	w := &Window{proof: proof, key: key, clock: clock, last: before, deadline: before.elapsed + remaining}
	// Crypto/JSON work cannot consume an unnoticed portion of the deadline.
	if _, err := w.Check(v); err != nil {
		return nil, err
	}
	return w, nil
}

// Check samples wall and monotonic clocks under this instance's lock and checks
// freshly supplied immutable public trust. The caller must provision/refresh
// that trust; this method neither fetches keys nor claims live Core eligibility.
// Any refusal is terminal even if the clock or key trust later recovers.
func (w *Window) Check(current *Verifier) (Proof, error) {
	if w == nil {
		return Proof{}, ErrWindowUnavailable
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.terminal || w.clock == nil {
		return Proof{}, ErrWindowUnavailable
	}
	sample := w.clock()
	key, exists := trusted{}, false
	if current != nil {
		key, exists = current.keys[w.proof.KeyID]
	}
	if !exists || !sameWindowTrust(w.key, key.meta) || key.meta.Revoked ||
		!sampleValid(sample) || sample.elapsed < w.last.elapsed || wallBefore(sample.wall, w.last.wall) ||
		sample.elapsed >= w.deadline || !insideWindow(w.proof, key.meta, sample.wall) {
		w.terminal = true
		return Proof{}, ErrWindowUnavailable
	}
	w.last = sample
	result := w.proof
	result.WindowValidation = "valid_at_observation"
	return result, nil
}

// Close seals the diagnostic instance. It does not terminate Node sessions or
// acknowledge a Core revocation; no such runtime consumer exists in this slice.
func (w *Window) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.terminal = true
}

func sampleValid(s windowSample) bool {
	return s.elapsed >= 0 && validTime(s.wall.Unix())
}

func wallBefore(a, b time.Time) bool {
	// time.Time.Before may use only the monotonic component. Compare UTC fields
	// explicitly so a wall-clock regression is checked independently.
	return a.Unix() < b.Unix() || a.Unix() == b.Unix() && a.Nanosecond() < b.Nanosecond()
}

func insideWindow(p Proof, k TrustedKey, now time.Time) bool {
	seconds := now.Unix()
	return seconds >= p.IssuedAt && seconds < p.LeaseExpiresAt && seconds >= k.NotBefore && seconds < k.NotAfter
}

func sameWindowTrust(a, b TrustedKey) bool {
	return a.ID == b.ID && a.Epoch == b.Epoch && a.SPKISHA256 == b.SPKISHA256 &&
		a.NotBefore == b.NotBefore && a.NotAfter == b.NotAfter
}
