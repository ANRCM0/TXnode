package usageinterval

import (
	"context"
	"errors"
	"time"
)

var ErrNativeRenewalUnsupported = errors.New("NATIVE_RENEWAL_UNSUPPORTED")

// RejectOperation latches invalid owner/replay use without completing another
// operation or touching persistence. Original evidence remains drainable.
func (c *NativeCollector) RejectOperation() {
	if c != nil {
		c.failed.Store(true)
		c.closed.Store(true)
	}
}

// RenewalTicket keeps admission paused until both accounting and the service's
// authorization deadline have moved to the same immutable generation.
type RenewalTicket interface {
	WaitQuiescent(context.Context) error
	Retire(context.Context) (time.Time, error)
	Commit(*NativeCollector) error
	Resume() error
	Abort()
}

// RenewalSuccessor accepts only the same durable owner and unchanged user map.
// The service separately verifies the signed policy and immutable grant terms.
func (c *NativeCollector) RenewalSuccessor(next *NativeCollector, boundary time.Time) bool {
	if c == nil || next == nil || c == next || c.store != next.store || next.CheckCurrent() != nil || next.ReadyAt().Before(boundary) || len(c.users) != len(next.users) {
		return false
	}
	for uuid, user := range c.users {
		if next.users[uuid] != user {
			return false
		}
	}
	return true
}

// RetireQuiescent differs from terminal Drain: a timeout, unresolved operation,
// failed completion or persistence failure cannot certify a renewal boundary.
func (c *NativeCollector) RetireQuiescent(ctx context.Context) (time.Time, error) {
	if c == nil {
		return time.Time{}, ErrUnknown
	}
	if !c.closed.CompareAndSwap(false, true) {
		return time.Time{}, ErrUnknown
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return time.Time{}, err
		}
		if c.mu.TryLock() {
			break
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-ticker.C:
		}
	}
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if c.failed.Load() || c.state.Retired || c.inflight.Load() != 0 || !time.Now().Before(c.deadline) {
		return time.Time{}, ErrPending
	}
	for _, event := range c.state.Events {
		if !event.Done || !event.Eligible {
			return time.Time{}, ErrPending
		}
	}
	// Keep the existing collector -> store lock order. TryLock allows an expiry
	// to interrupt waiting behind another owner's slow disk operation.
	for !c.store.mu.TryLock() {
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-ticker.C:
		}
	}
	defer c.store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if !time.Now().Before(c.deadline) {
		return time.Time{}, ErrUnknown
	}
	if err := c.store.seal(&c.state, 0, true); err != nil {
		c.failed.Store(true)
		return time.Time{}, err
	}
	c.state.Retired = true
	if err := c.store.saveOrRetire(&c.state); err != nil {
		c.failed.Store(true)
		return time.Time{}, err
	}
	boundary := time.Unix(c.state.StartedAt, 0)
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return boundary, nil
}
