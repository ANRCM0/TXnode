package singbox

import (
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
	"net"
	"net/netip"
	"time"
)

// NewConnTrackerWithBoundedUsage is a prototype producer/consumer opt-in. No
// Service calls it and it does not install credentials or authorize admission.
func NewConnTrackerWithBoundedUsage(session usagev2.Session, users map[string]int, journal *usageinterval.Journal) (*ConnTracker, error) {
	collector, err := usageinterval.New(session, users, journal)
	if err != nil {
		return nil, err
	}
	tracker := NewConnTracker(0)
	tracker.SetUserMap(users)
	tracker.boundedUsage = collector
	return tracker, nil
}

func (t *ConnTracker) FlushBoundedUsage() (*usagev2.Submission, error) {
	if t.boundedUsage == nil {
		return nil, usageinterval.ErrUnknown
	}
	return t.boundedUsage.Flush()
}
func (t *ConnTracker) CloseBoundedUsage() {
	if t.boundedUsage != nil {
		t.boundedUsage.Close()
	}
}

// boundedTCPView intentionally implements neither CountReader/CountWriter nor
// Upstream. Pinned sing recursively unwraps counter interfaces independent of
// Replaceable flags; returning the same counter-bearing trackedConn is unsafe.
// No exported embedded raw connection is available on this explicit view.
type boundedTCPView struct{ base *trackedConn }

func (c *boundedTCPView) Read(p []byte) (int, error)         { return c.base.Read(p) }
func (c *boundedTCPView) Write(p []byte) (int, error)        { return c.base.Write(p) }
func (c *boundedTCPView) Close() error                       { return c.base.Close() }
func (c *boundedTCPView) LocalAddr() net.Addr                { return c.base.LocalAddr() }
func (c *boundedTCPView) RemoteAddr() net.Addr               { return c.base.RemoteAddr() }
func (c *boundedTCPView) SetDeadline(t time.Time) error      { return c.base.SetDeadline(t) }
func (c *boundedTCPView) SetReadDeadline(t time.Time) error  { return c.base.SetReadDeadline(t) }
func (c *boundedTCPView) SetWriteDeadline(t time.Time) error { return c.base.SetWriteDeadline(t) }
func (c *boundedTCPView) ReaderReplaceable() bool            { return false }
func (c *boundedTCPView) WriterReplaceable() bool            { return false }

func (c *boundedTCPView) ReportTargetIP(address netip.Addr) { c.base.ReportTargetIP(address) }

// EnableEnforcingBounded is Service's explicit policy before first connection.
// The isolated prototype constructor alone retains its original v1 behavior.
func (t *ConnTracker) EnableEnforcingBounded() bool {
	if t == nil || t.boundedUsage == nil {
		return false
	}
	t.usersMu.Lock()
	defer t.usersMu.Unlock()
	if len(t.connMap) != 0 || t.enforceBounded {
		return false
	}
	t.enforceBounded = true
	return true
}
func (t *ConnTracker) CheckBoundedUsage() error {
	if t == nil || t.boundedUsage == nil {
		return usageinterval.ErrUnknown
	}
	return t.boundedUsage.CheckCurrent()
}
func (t *ConnTracker) StopBoundedUsageTraffic() {
	if t == nil || t.boundedUsage == nil {
		return
	}
	t.boundedUsage.Fail()
	t.usersMu.RLock()
	var closers []trackedConnection
	for _, connection := range t.connMap {
		closers = append(closers, connection)
	}
	t.usersMu.RUnlock()
	for _, connection := range closers {
		_ = connection.closer.Close()
	}
}

func (s *SingBox) SetBoundedUsageTracker(tracker *ConnTracker) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tracker == nil || !tracker.enforceBounded || s.box != nil || s.connTracker != nil || s.boundedPrepared != nil || s.localEventConsumer != nil {
		return false
	}
	s.boundedPrepared = tracker
	return true
}
func (s *SingBox) FlushBoundedUsage() (*usagev2.Submission, error) {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil, usageinterval.ErrUnknown
	}
	return ct.FlushBoundedUsage()
}
func (s *SingBox) CheckBoundedUsage() error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return usageinterval.ErrUnknown
	}
	return ct.CheckBoundedUsage()
}
func (s *SingBox) StopBoundedUsageTraffic() {
	ct := s.connTrackerSafe()
	if ct != nil {
		ct.StopBoundedUsageTraffic()
	}
}
