package core

import (
	"net/netip"
	"sync/atomic"
	"testing"
)

type trackedClose struct {
	closed atomic.Int32
	after  func()
}

func (c *trackedClose) Close() error {
	c.closed.Add(1)
	if c.after != nil {
		c.after()
	}
	return nil
}

func TestTrackerRevocationPreservesFinalTraffic(t *testing.T) {
	tr := NewTracker()
	tr.SetUsers([]User{{ID: 7, UUID: "old"}})
	c := &trackedClose{after: func() { tr.Traffic(7, 3, 5) }}
	lease, ok := tr.Acquire(7, netip.MustParseAddr("192.0.2.1"), c)
	if !ok {
		t.Fatal("initial admission failed")
	}
	tr.Traffic(7, 11, 13)
	tr.SetUsers(nil)
	if c.closed.Load() != 1 {
		t.Fatal("revocation did not close session")
	}
	if _, ok := tr.Acquire(7, netip.MustParseAddr("192.0.2.1"), nil); ok {
		t.Fatal("removed user admitted")
	}
	lease.Release()
	if got := tr.Snapshot()[7]; got != [2]int64{14, 18} {
		t.Fatalf("final traffic = %v", got)
	}
	tr.SetUsers([]User{{ID: 7, UUID: "new"}})
	if got := tr.Snapshot()[7]; got != [2]int64{14, 18} {
		t.Fatalf("readd reset counters: %v", got)
	}
}

func TestTrackerRotationClosesOldSessions(t *testing.T) {
	tr := NewTracker()
	tr.SetUsers([]User{{ID: 7, UUID: "old"}})
	c := &trackedClose{}
	l, ok := tr.Acquire(7, netip.MustParseAddr("192.0.2.1"), c)
	if !ok {
		t.Fatal("initial admission failed")
	}
	defer l.Release()
	tr.SetUsers([]User{{ID: 7, UUID: "new"}})
	if c.closed.Load() != 1 {
		t.Fatal("credential rotation kept old connection")
	}
	if _, ok := tr.AcquireAuthenticated(7, netip.MustParseAddr("192.0.2.2"), nil, func() bool { return false }); ok {
		t.Fatal("obsolete handshake admitted")
	}
}

func TestTrackerDeviceLimitChecksBeforeInsertion(t *testing.T) {
	tr := NewTracker()
	tr.SetUsers([]User{{ID: 7, UUID: "u", DeviceLimit: 1}})
	l, ok := tr.Acquire(7, netip.MustParseAddr("192.0.2.1"), nil)
	if !ok {
		t.Fatal("first device refused")
	}
	defer l.Release()
	if _, ok := tr.Acquire(7, netip.MustParseAddr("192.0.2.2"), nil); ok {
		t.Fatal("second device admitted")
	}
	if got := tr.Alive()[7]; len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("refused device leaked into online state: %v", got)
	}
}
