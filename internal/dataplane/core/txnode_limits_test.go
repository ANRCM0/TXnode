package core

import (
	"net/netip"
	"testing"
)

func TestTrackerSpeedLimitUsesDecimalMbps(t *testing.T) {
	tr := NewTracker()
	tr.SetUsers([]User{{ID: 1, UUID: "u"}})
	tr.SetGlobalSpeedLimit(100)

	up, down := tr.Limiters(1)
	if up == nil || down == nil {
		t.Fatal("no limiters for a limited user")
	}
	const want = 100 * 1_000_000 / 8
	if got := int64(up.Rate()); got != want {
		t.Fatalf("rate = %d, want %d", got, want)
	}
	if got := int64(down.Rate()); got != want {
		t.Fatalf("down rate = %d, want %d", got, want)
	}
}

func TestSetUserLimitOverridesPanelMbps(t *testing.T) {
	tr := NewTracker()
	tr.SetUsers([]User{{ID: 7, UUID: "u"}})

	// A manual limit must not be overwritten by a later SetUsers refresh.
	tr.SetUserLimit(7, 2_000_000, 1_000_000, 4_000_000)
	tr.SetUsers([]User{{ID: 7, UUID: "u"}})

	up, down := tr.Limiters(7)
	if up == nil || down == nil {
		t.Fatal("no limiters")
	}
	if got := int64(up.Rate()); got != 2_000_000 {
		t.Fatalf("up rate = %d", got)
	}
	if got := int64(down.Rate()); got != 1_000_000 {
		t.Fatalf("down rate = %d", got)
	}
	if got := up.Burst(); got != 4_000_000 {
		t.Fatalf("burst = %d", got)
	}
}

type fakeCloser struct{ closed bool }

func (f *fakeCloser) Close() error { f.closed = true; return nil }

func TestCloseUserConns(t *testing.T) {
	tr := NewTracker()
	tr.SetUsers([]User{{ID: 3, UUID: "u"}})
	c := &fakeCloser{}
	if _, ok := tr.Acquire(3, netip.MustParseAddr("203.0.113.9"), c); !ok {
		t.Fatal("acquire failed")
	}
	if n := tr.CloseUserConns(3); n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}
	if !c.closed {
		t.Fatal("closer was not closed")
	}
}

type allowGate struct {
	calls int
	allow bool
}

func (g *allowGate) Allow(_ int, _ netip.Addr, _ map[string]int) bool {
	g.calls++
	return g.allow
}

func TestDeviceGateReplacesBuiltinCheck(t *testing.T) {
	tr := NewTracker()
	tr.SetUsers([]User{{ID: 1, UUID: "u", DeviceLimit: 1}})
	gate := &allowGate{allow: false}
	tr.SetDeviceGate(gate)

	if _, ok := tr.Acquire(1, netip.MustParseAddr("198.51.100.7"), nil); ok {
		t.Fatal("gate refused but the session was admitted")
	}
	if gate.calls != 1 {
		t.Fatalf("gate calls = %d, want 1", gate.calls)
	}

	gate.allow = true
	if _, ok := tr.Acquire(1, netip.MustParseAddr("198.51.100.7"), nil); !ok {
		t.Fatal("gate allowed but the session was refused")
	}
}
