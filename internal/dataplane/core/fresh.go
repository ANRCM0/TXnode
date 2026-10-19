package core

import (
	"container/list"
	"net"
	"sync"
	"sync/atomic"
)

// Fresh is the pre-handshake concurrency gate (notes/rev-core.md §2.1):
//
//	core.freshSet @0xe807e0 { mu, max int, l *list.List }
//	core.Fresh    @0xea5940 { set *freshSet, conn, el *list.Element, out atomic.Bool }
//	freshSet.add @0x7b8a60, Fresh.Done @0x7b8dc0, freshSet.len @0x7b8f20
//
// Every accepted connection occupies a slot before the handshake and releases it
// when the handshake is over; Server.MaxFresh bounds how many unauthenticated
// connections one listener may hold.
//
// UNVERIFIED: whether add() blocks or drops once max is reached could not be
// recovered from the static evidence. Dropping the connection is used here: a
// blocking accept loop would let one slow client stall the listener, and the
// gate exists to bound unauthenticated state.

type freshSet struct {
	mu  sync.Mutex
	max int
	l   *list.List
}

// Fresh is one occupied slot.
type Fresh struct {
	set  *freshSet
	conn net.Conn
	el   *list.Element
	out  atomic.Bool
}

func newFreshSet(max int) *freshSet {
	return &freshSet{max: max, l: list.New()}
}

// add registers conn. It returns nil when the gate is full, or when the server
// has no limit configured and max <= 0 (unlimited) — in the unlimited case a
// slot is still tracked so len() is meaningful.
func (s *freshSet) add(conn net.Conn) *Fresh {
	if s == nil {
		return &Fresh{conn: conn}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.max > 0 && s.l.Len() >= s.max {
		return nil
	}
	f := &Fresh{set: s, conn: conn}
	f.el = s.l.PushBack(f)
	return f
}

// Done releases the slot exactly once (Fresh.Done @0x7b8dc0).
func (f *Fresh) Done() {
	if f == nil || f.set == nil || f.el == nil {
		return
	}
	if !f.out.CompareAndSwap(false, true) {
		return
	}
	f.set.mu.Lock()
	f.set.l.Remove(f.el)
	f.set.mu.Unlock()
}

// Out reports whether the handshake finished (Fresh.out).
func (f *Fresh) Out() bool {
	if f == nil {
		return true
	}
	return f.out.Load()
}

// setMax updates the gate limit. Existing slots above the new limit are left
// alone; new connections are refused until the count drops.
func (s *freshSet) setMax(max int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.max = max
	s.mu.Unlock()
}

// len returns the number of in-flight handshakes (freshSet.len @0x7b8f20).
func (s *freshSet) len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.l.Len()
}
