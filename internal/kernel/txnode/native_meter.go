package txnode

import (
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
)

// nativeMeter is the data plane's per-chunk accountant. It serves two owners:
//
//   - usage_v2: every chunk is charged to the authorization window through the
//     caller-owned NativeCollector (BeginIO/CompleteIO), which can refuse a
//     chunk once the grant is exhausted;
//   - the local event store: every connection gets a usagebucket.Session and
//     each chunk becomes an accounting event.
//
// Both are optional; a meter with neither enabled is inert. The type implements
// core.ChunkHook so the relay can call it directly.
type nativeMeter struct {
	collector *usageinterval.NativeCollector
	users     map[string]int

	enforcing atomic.Bool
	stopped   atomic.Bool

	events *usagebucket.Meter

	// onStop closes the live transports when bounded usage is revoked; the
	// kernel installs it so the meter stays free of server state.
	onStop func()

	sessions sync.Map // connID(uint64) -> *usagebucket.Session
}

type chunkTokens struct {
	native  *usageinterval.Operation
	session *usagebucket.Session
	bucket  usagebucket.Operation
}

func (m *nativeMeter) setEventMeter(meter *usagebucket.Meter) {
	if m == nil {
		return
	}
	m.events = meter
}

// EnableEnforcingBounded implements usageinterval.Meter.
func (m *nativeMeter) EnableEnforcingBounded() bool {
	if m == nil || m.collector == nil || m.stopped.Load() {
		return false
	}
	m.enforcing.Store(true)
	return true
}

// StopBoundedUsageTraffic implements usageinterval.Meter: new chunks stop being
// charged, the collector drains.
func (m *nativeMeter) StopBoundedUsageTraffic() {
	if m == nil {
		return
	}
	m.stopped.Store(true)
	m.enforcing.Store(false)
	// Match the sing-box runtime: a revoked grant fails the collector so no
	// further BeginIO succeeds, and the affected sessions lose their transport.
	if m.collector != nil {
		m.collector.Fail()
	}
	if m.onStop != nil {
		m.onStop()
	}
}

func (m *nativeMeter) enforcingNow() bool {
	return m != nil && m.enforcing.Load() && !m.stopped.Load() && m.collector != nil
}

// Begin implements core.ChunkHook.
func (m *nativeMeter) Begin(c core.Chunk) (any, error) {
	if m == nil || m.stopped.Load() {
		return nil, nil
	}
	t := &chunkTokens{}
	if m.enforcingNow() {
		op := m.collector.BeginIO(c.UserID, directionName(c.Dir), c.N)
		if op == nil {
			return nil, usageinterval.ErrUnknown
		}
		t.native = op
	}
	if m.events != nil {
		if s := m.session(c); s != nil {
			t.session = s
			t.bucket = s.Begin()
		}
	}
	if t.native == nil && t.session == nil {
		return nil, nil
	}
	return t, nil
}

// Complete implements core.ChunkHook.
func (m *nativeMeter) Complete(c core.Chunk, token any) {
	t, ok := token.(*chunkTokens)
	if !ok || t == nil {
		return
	}
	ioError := c.Err != nil && !errors.Is(c.Err, io.EOF) && !errors.Is(c.Err, net.ErrClosed)
	if t.native != nil {
		_ = m.collector.CompleteIO(t.native, directionName(c.Dir), c.N, ioError)
	}
	if t.session != nil {
		t.session.Complete(t.bucket, pathOf(c), physicalDirection(c.Dir), usagebucket.Direction(directionName(c.Dir)), c.N, ioError, true)
	}
}

// Close implements core.ChunkHook: it closes the connection's bucket session.
func (m *nativeMeter) Close(c core.Chunk) {
	if m == nil {
		return
	}
	if v, ok := m.sessions.LoadAndDelete(c.ConnID); ok {
		if s, ok := v.(*usagebucket.Session); ok {
			s.Close()
		}
	}
}

func (m *nativeMeter) session(c core.Chunk) *usagebucket.Session {
	key := c.ConnID
	if key == 0 {
		return nil
	}
	if v, ok := m.sessions.Load(key); ok {
		s, _ := v.(*usagebucket.Session)
		return s
	}
	s := m.events.Bind(c.UserID, "tx-"+strconv.FormatUint(key, 36), transportOf(c))
	if s == nil {
		return nil
	}
	actual, _ := m.sessions.LoadOrStore(key, s)
	stored, _ := actual.(*usagebucket.Session)
	return stored
}

func directionName(d core.ChunkDirection) string {
	if d == core.DirDownload {
		return string(usagebucket.Download)
	}
	return string(usagebucket.Upload)
}

func physicalDirection(d core.ChunkDirection) usagebucket.Direction {
	if d == core.DirDownload {
		return usagebucket.Download
	}
	return usagebucket.Upload
}

func pathOf(c core.Chunk) usagebucket.Path {
	if c.Path == "udp" {
		if c.Dir == core.DirDownload {
			return usagebucket.UDPWrite
		}
		return usagebucket.UDPRead
	}
	if c.Dir == core.DirDownload {
		return usagebucket.TCPWrite
	}
	return usagebucket.TCPRead
}

func transportOf(c core.Chunk) string {
	if c.Path == "udp" {
		return "udp"
	}
	return "tcp"
}
