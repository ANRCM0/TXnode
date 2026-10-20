package txnode

import (
	"errors"
	"io"
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
	inflight  atomic.Int64

	events *usagebucket.Meter

	serverMu sync.Mutex
	servers  map[*core.Server]struct{}

	sessions sync.Map // connID(uint64) -> *usagebucket.Session
}

type chunkTokens struct {
	native  *usageinterval.Operation
	session *usagebucket.Session
	bucket  usagebucket.Operation
}

// AllowSplice keeps authorization-enforcing collectors on their existing copy
// path. Only the original, active local observation owner opts in.
func (m *nativeMeter) AllowSplice() bool {
	return m != nil && m.collector == nil && m.events != nil && !m.stopped.Load()
}

// replaceNativeMeterLocked leaves all old hooks bound to their own collector.
// The caller holds k.mu and has stopped the previous runtime.
func (k *Kernel) replaceNativeMeterLocked(collector *usageinterval.NativeCollector, users map[string]int) (*nativeMeter, bool) {
	if collector == nil || collector.Unknown() || k.running || (k.meter != nil && k.meter.collector != nil && !k.meter.stopped.Load()) {
		return nil, false
	}
	if k.meter != nil {
		k.meter.retire()
	}
	m := &nativeMeter{collector: collector, users: users}
	m.setEventMeter(k.localEvents())
	k.meter = m
	return m, true
}

func (k *Kernel) installEventMeterLocked(meter *usagebucket.Meter) {
	if k.meter == nil || (k.meter.collector == nil && k.meter.stopped.Load()) {
		k.meter = &nativeMeter{}
	}
	k.meter.setEventMeter(meter)
}

func (m *nativeMeter) setEventMeter(meter *usagebucket.Meter) {
	if m == nil {
		return
	}
	m.events = meter
}

// EnableEnforcingBounded implements usageinterval.Meter.
func (m *nativeMeter) EnableEnforcingBounded() bool {
	if m == nil || m.collector == nil || m.collector.Unknown() || m.stopped.Load() {
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
	m.retire()
	// Match the sing-box runtime: a revoked grant fails the collector so no
	// further BeginIO succeeds, and the affected sessions lose their transport.
	m.serverMu.Lock()
	servers := make([]*core.Server, 0, len(m.servers))
	for srv := range m.servers {
		servers = append(servers, srv)
	}
	m.serverMu.Unlock()
	for _, srv := range servers {
		srv.CloseAllSessions()
	}
}

func (m *nativeMeter) attachServer(srv *core.Server) {
	if m == nil || srv == nil {
		return
	}
	m.serverMu.Lock()
	if m.servers == nil {
		m.servers = make(map[*core.Server]struct{})
	}
	m.servers[srv] = struct{}{}
	stopped := m.stopped.Load()
	m.serverMu.Unlock()
	if stopped {
		srv.CloseAllSessions()
	}
}

func (m *nativeMeter) detachServer(srv *core.Server) {
	if m == nil {
		return
	}
	m.serverMu.Lock()
	delete(m.servers, srv)
	m.serverMu.Unlock()
}

// retire refuses fresh operations but preserves the collector for completions
// already issued to this generation. The service owns draining and retirement.
func (m *nativeMeter) retire() {
	if m == nil {
		return
	}
	m.stopped.Store(true)
	m.enforcing.Store(false)
	if m.collector != nil {
		m.collector.Fail()
	}
}

func (m *nativeMeter) enforcingNow() bool {
	return m != nil && m.enforcing.Load() && !m.stopped.Load() && m.collector != nil
}

// Begin implements core.ChunkHook.
func (m *nativeMeter) Begin(c core.Chunk) (any, error) {
	if m == nil {
		return nil, nil
	}
	if m.stopped.Load() || (m.collector != nil && !m.enforcingNow()) {
		return nil, usageinterval.ErrUnknown
	}
	t := &chunkTokens{}
	if m.collector != nil {
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
	m.inflight.Add(1)
	return t, nil
}

// Complete implements core.ChunkHook.
func (m *nativeMeter) Complete(c core.Chunk, token any) {
	t, ok := token.(*chunkTokens)
	if !ok || t == nil {
		return
	}
	defer m.inflight.Add(-1)
	ioError := c.Err != nil && !errors.Is(c.Err, io.EOF)
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
