package txnode

import (
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
	gateMu      sync.Mutex
	paused      bool
	wake        chan struct{}
	renewal     *nativeRenewalTicket
	readPausers map[*nativeReadBinding]struct{}
	collector   *usageinterval.NativeCollector
	users       map[string]int

	enforcing atomic.Bool
	stopped   atomic.Bool
	inflight  atomic.Int64

	events *usagebucket.Meter

	serverMu sync.Mutex
	servers  map[*core.Server]struct{}

	sessions sync.Map // connID(uint64) -> *usagebucket.Session
}

type chunkTokens struct {
	issuer    *nativeMeter
	collector *usageinterval.NativeCollector
	completed atomic.Bool
	native    *usageinterval.Operation
	session   *usagebucket.Session
	bucket    usagebucket.Operation
}

// AllowSplice keeps authorization-enforcing collectors on their existing copy
// path. Only the original, active local observation owner opts in.
func (m *nativeMeter) AllowSplice() bool {
	if m == nil {
		return false
	}
	m.gateMu.Lock()
	defer m.gateMu.Unlock()
	return m.collector == nil && m.events != nil && !m.stopped.Load() && !m.paused
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
	if m == nil {
		return false
	}
	m.gateMu.Lock()
	defer m.gateMu.Unlock()
	if m.collector == nil || m.collector.Unknown() || m.stopped.Load() || m.paused {
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
	m.gateMu.Lock()
	defer m.gateMu.Unlock()
	m.stopped.Store(true)
	m.enforcing.Store(false)
	if m.collector != nil {
		m.collector.Fail()
	}
	m.signalLocked()
}

func (m *nativeMeter) enforcingNow() bool {
	return m != nil && m.enforcing.Load() && !m.stopped.Load() && m.collector != nil
}

// Begin implements core.ChunkHook.
func (m *nativeMeter) Begin(c core.Chunk) (any, error) {
	if m == nil {
		return nil, nil
	}
	m.gateMu.Lock()
	if m.stopped.Load() || (m.collector != nil && !m.enforcingNow()) {
		m.gateMu.Unlock()
		return nil, usageinterval.ErrUnknown
	}
	if m.paused {
		m.gateMu.Unlock()
		return nil, core.ErrReadPaused
	}
	t := &chunkTokens{issuer: m, collector: m.collector}
	// Register before BeginIO can block in durable persistence. Stop never waits
	// for that disk operation, while renewal must include it in quiescence.
	m.inflight.Add(1)
	m.gateMu.Unlock()
	if t.collector != nil {
		op := t.collector.BeginIO(c.UserID, directionName(c.Dir), c.N)
		if op == nil {
			m.finishChunk()
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
		m.finishChunk()
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
	if t.issuer != m || !t.completed.CompareAndSwap(false, true) {
		if t.collector != nil {
			t.collector.RejectOperation()
		}
		m.StopBoundedUsageTraffic()
		return
	}
	defer m.finishChunk()
	ioError := c.Err != nil && !errors.Is(c.Err, io.EOF)
	if t.native != nil {
		_ = t.collector.CompleteIO(t.native, directionName(c.Dir), c.N, ioError)
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

type nativeReadBinding struct{ pauser core.ReadPauser }

type nativeRenewalTicket struct {
	kernel    *Kernel
	meter     *nativeMeter
	old       *usageinterval.NativeCollector
	boundary  time.Time
	retired   bool
	retiring  bool
	committed bool
	finished  bool
}

func (m *nativeMeter) signalLocked() {
	if m.wake != nil {
		close(m.wake)
		m.wake = nil
	}
}

func (m *nativeMeter) finishChunk() {
	m.gateMu.Lock()
	m.inflight.Add(-1)
	m.signalLocked()
	m.gateMu.Unlock()
}

func (m *nativeMeter) WaitReady(ctx context.Context) error {
	for {
		m.gateMu.Lock()
		if m.stopped.Load() {
			m.gateMu.Unlock()
			return usageinterval.ErrUnknown
		}
		if !m.paused {
			m.gateMu.Unlock()
			return ctx.Err()
		}
		if m.wake == nil {
			m.wake = make(chan struct{})
		}
		wake := m.wake
		m.gateMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

func (m *nativeMeter) BindReadPause(pauser core.ReadPauser) (func(), error) {
	m.gateMu.Lock()
	defer m.gateMu.Unlock()
	if m.stopped.Load() {
		return nil, usageinterval.ErrUnknown
	}
	if m.paused {
		if pauser == nil {
			return nil, core.ErrReadPauseUnsupported
		}
		if err := pauser.PauseRead(); err != nil {
			return nil, err
		}
	}
	binding := &nativeReadBinding{pauser: pauser}
	if m.readPausers == nil {
		m.readPausers = make(map[*nativeReadBinding]struct{})
	}
	m.readPausers[binding] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() { m.gateMu.Lock(); delete(m.readPausers, binding); m.signalLocked(); m.gateMu.Unlock() })
	}, nil
}

func (k *Kernel) PauseNativeRenewal(expected usageinterval.Meter) (usageinterval.RenewalTicket, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, ok := expected.(*nativeMeter)
	if !ok || m == nil || k.meter != m {
		return nil, usageinterval.ErrUnknown
	}
	m.gateMu.Lock()
	if !m.enforcingNow() || m.paused || m.renewal != nil || m.collector.CheckCurrent() != nil {
		m.gateMu.Unlock()
		return nil, usageinterval.ErrUnknown
	}
	for binding := range m.readPausers {
		if binding.pauser == nil {
			m.gateMu.Unlock()
			return nil, usageinterval.ErrNativeRenewalUnsupported
		}
	}
	ticket := &nativeRenewalTicket{kernel: k, meter: m, old: m.collector}
	m.paused, m.renewal = true, ticket
	for binding := range m.readPausers {
		if err := binding.pauser.PauseRead(); err != nil {
			m.gateMu.Unlock()
			ticket.Abort()
			return nil, err
		}
	}
	m.signalLocked()
	m.gateMu.Unlock()
	return ticket, nil
}

func (t *nativeRenewalTicket) WaitQuiescent(ctx context.Context) error {
	m := t.meter
	for {
		m.gateMu.Lock()
		if m.stopped.Load() || t.finished || m.renewal != t {
			m.gateMu.Unlock()
			return usageinterval.ErrUnknown
		}
		if err := ctx.Err(); err != nil {
			m.gateMu.Unlock()
			return err
		}
		if m.inflight.Load() == 0 {
			m.gateMu.Unlock()
			return nil
		}
		if m.wake == nil {
			m.wake = make(chan struct{})
		}
		wake := m.wake
		m.gateMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

func (t *nativeRenewalTicket) Retire(ctx context.Context) (time.Time, error) {
	if err := t.WaitQuiescent(ctx); err != nil {
		return time.Time{}, err
	}
	m := t.meter
	m.gateMu.Lock()
	if t.retired {
		boundary := t.boundary
		m.gateMu.Unlock()
		return boundary, nil
	}
	if t.retiring || m.stopped.Load() || t.finished || m.renewal != t {
		m.gateMu.Unlock()
		return time.Time{}, usageinterval.ErrUnknown
	}
	t.retiring = true
	m.gateMu.Unlock()
	boundary, err := t.old.RetireQuiescent(ctx)
	m.gateMu.Lock()
	defer m.gateMu.Unlock()
	t.retiring = false
	if err != nil {
		return time.Time{}, err
	}
	if m.stopped.Load() || t.finished || m.renewal != t {
		return time.Time{}, usageinterval.ErrUnknown
	}
	t.retired, t.boundary = true, boundary
	return boundary, nil
}

func (t *nativeRenewalTicket) Commit(next *usageinterval.NativeCollector) error {
	t.kernel.mu.Lock()
	defer t.kernel.mu.Unlock()
	m := t.meter
	m.gateMu.Lock()
	defer m.gateMu.Unlock()
	if t.kernel.meter != m || m.stopped.Load() || !m.paused || m.renewal != t || t.finished || !t.retired || t.committed ||
		m.collector != t.old || m.inflight.Load() != 0 || !t.old.RenewalSuccessor(next, t.boundary) {
		return usageinterval.ErrUnknown
	}
	m.collector = next
	t.committed = true
	return nil
}

func (t *nativeRenewalTicket) Resume() error {
	m := t.meter
	m.gateMu.Lock()
	if m.stopped.Load() || !m.paused || m.renewal != t || t.finished || !t.committed || m.collector.CheckCurrent() != nil {
		m.gateMu.Unlock()
		return usageinterval.ErrUnknown
	}
	for binding := range m.readPausers {
		if binding.pauser == nil {
			m.gateMu.Unlock()
			t.Abort()
			return core.ErrReadPauseUnsupported
		}
		if err := binding.pauser.ResumeRead(); err != nil {
			m.gateMu.Unlock()
			t.Abort()
			return err
		}
	}
	t.finished = true
	m.paused, m.renewal = false, nil
	m.signalLocked()
	m.gateMu.Unlock()
	return nil
}

func (t *nativeRenewalTicket) Abort() {
	m := t.meter
	m.gateMu.Lock()
	if t.finished {
		m.gateMu.Unlock()
		return
	}
	t.finished = true
	t.old.Fail()
	m.gateMu.Unlock()
	m.StopBoundedUsageTraffic()
}
