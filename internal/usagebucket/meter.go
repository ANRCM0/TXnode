// Package usagebucket records bounded local accounting events. Callback time is
// not packet time; even durably retained local buckets remain unattributable.
package usagebucket

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"time"
)

type Direction string

const (
	Upload   Direction = "upload"
	Download Direction = "download"
)

type Path string

const (
	TCPRead          Path = "tcp_read"
	TCPWrite         Path = "tcp_write"
	TCPReadCallback  Path = "tcp_read_callback"
	TCPWriteCallback Path = "tcp_write_callback"
	UDPRead          Path = "udp_read_packet"
	UDPWrite         Path = "udp_write_packet"
	UDPReadCallback  Path = "udp_read_callback"
	UDPWriteCallback Path = "udp_write_callback"
)

type SealReason string

const (
	ManualFence    SealReason = "LOCAL_FENCE"
	LifecycleFence SealReason = "LIFECYCLE_FENCE"
	TimeBoundary   SealReason = "MONOTONIC_WINDOW"
	EventLimit     SealReason = "EVENT_LIMIT"
	ClockBoundary  SealReason = "WALL_CLOCK_ROLLBACK"
)

var ErrOptions = errors.New("invalid usage bucket options")

type Stamp struct {
	WallUnixNanos int64
	ElapsedNanos  int64
}

type Options struct {
	Enabled   bool
	Window    time.Duration
	MaxEvents int
	MaxSealed int
	// Clock is instance-owned. Nil uses process-relative monotonic time.
	Clock func() Stamp
}

// Event reports a count at the original meter site, independently of v1 totals.
// Direct method ranges exist only when Begin actually ran for that operation.
type Event struct {
	Sequence              uint64
	ConnectionID          string
	UserID                int
	Transport             string
	BindingGeneration     uint64
	ObservationGeneration uint64
	ClockEra              uint64
	Kind                  string
	Path                  Path
	PhysicalDirection     Direction
	LegacyDirection       Direction
	RawCount              int64
	CountKnown            bool
	Completed             Stamp
	HasIOStart            bool
	IOStarted             Stamp
	IOError               bool
	IntervalUnknown       bool
	CrossedFence          bool
	LateAfterClose        bool
	StartedAfterClose     bool
	CloseFenceSequence    uint64
	DirectionMismatch     bool
	Attribution           string
	startCutVersion       uint64
	startClockEra         uint64
}

// Sequence ranges are half-open and authoritative for local serialization.
// Time bounds are observations; equal-resolution timestamps may straddle a fence.
type Bucket struct {
	TrackerID            string
	Number               uint64
	Generation           uint64
	ClockEra             uint64
	StartSequence        uint64
	EndSequenceExclusive uint64
	Started              Stamp
	SealedAt             Stamp
	Reason               SealReason
	Sealed               bool
	Events               []Event
	PhysicalTotals       [2]int64
	LegacyTotals         [2]int64
	Attribution          string
	VolatileTailUnknown  bool
}

type Status struct {
	Degraded            bool
	Reason              string
	Generation          uint64
	NextSequence        uint64
	SealedBuckets       int
	DroppedEvents       uint64
	FirstGap            Event
	VolatileTailUnknown bool
	PersistedBuckets    uint64
	ClaimedBucket       uint64
	Stopped             bool
	StopReason          string
	Retiring            bool
}

type Snapshot struct {
	Sealed []Bucket
	Open   Bucket
	Status Status
}

type Meter struct {
	mu           sync.Mutex
	clock        func() Stamp
	window       int64
	maxEvents    int
	maxSealed    int
	trackerID    string
	generation   uint64
	clockEra     uint64
	nextSequence uint64
	cutVersion   uint64
	last         Stamp
	open         Bucket
	sealed       []Bucket
	degraded     string
	dropped      uint64
	firstGap     Event
	claim        *bucketClaim
	consumer     *Coordinator
	persisted    uint64
	stopped      string
	retiring     bool
	retireAt     int64
}

// Session retains its original registration. It never looks up a current UUID
// mapping, and late callbacks cannot move to a newly registered numeric user.
type Session struct {
	meter         *Meter
	connectionID  string
	userID        int
	transport     string
	generation    uint64
	closed        bool // all mutable session state is protected by meter.mu
	closeSequence uint64
}

type Operation struct {
	session       *Session
	started       Stamp
	generation    uint64
	cutVersion    uint64
	clockEra      uint64
	startedClosed bool
	valid         bool
}

// New returns nil without clock reads, allocations or locks when disabled.
func New(options Options) (*Meter, error) {
	if !options.Enabled {
		return nil, nil
	}
	if options.Window == 0 {
		options.Window = time.Second
	}
	if options.MaxEvents == 0 {
		options.MaxEvents = 1024
	}
	if options.MaxSealed == 0 {
		options.MaxSealed = 32
	}
	if options.Window < time.Nanosecond || options.Window > time.Hour || options.MaxEvents < 1 || options.MaxEvents > 4096 || options.MaxSealed < 1 || options.MaxSealed > 1024 || options.MaxEvents*(options.MaxSealed+1) > 65536 {
		return nil, ErrOptions
	}
	clock := options.Clock
	if clock == nil {
		boot := time.Now()
		clock = func() Stamp { now := time.Now(); return Stamp{now.UnixNano(), int64(now.Sub(boot))} }
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	at := clock()
	if at.ElapsedNanos < 0 {
		return nil, ErrOptions
	}
	m := &Meter{clock: clock, window: int64(options.Window), maxEvents: options.MaxEvents, maxSealed: options.MaxSealed, trackerID: hex.EncodeToString(nonce[:]), generation: 1, clockEra: 1, nextSequence: 1, last: at}
	m.open = m.newBucket(1, at)
	return m, nil
}

func (m *Meter) newBucket(number uint64, at Stamp) Bucket {
	return Bucket{TrackerID: m.trackerID, Number: number, Generation: m.generation, ClockEra: m.clockEra, StartSequence: m.nextSequence, Started: at, Events: []Event{}, Attribution: "unattributable", VolatileTailUnknown: true}
}

func (m *Meter) Bind(userID int, connectionID, transport string) *Session {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return &Session{meter: m, connectionID: connectionID, userID: userID, transport: transport, generation: m.generation}
}

func (s *Session) Begin() Operation {
	if s == nil {
		return Operation{}
	}
	m := s.meter
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.degraded != "" || m.stopped != "" {
		return Operation{}
	}
	at, ok := m.stamp()
	if !ok {
		return Operation{}
	}
	if m.checkRetirement(at) {
		return Operation{}
	}
	return Operation{session: s, started: at, generation: m.generation, cutVersion: m.cutVersion, clockEra: m.clockEra, startedClosed: s.closed, valid: true}
}

func (s *Session) Complete(operation Operation, path Path, physical, legacy Direction, n int64, ioError, countKnown bool) {
	if s == nil {
		return
	}
	m := s.meter
	m.mu.Lock()
	defer m.mu.Unlock()
	e := s.event(path, physical, legacy, n, countKnown)
	e.IOError = ioError
	if operation.valid && operation.session == s {
		e.HasIOStart = true
		e.IOStarted = operation.started
		e.StartedAfterClose = operation.startedClosed
		e.CrossedFence = operation.cutVersion != m.cutVersion || operation.generation != m.generation || operation.clockEra != m.clockEra
		e.startCutVersion = operation.cutVersion
		e.startClockEra = operation.clockEra
	} else {
		e.IntervalUnknown = true
	}
	m.add(e)
}

func (s *Session) Callback(path Path, physical, legacy Direction, n int64) {
	if s == nil {
		return
	}
	m := s.meter
	m.mu.Lock()
	defer m.mu.Unlock()
	e := s.event(path, physical, legacy, n, true)
	e.IntervalUnknown = true
	m.add(e)
}

func (s *Session) event(path Path, physical, legacy Direction, n int64, known bool) Event {
	return Event{ConnectionID: s.connectionID, UserID: s.userID, Transport: s.transport, BindingGeneration: s.generation, Kind: "accounting_completion", Path: path, PhysicalDirection: physical, LegacyDirection: legacy, RawCount: n, CountKnown: known, LateAfterClose: s.closed, CloseFenceSequence: s.closeSequence, DirectionMismatch: physical != legacy, Attribution: "unattributable"}
}

func (s *Session) Close() {
	if s == nil {
		return
	}
	m := s.meter
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.closeSequence = m.nextSequence
	e := Event{ConnectionID: s.connectionID, UserID: s.userID, Transport: s.transport, BindingGeneration: s.generation, Kind: "close_fence", CountKnown: true, CloseFenceSequence: s.closeSequence, Attribution: "unattributable"}
	m.add(e)
}

func (m *Meter) stamp() (Stamp, bool) {
	at := m.clock()
	if at.ElapsedNanos < 0 || at.ElapsedNanos < m.last.ElapsedNanos {
		m.fail("MONOTONIC_ROLLBACK", Event{Completed: at, Attribution: "unattributable"})
		return at, false
	}
	if at.WallUnixNanos < m.last.WallUnixNanos {
		if m.clockEra == math.MaxUint64 {
			m.fail("GENERATION_OVERFLOW", Event{Completed: at, Attribution: "unattributable"})
			return at, false
		}
		if !m.seal(at, ClockBoundary) {
			return at, false
		}
		m.clockEra++
		m.open.ClockEra = m.clockEra
	}
	m.last = at
	return at, true
}

func (m *Meter) add(e Event) {
	if m.degraded != "" || m.stopped != "" {
		m.drop()
		return
	}
	at, ok := m.stamp()
	if !ok {
		e.Completed = at
		m.captureGap(e)
		return
	}
	e.Completed = at
	if m.checkRetirement(at) {
		m.drop()
		return
	}
	e.ObservationGeneration = m.generation
	e.ClockEra = m.clockEra
	if e.HasIOStart && (e.startCutVersion != m.cutVersion || e.startClockEra != m.clockEra) {
		e.CrossedFence = true
	}
	if e.HasIOStart && (e.IOStarted.ElapsedNanos < m.open.Started.ElapsedNanos || e.IOStarted.WallUnixNanos > at.WallUnixNanos) {
		e.CrossedFence = true
	}
	if e.RawCount < 0 {
		m.fail("NEGATIVE_COUNT", e)
		return
	}
	if e.Kind == "accounting_completion" && (!validDirection(e.PhysicalDirection) || !validDirection(e.LegacyDirection)) {
		m.fail("INVALID_DIRECTION", e)
		return
	}
	// Monotonic elapsed values are nonnegative and increasing, so subtraction
	// cannot overflow. Rotate before appending this completion event.
	if at.ElapsedNanos-m.open.Started.ElapsedNanos >= m.window || len(m.open.Events) >= m.maxEvents {
		reason := TimeBoundary
		if len(m.open.Events) >= m.maxEvents {
			reason = EventLimit
		}
		if !m.seal(at, reason) {
			m.captureGap(e)
			return
		}
		if e.HasIOStart {
			e.CrossedFence = true
		}
	}
	if m.nextSequence == math.MaxUint64 {
		m.fail("SEQUENCE_OVERFLOW", e)
		return
	}
	physical, legacy := directionIndex(e.PhysicalDirection), directionIndex(e.LegacyDirection)
	if e.Kind == "accounting_completion" && e.CountKnown {
		if e.RawCount > math.MaxInt64-m.open.PhysicalTotals[physical] || e.RawCount > math.MaxInt64-m.open.LegacyTotals[legacy] {
			m.fail("COUNTER_OVERFLOW", e)
			return
		}
		m.open.PhysicalTotals[physical] += e.RawCount
		m.open.LegacyTotals[legacy] += e.RawCount
	}
	e.Sequence = m.nextSequence
	m.nextSequence++
	m.open.Events = append(m.open.Events, e)
}

func validDirection(d Direction) bool { return d == Upload || d == Download }
func directionIndex(d Direction) int {
	if d == Download {
		return 1
	}
	return 0
}

func (m *Meter) seal(at Stamp, reason SealReason) bool {
	if len(m.sealed) >= m.maxSealed {
		m.fail("CAPACITY_REACHED", Event{Completed: at, Attribution: "unattributable"})
		return false
	}
	if m.open.Number == math.MaxUint64 || m.cutVersion == math.MaxUint64 {
		m.fail("SEQUENCE_OVERFLOW", Event{Completed: at, Attribution: "unattributable"})
		return false
	}
	m.open.Sealed = true
	m.open.SealedAt = at
	m.open.Reason = reason
	m.open.EndSequenceExclusive = m.nextSequence
	m.sealed = append(m.sealed, m.open)
	m.cutVersion++
	m.open = m.newBucket(m.open.Number+1, at)
	// Wake the existing consumer without reversing its coordinator -> meter
	// lock order. The one-slot signal never waits for persistence or an ACK.
	if m.consumer != nil {
		select {
		case m.consumer.wake <- struct{}{}:
		default:
		}
	}
	return true
}

// Cut is a local observation fence. It cannot assert a remote authorization or
// Terms boundary. A sealed bucket is never reopened, including for late callbacks.
func (m *Meter) Cut(reason SealReason, advanceGeneration bool) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.degraded != "" || m.stopped != "" {
		return false
	}
	if reason != ManualFence && reason != LifecycleFence {
		return false
	}
	at, ok := m.stamp()
	if !ok {
		return false
	}
	if m.checkRetirement(at) {
		return false
	}
	if advanceGeneration && m.generation == math.MaxUint64 {
		m.fail("GENERATION_OVERFLOW", Event{Completed: at, Attribution: "unattributable"})
		return false
	}
	if !m.seal(at, reason) {
		return false
	}
	if advanceGeneration {
		m.generation++
		m.open.Generation = m.generation
	}
	return true
}

func (m *Meter) fail(reason string, e Event) {
	if m.degraded != "" {
		return
	}
	m.degraded = reason
	if e.Kind != "" {
		m.captureGap(e)
	} else {
		e.Sequence = m.nextSequence
		m.firstGap = e
	}
}
func (m *Meter) captureGap(e Event) {
	if m.dropped == 0 {
		e.Sequence = m.nextSequence
		m.firstGap = e
	}
	m.drop()
}
func (m *Meter) drop() {
	if m.dropped < math.MaxUint64 {
		m.dropped++
	}
}

// Snapshot makes independent copies. Callers cannot mutate retained sealed data.
// A snapshot does not acknowledge persistence. Only the private coordinator ACK
// can release retained sealed buckets; the remaining volatile tail is unknown.
func (m *Meter) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{Status: Status{VolatileTailUnknown: true}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sealed := make([]Bucket, len(m.sealed))
	for i, b := range m.sealed {
		sealed[i] = cloneBucket(b)
	}
	return Snapshot{Sealed: sealed, Open: cloneBucket(m.open), Status: m.statusLocked()}
}

func cloneBucket(b Bucket) Bucket { b.Events = append([]Event{}, b.Events...); return b }

// Status does not copy events or wait for persistence. A durable local receipt
// cannot establish that the remaining observation tail is complete.
func (m *Meter) Status() Status {
	if m == nil {
		return Status{VolatileTailUnknown: true}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

func (m *Meter) statusLocked() Status {
	s := Status{Degraded: m.degraded != "", Reason: m.degraded, Generation: m.generation, NextSequence: m.nextSequence, SealedBuckets: len(m.sealed), DroppedEvents: m.dropped, FirstGap: m.firstGap, VolatileTailUnknown: true, PersistedBuckets: m.persisted, Stopped: m.stopped != "", StopReason: m.stopped, Retiring: m.retiring}
	if m.claim != nil {
		s.ClaimedBucket = m.claim.bucket.Number
	}
	return s
}
