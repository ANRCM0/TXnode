package usageinterval

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

const nativeStateLimit = 2 << 20
const nativeCollectorLimit = 512

var ErrNativeStorage = errors.New("NATIVE_USAGE_STORAGE_UNAVAILABLE")

type NativeWindow struct {
	Revision  string `json:"revision"`
	Digest    string `json:"digest"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

type nativeEvent struct {
	Evidence   `json:"evidence"`
	Requested  int64  `json:"requested_bytes,string"`
	Operations uint64 `json:"operation_count,string"`
	Done       bool   `json:"done"`
	Eligible   bool   `json:"eligible"`
}

type nativeState struct {
	Version          int             `json:"version"`
	Collector        string          `json:"collector"`
	Session          usagev2.Session `json:"session"`
	Window           NativeWindow    `json:"window"`
	StartedAt        int64           `json:"started_at"`
	Sequence         uint64          `json:"sequence,string"`
	Retired          bool            `json:"retired"`
	Events           []nativeEvent   `json:"events"`
	Pending          *usagev2.Record `json:"pending,omitempty"`
	PendingSequences []uint64        `json:"pending_sequences"`
	PendingEnd       int64           `json:"pending_end"`
}

type nativeMarker struct {
	Version    int    `json:"version"`
	Core       string `json:"core"`
	Node       string `json:"node"`
	Epoch      string `json:"epoch"`
	Generation string `json:"generation"`
	Revision   string `json:"revision"`
	Digest     string `json:"digest"`
	LastEnd    int64  `json:"last_end"`
}

// NativeStore owns durable I/O intents, completed evidence and original-session
// batches. Unresolved evidence survives independently from the live collector.
type NativeStore struct {
	mu          sync.Mutex
	dir         string
	lock        *os.File
	spool       *usagev2.Spool
	marker      nativeMarker
	quarantined atomic.Int64
}

type NativeCollector struct {
	mu       sync.Mutex
	store    *NativeStore
	state    nativeState
	users    map[string]int
	grants   map[string]usagev2.Grant
	origin   time.Time
	deadline time.Time
	last     stamp
	closed   atomic.Bool
	failed   atomic.Bool
	inflight atomic.Int64
	wake     chan struct{}
}

func OpenNativeStore(dir string, session usagev2.Session, spool *usagev2.Spool) (*NativeStore, error) {
	if !filepath.IsAbs(dir) || session.Validate() != nil || spool == nil || durableJournalDirectory(dir) != nil {
		return nil, ErrNativeStorage
	}
	lock, err := lockJournal(dir)
	if err != nil {
		return nil, ErrNativeStorage
	}
	s := &NativeStore{dir: dir, lock: lock, spool: spool}
	fail := func() (*NativeStore, error) { lock.Close(); return nil, ErrNativeStorage }
	data, err := readNative(filepath.Join(dir, ".native-source"))
	if err == nil {
		if decodeNative(data, &s.marker) != nil || s.marker.Version != 1 ||
			s.marker.Core != session.CoreInstanceID || s.marker.Node != session.NodeID ||
			s.marker.Generation != session.ReceiptGeneration || usagev2.Decimal(s.marker.Epoch, false) != nil ||
			decimalCompare(session.SourceEpoch, s.marker.Epoch) < 0 || s.marker.LastEnd < 0 {
			return fail()
		}
	} else if !os.IsNotExist(err) {
		return fail()
	}
	if spool.BindSession(session) != nil {
		return fail()
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) > nativeCollectorLimit+4 {
		return fail()
	}
	type saved struct {
		path  string
		state nativeState
	}
	var records []saved
	for _, file := range files {
		if file.Name() == ".interval-lock" || file.Name() == ".native-source" {
			continue
		}
		if strings.HasPrefix(file.Name(), ".native-write-") {
			// An unpublished temporary file cannot authorize or replace its target.
			continue
		}
		if !strings.HasSuffix(file.Name(), ".native") || file.Type()&os.ModeSymlink != 0 || file.IsDir() {
			return fail()
		}
		raw, err := readNative(filepath.Join(dir, file.Name()))
		var state nativeState
		if err != nil || decodeNative(raw, &state) != nil || validateNativeState(state) != nil ||
			file.Name() != state.Collector+".native" || state.Session.CoreInstanceID != session.CoreInstanceID ||
			state.Session.NodeID != session.NodeID || state.Session.ReceiptGeneration != session.ReceiptGeneration ||
			decimalCompare(state.Session.SourceEpoch, session.SourceEpoch) > 0 {
			return fail()
		}
		records = append(records, saved{filepath.Join(dir, file.Name()), state})
		if state.Retired && len(state.Events) > 0 {
			s.quarantined.Add(1)
		}
		if s.marker.Version == 0 || decimalCompare(state.Window.Revision, s.marker.Revision) > 0 {
			s.marker = nativeMarker{1, state.Session.CoreInstanceID, state.Session.NodeID, state.Session.SourceEpoch,
				state.Session.ReceiptGeneration, state.Window.Revision, state.Window.Digest, s.marker.LastEnd}
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].state.StartedAt < records[j].state.StartedAt })
	for _, record := range records {
		state := record.state
		if err := s.exportPending(&state); err != nil {
			return fail()
		}
		if !state.Retired {
			// Recovery never resumes old I/O. Completed bounded operations retain
			// their old grant; absent completion is retained as unresolved evidence.
			if err := s.seal(&state, 0, true); err != nil {
				return fail()
			}
			state.Retired = true
			for i := range state.Events {
				state.Events[i].Eligible = false
			}
			if err := s.saveOrRetire(&state); err != nil {
				return fail()
			}
		}
	}
	return s, nil
}

func (s *NativeStore) NewCollector(session usagev2.Session, window NativeWindow, users map[string]int) (*NativeCollector, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil || session.Validate() != nil || !validNativeWindow(session, window) ||
		len(users) != len(session.Grants) || len(users) > MaxGrants {
		return nil, ErrNativeStorage
	}
	if s.marker.Version != 0 && (s.marker.Core != session.CoreInstanceID || s.marker.Node != session.NodeID ||
		s.marker.Generation != session.ReceiptGeneration || decimalCompare(session.SourceEpoch, s.marker.Epoch) < 0 ||
		decimalCompare(window.Revision, s.marker.Revision) <= 0) {
		return nil, ErrNativeStorage
	}
	if s.spool.BindSession(session) != nil {
		return nil, ErrNativeStorage
	}
	files, err := os.ReadDir(s.dir)
	if err != nil || len(files) >= nativeCollectorLimit {
		return nil, ErrNativeStorage
	}
	now := time.Now()
	started := now.Unix()
	if s.marker.LastEnd > started {
		started = s.marker.LastEnd
	}
	if started < window.IssuedAt {
		started = window.IssuedAt
	}
	if started >= window.ExpiresAt {
		return nil, ErrUnknown
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, ErrNativeStorage
	}
	c := &NativeCollector{store: s, users: map[string]int{}, grants: map[string]usagev2.Grant{}, origin: now,
		deadline: now.Add(time.Unix(window.ExpiresAt, 0).Sub(now)), last: stamp{now.UnixNano(), 0}, wake: make(chan struct{}, 1)}
	copied, _ := json.Marshal(session)
	var frozen usagev2.Session
	_ = json.Unmarshal(copied, &frozen)
	c.state = nativeState{Version: 1, Collector: hex.EncodeToString(id), Session: frozen, Window: window,
		StartedAt: started, Events: []nativeEvent{}, PendingSequences: []uint64{}}
	for _, grant := range session.Grants {
		c.grants[grant.UserID] = grant
	}
	seen := map[int]bool{}
	for uuid, user := range users {
		if uuid == "" || user <= 0 || user > 2147483647 || seen[user] {
			return nil, ErrUnknown
		}
		if _, ok := c.grants[strconv.Itoa(user)]; !ok {
			return nil, ErrUnknown
		}
		seen[user] = true
		c.users[uuid] = user
	}
	if err := s.save(&c.state); err != nil {
		return nil, err
	}
	s.marker = nativeMarker{1, session.CoreInstanceID, session.NodeID, session.SourceEpoch, session.ReceiptGeneration, window.Revision, window.Digest, s.marker.LastEnd}
	if err := s.write(".native-source", s.marker); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *NativeCollector) ReadyAt() time.Time { return time.Unix(c.state.StartedAt, 0) }
func (c *NativeCollector) Fail()              { c.closed.Store(true) }
func (c *NativeCollector) Close()             { c.closed.Store(true) }
func (c *NativeCollector) Unknown() bool      { return c.closed.Load() || c.failed.Load() }

func (c *NativeCollector) CheckCurrent() error {
	if c.Unknown() {
		return ErrUnknown
	}
	now := time.Now()
	if now.Unix() < c.state.Window.IssuedAt || now.Unix() >= c.state.Window.ExpiresAt || !now.Before(c.deadline) {
		c.closed.Store(true)
		return ErrUnknown
	}
	return nil
}

func (c *NativeCollector) CheckUsers(users map[string]int) {
	if len(users) != len(c.users) {
		c.Fail()
		return
	}
	for uuid, user := range c.users {
		if users[uuid] != user {
			c.Fail()
			return
		}
	}
}

func (c *NativeCollector) Begin(user int) *Operation {
	return c.BeginIO(user, "upload", int64(usagev2.MaxRawBytes))
}

func (c *NativeCollector) BeginIO(user int, direction string, requested int64) *Operation {
	if c.CheckCurrent() != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Unknown() || c.state.Retired || requested < 0 || requested > int64(usagev2.MaxRawBytes) ||
		(direction != "upload" && direction != "download") || len(c.state.Events) >= MaxOperations || c.state.Sequence == math.MaxUint64 {
		c.failed.Store(true)
		return nil
	}
	now := time.Now()
	at := stamp{now.UnixNano(), int64(now.Sub(c.origin))}
	grant, ok := c.grants[strconv.Itoa(user)]
	if !ok || at.Wall < c.last.Wall || at.Elapsed < c.last.Elapsed || now.Unix() < c.state.StartedAt || !insideGrant(grant, at.Wall) {
		c.failed.Store(true)
		return nil
	}
	c.last = at
	c.state.Sequence++
	event := nativeEvent{Evidence: Evidence{Sequence: c.state.Sequence, UserID: strconv.Itoa(user), Started: at, Direction: direction}, Requested: requested, Operations: 1}
	c.state.Events = append(c.state.Events, event)
	if c.persist() != nil {
		c.failed.Store(true)
		return nil
	}
	if c.closed.Load() || time.Now().Unix() >= c.state.Window.ExpiresAt || !time.Now().Before(c.deadline) {
		c.failed.Store(true)
		return nil
	}
	c.inflight.Add(1)
	return &Operation{native: c, sequence: event.Sequence, user: event.UserID, started: at}
}

func (c *NativeCollector) Complete(op *Operation, direction string, n int64, ioError bool) {
	_ = c.CompleteIO(op, direction, n, ioError)
}

func (c *NativeCollector) CompleteIO(op *Operation, direction string, n int64, ioError bool) error {
	if op == nil || op.native != c {
		c.failed.Store(true)
		return ErrUnknown
	}
	now := time.Now()
	at := stamp{now.UnixNano(), int64(now.Sub(c.origin))}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.state.Events {
		e := &c.state.Events[i]
		if e.Sequence != op.sequence {
			continue
		}
		if e.Done || direction != e.Direction || n < 0 || n > e.Requested {
			c.failed.Store(true)
			return ErrUnknown
		}
		defer func() {
			c.inflight.Add(-1)
			select {
			case c.wake <- struct{}{}:
			default:
			}
		}()
		e.Completed, e.Bytes, e.IOError, e.Done = at, n, ioError, true
		e.Eligible = !c.state.Retired && at.Wall >= e.Started.Wall && at.Elapsed >= e.Started.Elapsed &&
			(at.Elapsed < c.last.Elapsed || at.Wall >= c.last.Wall) &&
			now.Before(c.deadline) && insideGrant(c.grants[e.UserID], at.Wall)
		if at.Elapsed > c.last.Elapsed {
			c.last = at
		}
		if !e.Eligible {
			c.closed.Store(true)
		}
		c.compactCompleted(i)
		if err := c.persist(); err != nil {
			c.failed.Store(true)
			return err
		}
		return nil
	}
	c.failed.Store(true)
	return ErrUnknown
}

// Completed calls under one immutable grant may share bounded evidence. This
// preserves the entire observation window without letting an idle pending read
// retain an unbounded list of already completed writes.
func (c *NativeCollector) compactCompleted(index int) {
	event := c.state.Events[index]
	if !event.Done || !event.Eligible {
		return
	}
	pending := map[uint64]bool{}
	for _, sequence := range c.state.PendingSequences {
		pending[sequence] = true
	}
	for i := range c.state.Events {
		prior := &c.state.Events[i]
		if i == index || !prior.Done || !prior.Eligible || pending[prior.Sequence] ||
			prior.UserID != event.UserID || prior.Direction != event.Direction ||
			prior.Requested > int64(usagev2.MaxRawBytes)-event.Requested ||
			prior.Bytes > int64(usagev2.MaxRawBytes)-event.Bytes || prior.Operations > math.MaxUint64-event.Operations {
			continue
		}
		prior.Requested += event.Requested
		prior.Bytes += event.Bytes
		prior.Operations += event.Operations
		prior.IOError = prior.IOError || event.IOError
		if event.Started.Elapsed < prior.Started.Elapsed {
			prior.Started = event.Started
		}
		if event.Completed.Elapsed > prior.Completed.Elapsed {
			prior.Completed = event.Completed
		}
		c.state.Events = append(c.state.Events[:index], c.state.Events[index+1:]...)
		return
	}
}

func (c *NativeCollector) persist() error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	return c.store.save(&c.state)
}

func (c *NativeCollector) Flush() (*usagev2.Submission, error) {
	if c.failed.Load() {
		return nil, ErrUnknown
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.state.Retired {
		return nil, ErrPending
	}
	err := c.store.seal(&c.state, time.Now().Unix(), false)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// Drain is called only after listener/I/O closure. Timed-out operations retain
// their original intent and any later completion in this retired collector.
func (c *NativeCollector) Drain(ctx context.Context) error {
	c.closed.Store(true)
	for c.inflight.Load() > 0 {
		select {
		case <-ctx.Done():
			goto seal
		case <-c.wake:
		}
	}
seal:
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.state.Retired {
		return nil
	}
	if err := c.store.seal(&c.state, 0, true); err != nil {
		return err
	}
	c.state.Retired = true
	for i := range c.state.Events {
		c.state.Events[i].Eligible = false
	}
	return c.store.saveOrRetire(&c.state)
}

// Caller holds the store lock (or owns startup recovery before publication).
func (s *NativeStore) seal(state *nativeState, boundary int64, final bool) error {
	if err := s.exportPending(state); err != nil {
		return err
	}
	var selected []nativeEvent
	for _, e := range state.Events {
		if !e.Done || !e.Eligible {
			continue
		}
		if final || e.Completed.Wall < boundary*int64(time.Second) {
			selected = append(selected, e)
			if final {
				end := e.Completed.Wall/int64(time.Second) + 1
				if end > boundary {
					boundary = end
				}
			}
		}
	}
	if !final {
		for _, e := range state.Events {
			if !e.Done && e.Started.Wall < boundary*int64(time.Second) ||
				e.Done && e.Started.Wall < boundary*int64(time.Second) && e.Completed.Wall >= boundary*int64(time.Second) {
				return ErrPending
			}
		}
	}
	if len(selected) == 0 {
		return nil
	}
	raw := map[int][2]int64{}
	sequences := []uint64{}
	for _, event := range selected {
		id, _ := strconv.Atoi(event.UserID)
		counters := raw[id]
		index := 0
		if event.Direction == "download" {
			index = 1
		}
		if event.Bytes > int64(usagev2.MaxRawBytes)-counters[index] {
			return ErrUnknown
		}
		counters[index] += event.Bytes
		raw[id] = counters
		sequences = append(sequences, event.Sequence)
	}
	if boundary <= state.StartedAt || boundary > state.Window.ExpiresAt {
		return ErrUnknown
	}
	batch, err := state.Session.Build(state.StartedAt, boundary, raw)
	if err != nil {
		return ErrUnknown
	}
	state.Pending = &usagev2.Record{SchemaVersion: 1, Session: state.Session, Submission: batch}
	state.PendingSequences, state.PendingEnd = sequences, boundary
	if err := s.save(state); err != nil {
		return err
	}
	return s.exportPending(state)
}

func (s *NativeStore) exportPending(state *nativeState) error {
	if state.Pending == nil {
		return nil
	}
	record := *state.Pending
	confirmed, err := s.spool.ConfirmCapture(record)
	if err != nil {
		return err
	}
	if !confirmed {
		records, err := s.spool.Records()
		if err != nil {
			return err
		}
		for _, old := range records {
			a, b := old.Submission.Payload, record.Submission.Payload
			if a.StartedAt < b.EndedAt && b.StartedAt < a.EndedAt {
				return ErrUnknown
			}
		}
		if err := s.spool.Save(record); err != nil {
			return err
		}
	}
	consumed := map[uint64]bool{}
	for _, sequence := range state.PendingSequences {
		consumed[sequence] = true
	}
	remaining := []nativeEvent{}
	for _, event := range state.Events {
		if !consumed[event.Sequence] {
			remaining = append(remaining, event)
		}
	}
	state.Events = remaining
	state.StartedAt = state.PendingEnd
	state.Pending, state.PendingSequences, state.PendingEnd = nil, []uint64{}, 0
	if state.StartedAt > s.marker.LastEnd {
		s.marker.LastEnd = state.StartedAt
		if s.marker.Version != 0 {
			if err := s.write(".native-source", s.marker); err != nil {
				return err
			}
		}
	}
	return s.save(state)
}

func (s *NativeStore) save(state *nativeState) error {
	if s.lock == nil || validateNativeState(*state) != nil {
		return ErrNativeStorage
	}
	return s.write(state.Collector+".native", state)
}

func (s *NativeStore) saveOrRetire(state *nativeState) error {
	if err := s.save(state); err != nil {
		return err
	}
	if state.Retired && len(state.Events) > 0 {
		s.quarantined.Add(1)
	}
	if state.Retired && len(state.Events) == 0 && state.Pending == nil {
		if s.marker.Version != 0 {
			if err := s.write(".native-source", s.marker); err != nil {
				return err
			}
		}
		if err := os.Remove(filepath.Join(s.dir, state.Collector+".native")); err != nil {
			return ErrNativeStorage
		}
		return syncDirectory(s.dir)
	}
	return nil
}

func (s *NativeStore) QuarantinedCollectors() int64 { return s.quarantined.Load() }

func (s *NativeStore) write(name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrNativeStorage
	}
	hash := sha256.Sum256(raw)
	encoded, err := json.Marshal(struct {
		Payload json.RawMessage `json:"payload"`
		Digest  string          `json:"digest"`
	}{raw, hex.EncodeToString(hash[:])})
	if err != nil || len(encoded) > nativeStateLimit {
		return ErrNativeStorage
	}
	f, err := os.CreateTemp(s.dir, ".native-write-")
	if err != nil {
		return ErrNativeStorage
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(encoded)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(s.dir, name))
	}
	if err == nil {
		err = syncDirectory(s.dir)
	}
	if err != nil {
		return ErrNativeStorage
	}
	return nil
}

func (s *NativeStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

func readNative(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > nativeStateLimit {
		return nil, ErrNativeStorage
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, nativeStateLimit+1))
}

func decodeNative(raw []byte, target any) error {
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
		Digest  string          `json:"digest"`
	}
	if usagev2.StrictDecode(raw, &envelope, nativeStateLimit) != nil {
		return ErrNativeStorage
	}
	hash := sha256.Sum256(envelope.Payload)
	if envelope.Digest != hex.EncodeToString(hash[:]) || usagev2.StrictDecode(envelope.Payload, target, nativeStateLimit) != nil {
		return ErrNativeStorage
	}
	return nil
}

func validNativeWindow(session usagev2.Session, window NativeWindow) bool {
	if usagev2.Decimal(window.Revision, false) != nil || len(window.Digest) != 64 || window.IssuedAt != session.IssuedAt || window.ExpiresAt <= window.IssuedAt || window.ExpiresAt-window.IssuedAt > 120 {
		return false
	}
	if _, err := hex.DecodeString(window.Digest); err != nil || strings.ToLower(window.Digest) != window.Digest {
		return false
	}
	for _, grant := range session.Grants {
		if grant.IssuedAt != window.IssuedAt || grant.LeaseExpiresAt != window.ExpiresAt {
			return false
		}
	}
	return true
}

func validateNativeState(state nativeState) error {
	if state.Version != 1 || !collectorName.MatchString(state.Collector) || state.Session.Validate() != nil ||
		!validNativeWindow(state.Session, state.Window) || state.StartedAt < state.Window.IssuedAt || state.StartedAt > state.Window.ExpiresAt ||
		state.Events == nil || len(state.Events) > MaxOperations || state.PendingSequences == nil {
		return ErrNativeStorage
	}
	grants := map[string]usagev2.Grant{}
	for _, grant := range state.Session.Grants {
		grants[grant.UserID] = grant
	}
	seen := map[uint64]bool{}
	for _, e := range state.Events {
		grant, ok := grants[e.UserID]
		if !ok || e.Sequence == 0 || e.Sequence > state.Sequence || seen[e.Sequence] || e.Operations == 0 || e.Operations > state.Sequence ||
			!e.Done && e.Operations != 1 || e.Requested < 0 || e.Requested > int64(usagev2.MaxRawBytes) ||
			!validStamp(e.Started) || !insideGrant(grant, e.Started.Wall) || (e.Direction != "upload" && e.Direction != "download") ||
			e.Bytes < 0 || e.Bytes > e.Requested || !e.Done && (e.Bytes != 0 || e.Eligible) ||
			e.Eligible && (!e.Done || state.Retired || e.Completed.Wall < e.Started.Wall || e.Completed.Elapsed < e.Started.Elapsed || !insideGrant(grant, e.Completed.Wall)) {
			return ErrNativeStorage
		}
		seen[e.Sequence] = true
	}
	if state.Pending != nil {
		if state.Pending.Validate() != nil || state.Pending.Receipt != nil || state.PendingEnd != state.Pending.Submission.Payload.EndedAt || len(state.PendingSequences) == 0 {
			return ErrNativeStorage
		}
		a, _ := json.Marshal(state.Pending.Session)
		b, _ := json.Marshal(state.Session)
		if !bytes.Equal(a, b) {
			return ErrNativeStorage
		}
		chosen := map[uint64]bool{}
		for _, sequence := range state.PendingSequences {
			if !seen[sequence] || chosen[sequence] {
				return ErrNativeStorage
			}
			chosen[sequence] = true
		}
		raw := map[int][2]int64{}
		p := state.Pending.Submission.Payload
		if p.StartedAt != state.StartedAt {
			return ErrNativeStorage
		}
		for _, e := range state.Events {
			if !chosen[e.Sequence] {
				continue
			}
			if !e.Done || !e.Eligible || e.Started.Wall < p.StartedAt*int64(time.Second) || e.Completed.Wall >= p.EndedAt*int64(time.Second) {
				return ErrNativeStorage
			}
			id, _ := strconv.Atoi(e.UserID)
			values := raw[id]
			index := 0
			if e.Direction == "download" {
				index = 1
			}
			if e.Bytes > int64(usagev2.MaxRawBytes)-values[index] {
				return ErrNativeStorage
			}
			values[index] += e.Bytes
			raw[id] = values
		}
		expected, err := state.Session.Build(p.StartedAt, p.EndedAt, raw)
		if err != nil {
			return ErrNativeStorage
		}
		expected.Payload.BatchID = p.BatchID
		a, _ = expected.Payload.Canonical()
		b, _ = p.Canonical()
		if !bytes.Equal(a, b) {
			return ErrNativeStorage
		}
	} else if len(state.PendingSequences) != 0 || state.PendingEnd != 0 {
		return ErrNativeStorage
	}
	return nil
}

func decimalCompare(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}
