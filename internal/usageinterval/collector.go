// Package usageinterval joins actual bounded direct-I/O evidence to a frozen
// Core usage-v2 Session. It is an explicit prototype, never an admission grant.
package usageinterval

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

var (
	ErrUnknown = errors.New("USAGE_INTERVAL_UNKNOWN")
	ErrPending = errors.New("USAGE_INTERVAL_BOUNDARY_PENDING")
)

const MaxOperations = 1024
const MaxGrants = 128

type stamp struct {
	Wall    int64 `json:"wall_nanos,string"`
	Elapsed int64 `json:"elapsed_nanos,string"`
}
type Evidence struct {
	Sequence  uint64 `json:"sequence,string"`
	UserID    string `json:"user_id"`
	Started   stamp  `json:"started"`
	Completed stamp  `json:"completed"`
	Direction string `json:"direction"`
	Bytes     int64  `json:"bytes,string"`
	IOError   bool   `json:"io_error"`
}

type Operation struct {
	owner    *Collector
	sequence uint64
	user     string
	started  stamp
}

type Collector struct {
	mu        sync.Mutex
	flushMu   sync.Mutex
	journal   *Journal
	session   usagev2.Session
	grants    map[string]usagev2.Grant
	users     map[string]int
	identity  string
	started   int64
	sequence  uint64
	interval  uint64
	last      stamp
	clock     func() stamp
	inflight  map[uint64]*Operation
	completed []Evidence
	pending   *claim
	deadline  int64
	terminal  bool
	closed    bool
}

func New(session usagev2.Session, users map[string]int, journal *Journal) (*Collector, error) {
	origin := time.Now()
	return newCollector(session, users, journal, func() stamp { now := time.Now(); return stamp{now.UnixNano(), int64(now.Sub(origin))} })
}

func newCollector(session usagev2.Session, users map[string]int, journal *Journal, clock func() stamp) (*Collector, error) {
	if journal == nil || clock == nil || session.Validate() != nil || len(session.Grants) == 0 || len(session.Grants) > MaxGrants || len(users) != len(session.Grants) {
		return nil, ErrUnknown
	}
	frozen, _ := json.Marshal(session)
	var copied usagev2.Session
	if json.Unmarshal(frozen, &copied) != nil {
		return nil, ErrUnknown
	}
	c := &Collector{journal: journal, session: copied, grants: map[string]usagev2.Grant{}, users: map[string]int{}, clock: clock, inflight: map[uint64]*Operation{}}
	for _, g := range copied.Grants {
		c.grants[g.UserID] = g
	}
	seen := map[int]bool{}
	for label, id := range users {
		if label == "" || len(label) > 256 || id <= 0 || id > 2147483647 || seen[id] {
			return nil, ErrUnknown
		}
		if _, exists := c.grants[strconv.Itoa(id)]; !exists {
			return nil, ErrUnknown
		}
		seen[id] = true
		c.users[label] = id
	}
	c.last = clock()
	if !validStamp(c.last) {
		return nil, ErrUnknown
	}
	c.started = c.last.Wall / int64(time.Second)
	for _, g := range copied.Grants {
		if c.started < g.IssuedAt || c.started >= g.LeaseExpiresAt {
			return nil, ErrUnknown
		}
	}
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, ErrUnknown
	}
	c.identity = hex.EncodeToString(identity[:])
	if err := journal.startCollector(copied, c.identity); err != nil {
		return nil, err
	}
	next := clock()
	if !validStamp(next) || next.Wall < c.last.Wall || next.Elapsed < c.last.Elapsed {
		return nil, ErrUnknown
	}
	c.last = next
	c.started = c.last.Wall / int64(time.Second)
	for _, g := range copied.Grants {
		if c.started < g.IssuedAt || c.started >= g.LeaseExpiresAt {
			return nil, ErrUnknown
		}
	}

	c.deadline = math.MaxInt64
	for _, g := range copied.Grants {
		if g.LeaseExpiresAt > 9223372036 {
			return nil, ErrUnknown
		}
		remaining := g.LeaseExpiresAt*int64(time.Second) - c.last.Wall
		if remaining <= 0 || remaining > int64(time.Hour) || c.last.Elapsed > math.MaxInt64-remaining {
			return nil, ErrUnknown
		}
		deadline := c.last.Elapsed + remaining
		if deadline < c.deadline {
			c.deadline = deadline
		}
	}
	return c, nil
}

func (c *Collector) Fail() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.terminal = true
	c.mu.Unlock()
}

// CheckUsers detects local identity updates; no caller may rebind old counters.
func (c *Collector) CheckUsers(users map[string]int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(users) != len(c.users) {
		c.terminal = true
		return
	}
	for key, id := range c.users {
		if users[key] != id {
			c.terminal = true
			return
		}
	}
}

func (c *Collector) sample() (stamp, bool) {
	s := c.clock()
	if !validStamp(s) || s.Wall < c.last.Wall || s.Elapsed < c.last.Elapsed || s.Elapsed >= c.deadline {
		c.terminal = true
		return s, false
	}
	c.last = s
	return s, true
}
func validStamp(s stamp) bool { return s.Wall >= 0 && s.Elapsed >= 0 }

func (c *Collector) Begin(userID int) *Operation {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal || c.closed {
		return nil
	}
	at, ok := c.sample()
	if !ok {
		return nil
	}
	user := strconv.Itoa(userID)
	g, exists := c.grants[user]
	if !exists || userID <= 0 || userID > 2147483647 || at.Wall/int64(time.Second) < c.started || !insideGrant(g, at.Wall) || len(c.inflight)+len(c.completed) >= MaxOperations || c.sequence == math.MaxUint64 {
		c.terminal = true
		return nil
	}
	c.sequence++
	op := &Operation{c, c.sequence, user, at}
	c.inflight[op.sequence] = op
	return op
}

func (c *Collector) Complete(op *Operation, direction string, n int64, ioError bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if op == nil || op.owner != c || c.inflight[op.sequence] != op {
		c.terminal = true
		return
	}
	delete(c.inflight, op.sequence)
	at, ok := c.sample()
	g := c.grants[op.user]
	if !ok || c.closed || n < 0 || n > int64(usagev2.MaxRawBytes) || (direction != "upload" && direction != "download") || at.Wall < op.started.Wall || at.Elapsed < op.started.Elapsed || !insideGrant(g, at.Wall) || len(c.completed) >= MaxOperations {
		c.terminal = true
		return
	}
	// Even after fail-stop, keep bounded completed evidence for diagnostics. It
	// cannot be exported as a valid interval while terminal is set.
	c.completed = append(c.completed, Evidence{op.sequence, op.user, op.started, at, direction, n, ioError})
}
func insideGrant(g usagev2.Grant, nanos int64) bool {
	return nanos/int64(time.Second) >= g.IssuedAt && nanos/int64(time.Second) < g.LeaseExpiresAt
}

// Flush retains every operation that cannot yet fit a complete integer boundary.
// Disk work is serialized separately; Begin/Complete continue into the next pane.
func (c *Collector) Flush() (*usagev2.Submission, error) {
	if c == nil {
		return nil, ErrUnknown
	}
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	c.mu.Lock()
	if c.pending != nil {
		claim := c.pending
		c.mu.Unlock()
		if err := c.journal.commit(claim); err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.pending = nil
		c.mu.Unlock()
		copy := claim.Record.Submission
		return &copy, nil
	}
	if c.terminal || c.closed {
		c.mu.Unlock()
		return nil, ErrUnknown
	}
	now, ok := c.sample()
	if !ok {
		c.mu.Unlock()
		return nil, ErrUnknown
	}
	boundary := now.Wall / int64(time.Second)
	if boundary <= c.started {
		c.mu.Unlock()
		return nil, ErrPending
	}
	cutoff := boundary * int64(time.Second)
	for _, op := range c.inflight {
		if op.started.Wall < cutoff {
			c.mu.Unlock()
			return nil, ErrPending
		}
	}
	var selected, retained []Evidence
	for _, event := range c.completed {
		if event.Started.Wall < cutoff && event.Completed.Wall >= cutoff {
			c.mu.Unlock()
			return nil, ErrPending
		}
		if event.Completed.Wall < cutoff {
			selected = append(selected, event)
		} else {
			retained = append(retained, event)
		}
	}
	raw := map[int][2]int64{}
	for _, e := range selected {
		id, _ := strconv.Atoi(e.UserID)
		v := raw[id]
		index := 0
		if e.Direction == "download" {
			index = 1
		}
		if e.Bytes > int64(usagev2.MaxRawBytes)-v[index] {
			c.terminal = true
			c.mu.Unlock()
			return nil, ErrUnknown
		}
		v[index] += e.Bytes
		raw[id] = v
	}
	nonzero := false
	for _, v := range raw {
		nonzero = nonzero || v[0] > 0 || v[1] > 0
	}
	if !nonzero {
		c.completed = retained
		c.started = boundary
		c.mu.Unlock()
		return nil, ErrPending
	}
	submission, err := c.session.Build(c.started, boundary, raw)
	if err != nil {
		c.terminal = true
		c.mu.Unlock()
		return nil, ErrUnknown
	}
	c.interval++
	claim, err := makeClaim(c.identity, c.interval, c.session, submission, selected)
	if err != nil {
		c.terminal = true
		c.mu.Unlock()
		return nil, err
	}
	c.pending = claim
	c.completed = retained
	c.started = boundary
	c.mu.Unlock()
	if err := c.journal.commit(claim); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.pending = nil
	c.mu.Unlock()
	copy := claim.Record.Submission
	return &copy, nil
}

// Close never invents a final interval; unsealed/in-flight tail stays unknown.
func (c *Collector) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

func (c *Collector) Unknown() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terminal || c.closed
}
