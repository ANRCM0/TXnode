package core

import (
	"io"

	"net/netip"
	"sort"

	"sync"
	"sync/atomic"
	"time"
)

// userState is the per-user accounting record (core.userState, size 0x88).
type userState struct {
	User
	up      atomic.Int64
	down    atomic.Int64
	upLim   atomic.Pointer[Limiter]
	downLim atomic.Pointer[Limiter]
	mu      sync.Mutex
	ips     map[string]*ipState
	conns   map[io.Closer]struct{}
	others  int
	// manual marks a bucket set by SetUserLimit; applySpeedLocked must not
	// overwrite it when the user table is refreshed from the panel.
	manual    bool
	slowUntil time.Time
}

type ipState struct {
	conns int
	last  time.Time
	addr  string
}

// Tracker owns every user's usage, device set and speed limit. It mirrors
// core.Tracker (size 0x70).
type Tracker struct {
	mu                sync.RWMutex
	users             map[int]*userState
	retired           map[int]*userState
	globalSpeedLimit  int
	globalDeviceLimit int
	ipv6Prefix        int
	connLimit         int
	nodeUp            atomic.Pointer[Limiter]
	nodeDown          atomic.Pointer[Limiter]
	dyn               *DynamicLimit
	totalSessions     atomic.Int64
	deviceRefusals    atomic.Int64
	revocationCloses  atomic.Uint64
	userCloseRequests atomic.Uint64
	activeSince       map[int]time.Time
	deviceGate        DeviceGate
}

// DynamicLimit mirrors core.DynamicLimit (size 0x40).
type DynamicLimit struct {
	Trigger     time.Duration
	TriggerMbps int
	LimitMbps   int
	Duration    time.Duration
	Hours       []DayRange
	Exempt      map[int]bool
}

// NewTracker builds an empty tracker with the documented defaults.
func NewTracker() *Tracker {
	return &Tracker{
		users:       make(map[int]*userState),
		retired:     make(map[int]*userState),
		ipv6Prefix:  64,
		activeSince: make(map[int]time.Time),
	}
}

// SetUsers replaces the user table, preserving traffic counters of users that
// remain, exactly as applyUsers/Tracker.SetUsers does.
func (t *Tracker) SetUsers(users []User) {
	t.mu.Lock()
	next := make(map[int]*userState, len(users))
	var closeAfter []io.Closer
	for _, u := range users {
		if old, ok := t.users[u.ID]; ok {
			if old.UUID != u.UUID {
				old.mu.Lock()
				for c := range old.conns {
					closeAfter = append(closeAfter, c)
				}
				old.mu.Unlock()
			}
			old.User = u
			next[u.ID] = old
			continue
		}
		if old := t.retired[u.ID]; old != nil {
			old.User = u
			next[u.ID] = old
			delete(t.retired, u.ID)
			continue
		}
		next[u.ID] = &userState{
			User:  u,
			ips:   make(map[string]*ipState),
			conns: make(map[io.Closer]struct{}),
		}
	}
	for id, old := range t.users {
		if next[id] != nil {
			continue
		}
		t.retired[id] = old
		old.mu.Lock()
		for c := range old.conns {
			closeAfter = append(closeAfter, c)
		}
		old.mu.Unlock()
	}
	t.users = next
	t.applySpeedLocked()
	t.mu.Unlock()
	// Close outside the tracker lock: session teardown may record final traffic.
	t.revocationCloses.Add(uint64(len(closeAfter)))
	for _, c := range closeAfter {
		_ = c.Close()
	}
}

// SetGlobalSpeedLimit sets user_speed_limit (Mbps).
func (t *Tracker) SetGlobalSpeedLimit(mbps int) {
	t.mu.Lock()
	t.globalSpeedLimit = mbps
	t.applySpeedLocked()
	t.mu.Unlock()
}

// SetGlobalDeviceLimit sets user_device_limit (concurrent devices per user).
func (t *Tracker) SetGlobalDeviceLimit(n int) {
	t.mu.Lock()
	t.globalDeviceLimit = n
	t.mu.Unlock()
}

// SetIPv6Prefix sets device_ipv6_prefix.
func (t *Tracker) SetIPv6Prefix(bits int) {
	if bits <= 0 || bits > 128 {
		bits = 64
	}
	t.mu.Lock()
	t.ipv6Prefix = bits
	t.mu.Unlock()
}

// SetConnLimit sets user_tcp_limit.
func (t *Tracker) SetConnLimit(n int) {
	t.mu.Lock()
	t.connLimit = n
	t.mu.Unlock()
}

// SetNodeSpeedLimit sets node_speed_limit (Mbps) as independent up/down
// buckets, matching SetNodeSpeedLimit's atomic pointers.
func (t *Tracker) SetNodeSpeedLimit(mbps int) {
	r := mbpsToBytes(mbps)
	t.nodeUp.Store(NewLimiter(r))
	t.nodeDown.Store(NewLimiter(r))
}

// SetDynamicLimit installs dy_limit_* and starts the evaluator. A nil limit
// disables the feature.
func (t *Tracker) SetDynamicLimit(d *DynamicLimit) {
	t.mu.Lock()
	t.dyn = d
	t.mu.Unlock()
	if d != nil {
		go t.watch(d)
	}
}

func (t *Tracker) watch(d *DynamicLimit) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for range tick.C {
		t.mu.Lock()
		if t.dyn != d {
			t.mu.Unlock()
			return
		}
		active := d.active(time.Now())
		for _, u := range t.users {
			u.mu.Lock()
			if active && !d.Exempt[u.ID] {
				u.slowUntil = time.Now().Add(d.Duration)
			} else if !active {
				u.slowUntil = time.Time{}
			}
			u.mu.Unlock()
		}
		t.applySpeedLocked()
		t.mu.Unlock()
	}
}

func (d *DynamicLimit) active(now time.Time) bool {
	if len(d.Hours) == 0 {
		return true
	}
	for _, h := range d.Hours {
		if h.Contains(now) {
			return true
		}
	}
	return false
}

// speedFor is the original's combination rule: the smallest non-zero of the
// global cap, the per-user cap and the dynamic cap.
func (t *Tracker) speedFor(u *userState) int {
	cap := t.globalSpeedLimit
	if cap > 0 && u.SpeedLimit != 0 && cap >= u.SpeedLimit {
		cap = u.SpeedLimit
	} else if cap == 0 {
		cap = u.SpeedLimit
	}
	if u.slowUntil.IsZero() {
		return cap
	}
	if t.dyn == nil || t.dyn.LimitMbps <= 0 {
		return cap
	}
	if cap == 0 || cap > t.dyn.LimitMbps {
		return t.dyn.LimitMbps
	}
	return cap
}

func (t *Tracker) applySpeedLocked() {
	for _, u := range t.users {
		if u.manual {
			continue
		}
		r := mbpsToBytes(t.speedFor(u))
		up := u.upLim.Load()
		if up == nil {
			u.upLim.Store(NewLimiter(r))
			u.downLim.Store(NewLimiter(r))
			continue
		}
		up.SetRate(r)
		u.downLim.Load().SetRate(r)
	}
}

// Limiters returns the up/down buckets for a user. Buckets are only created
// when the user is actually rate limited: an unlimited session must not pay for
// two limiter allocations (and their mutexes) on the hot path.
func (t *Tracker) Limiters(userID int) (up, down *Limiter) {
	t.mu.RLock()
	u := t.users[userID]
	t.mu.RUnlock()
	if u == nil {
		return nil, nil
	}
	if b := u.upLim.Load(); b != nil {
		return b, u.downLim.Load()
	}
	t.mu.Lock()
	if r := mbpsToBytes(t.speedFor(u)); r > 0 {
		u.upLim.Store(NewLimiter(r))
		u.downLim.Store(NewLimiter(r))
	}
	up, down = u.upLim.Load(), u.downLim.Load()
	t.mu.Unlock()
	return up, down
}

// SetUserLimit installs one user's byte/s ceilings and token ceiling. This is
// the TX-Node path: limiter.SpeedTracker is the authority for rate and burst,
// so the tracker must not derive them from the panel Mbps field (SpeedLimit).
// rate <= 0 removes the limit; burst <= 0 keeps the sample's 0.25*rate.
func (t *Tracker) SetUserLimit(userID int, upBps, downBps, burst int64) {
	t.mu.Lock()
	u := t.users[userID]
	if u == nil {
		t.mu.Unlock()
		return
	}
	u.manual = true
	up := u.upLim.Load()
	down := u.downLim.Load()
	if up == nil {
		up = NewLimiter(0)
		u.upLim.Store(up)
	}
	if down == nil {
		down = NewLimiter(0)
		u.downLim.Store(down)
	}
	t.mu.Unlock()
	up.SetRate(upBps)
	up.SetBurst(burst)
	down.SetRate(downBps)
	down.SetBurst(burst)
}

// SetUserDeviceLimit updates one user's concurrent-device ceiling.
func (t *Tracker) SetUserDeviceLimit(userID, n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if u := t.users[userID]; u != nil {
		u.DeviceLimit = n
	}
}

// DeviceGate replaces the built-in device check. TX-Node implements the panel
// merge (local addresses + the panel's global device set) here; the implementation
// must not call back into the Tracker.
type DeviceGate interface {
	// Allow reports whether src may open another session for userID. local maps
	// the locally live device keys to their connection counts.
	Allow(userID int, src netip.Addr, local map[string]int) bool
}

// SetDeviceGate installs the optional device gate. nil restores the built-in
// per-user/global device limit.
func (t *Tracker) SetDeviceGate(g DeviceGate) {
	t.mu.Lock()
	t.deviceGate = g
	t.mu.Unlock()
}

// CloseUserConns closes every tracked session of one user and reports how many
// were closed. It is the kernel.RemoveUsers path (a removed user must lose its
// live sessions immediately, as the sing-box runtime did).
func (t *Tracker) CloseUserConns(userID int) int {
	t.mu.RLock()
	u := t.users[userID]
	if u == nil {
		u = t.retired[userID]
	}
	t.mu.RUnlock()
	if u == nil {
		return 0
	}
	u.mu.Lock()
	closers := make([]io.Closer, 0, len(u.conns))
	for c := range u.conns {
		closers = append(closers, c)
	}
	u.mu.Unlock()
	t.userCloseRequests.Add(uint64(len(closers)))
	for _, c := range closers {
		_ = c.Close()
	}
	return len(closers)
}

// Lease is a granted session slot. Release returns the connection and device
// quota exactly once.
type Lease struct {
	t      *Tracker
	u      *userState
	ip     string
	closer io.Closer
	once   sync.Once
}

// Acquire admits one session for userID from src. It enforces conn limit,
// device limit and the online-user cap. A nil lease with ok=false means the
// session is refused.
func (t *Tracker) Acquire(userID int, src netip.Addr, closer io.Closer) (*Lease, bool) {
	return t.AcquireAuthenticated(userID, src, closer, nil)
}

// AcquireAuthenticated checks the credential generation while holding the same
// lock that replaces users, so an in-flight obsolete handshake cannot reopen
// a revoked user's slot.
func (t *Tracker) AcquireAuthenticated(userID int, src netip.Addr, closer io.Closer, valid func() bool) (*Lease, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if valid != nil && !valid() {
		return nil, false
	}
	u := t.users[userID]
	if u == nil {
		return nil, false
	}
	now := time.Now()
	key := t.deviceKey(src)
	u.mu.Lock()
	defer u.mu.Unlock()
	if t.connLimit > 0 && len(u.conns) >= t.connLimit {
		return nil, false
	}
	st := u.ips[key]
	limit := t.globalDeviceLimit
	if u.DeviceLimit > 0 && (limit == 0 || u.DeviceLimit < limit) {
		limit = u.DeviceLimit
	}
	if t.deviceGate != nil {
		local := make(map[string]int, len(u.ips))
		for k, state := range u.ips {
			local[k] = state.conns
		}
		if !t.deviceGate.Allow(userID, src, local) {
			t.deviceRefusals.Add(1)
			return nil, false
		}
	} else if limit > 0 && (st == nil || st.conns == 0) && len(u.ips) >= limit {
		t.deviceRefusals.Add(1)
		return nil, false
	}
	if st == nil {
		st = &ipState{addr: src.String(), last: now}
		u.ips[key] = st
	}
	st.conns++
	st.last = now
	if closer != nil {
		u.conns[closer] = struct{}{}
	}
	t.totalSessions.Add(1)
	return &Lease{t: t, u: u, ip: key, closer: closer}, true
}

func (t *Tracker) deviceKey(src netip.Addr) string {
	if !src.IsValid() {
		return ""
	}
	src = src.Unmap()
	if src.Is6() {
		bits := t.ipv6Prefix
		if bits <= 0 || bits > 128 {
			bits = 64
		}
		p, err := src.Prefix(bits)
		if err == nil {
			return p.String()
		}
	}
	return src.String()
}

// Release returns this lease's quota.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		u := l.u
		u.mu.Lock()
		if st := u.ips[l.ip]; st != nil {
			st.conns--
			if st.conns <= 0 {
				delete(u.ips, l.ip)
			}
		}
		if l.closer != nil {
			delete(u.conns, l.closer)
		}
		u.mu.Unlock()
	})
}

// Traffic records bytes for a user (up = client->remote, down = remote->client).
func (t *Tracker) Traffic(userID int, up, down int64) {
	t.mu.RLock()
	u := t.users[userID]
	if u == nil {
		u = t.retired[userID]
	}
	t.mu.RUnlock()
	if u == nil {
		return
	}
	if up > 0 {
		u.up.Add(up)
	}
	if down > 0 {
		u.down.Add(down)
	}
}

// TrafficOf returns cumulative up/down counters.
func (t *Tracker) TrafficOf(userID int) (up, down int64) {
	t.mu.RLock()
	u := t.users[userID]
	if u == nil {
		u = t.retired[userID]
	}
	t.mu.RUnlock()
	if u == nil {
		return 0, 0
	}
	return u.up.Load(), u.down.Load()
}

// Snapshot returns the traffic map in panel report shape.
func (t *Tracker) Snapshot() map[int][2]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[int][2]int64, len(t.users))
	for id, u := range t.retired {
		out[id] = [2]int64{u.up.Load(), u.down.Load()}
	}
	for id, u := range t.users {
		out[id] = [2]int64{u.up.Load(), u.down.Load()}
	}
	return out
}

// Connections returns live connection counts per user.
func (t *Tracker) Connections() map[int]int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[int]int, len(t.users))
	for id, u := range t.users {
		u.mu.Lock()
		out[id] = len(u.conns)
		u.mu.Unlock()
	}
	return out
}

// Alive returns the live device addresses per user, for AliveList reporting.
func (t *Tracker) Alive() map[int][]string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[int][]string, len(t.users))
	for id, u := range t.users {
		u.mu.Lock()
		ips := make([]string, 0, len(u.ips))
		for _, st := range u.ips {
			ips = append(ips, st.addr)
		}
		u.mu.Unlock()
		if len(ips) > 0 {
			sort.Strings(ips)
			out[id] = ips
		}
	}
	return out
}

// SetGlobalAlive applies the panel's sync.devices numbers: userState.others is
// max(0, reported - locally live addresses), as observed at 0x7bc11c.
func (t *Tracker) SetGlobalAlive(reported map[int]int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, u := range t.users {
		u.mu.Lock()
		local := 0
		for _, st := range u.ips {
			if st.conns > 0 {
				local++
			}
		}
		n := reported[id] - local
		if n < 0 {
			n = 0
		}
		u.others = n
		u.mu.Unlock()
	}
}

// Online returns the panel online counter per user (local + panel-reported
// external devices).
func (t *Tracker) Online() map[int]int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[int]int, len(t.users))
	for id, u := range t.users {
		u.mu.Lock()
		n := u.others
		for _, st := range u.ips {
			if st.conns > 0 {
				n++
			}
		}
		u.mu.Unlock()
		if n > 0 {
			out[id] = n
		}
	}
	return out
}

// TotalUsers counts admitted users.
func (t *Tracker) TotalUsers() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.users)
}

// TotalSessions returns the lifetime session count.
func (t *Tracker) TotalSessions() int64 { return t.totalSessions.Load() }

// DeviceRefusals returns the lifetime device-limit refusal count.
func (t *Tracker) DeviceRefusals() int64 { return t.deviceRefusals.Load() }

// CloseDiagnostics uses fixed reasons and never exposes credential identities.
func (t *Tracker) CloseDiagnostics() (revoked, requested uint64) {
	return t.revocationCloses.Load(), t.userCloseRequests.Load()
}

// Users returns the current user list ordered by ID.
func (t *Tracker) Users() []User {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]User, 0, len(t.users))
	for _, u := range t.users {
		out = append(out, u.User)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// UserByUUID finds a user by credential for protocols that authenticate by
// UUID or password.
func (t *Tracker) UserByUUID(uuid string) (User, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, u := range t.users {
		if u.UUID == uuid {
			return u.User, true
		}
	}
	return User{}, false
}

// NodeLimiters returns the node-wide buckets (may be nil).
func (t *Tracker) NodeLimiters() (up, down *Limiter) {
	return t.nodeUp.Load(), t.nodeDown.Load()
}
