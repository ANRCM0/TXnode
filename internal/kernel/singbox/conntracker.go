package singbox

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"

	"github.com/ANRCM0/TX-Node/internal/audit"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
)

// ipPool caches ipSnapshot maps to reduce allocations.
var ipPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]struct{}, 16)
	},
}

// ─── Per-user statistics ────────────────────────────────────────────────────

// userStats holds per-user traffic counters and alive IP tracking.
// Traffic counters are lock-free atomics (read on every packet).
// IP tracking uses a lightweight mutex (only touched at connect/disconnect).
type userStats struct {
	upload   atomic.Int64
	download atomic.Int64

	mu        sync.RWMutex   // RWMutex for concurrent reads
	ips       map[string]int // sourceIP → refcount (number of active conns from that IP)
	connCount int            // total active connections
}

// addConn registers a new connection from sourceIP.
func (u *userStats) addConn(sourceIP string) {
	u.mu.Lock()
	u.connCount++
	u.ips[sourceIP]++
	u.mu.Unlock()
}

// removeConn unregisters a connection from sourceIP.
func (u *userStats) removeConn(sourceIP string) {
	u.mu.Lock()
	u.connCount--
	u.ips[sourceIP]--
	if u.ips[sourceIP] <= 0 {
		delete(u.ips, sourceIP)
	}
	u.mu.Unlock()
}

// distinctIPs returns the number of distinct IPs currently connected.
func (u *userStats) distinctIPs() int {
	u.mu.Lock()
	n := len(u.ips)
	u.mu.Unlock()
	return n
}

// ipSnapshot returns a pooled copy of the current IP set.
func (u *userStats) ipSnapshot() map[string]struct{} {
	cp := ipPool.Get().(map[string]struct{})
	for k := range cp {
		delete(cp, k)
	}
	u.mu.Lock()
	for ip := range u.ips {
		cp[ip] = struct{}{}
	}
	u.mu.Unlock()
	return cp
}

// releaseIPSnapshot returns the snapshot to pool.
// Large maps are discarded to prevent memory bloat.
func releaseIPSnapshot(m map[string]struct{}) {
	// Discard large maps to prevent pool memory bloat
	if len(m) > 64 {
		return
	}
	ipPool.Put(m)
}

// aliveIPList returns the set of alive IPs as a boolean map (for reporting).
func (u *userStats) aliveIPList() map[string]bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.ips) == 0 {
		return nil
	}
	result := make(map[string]bool, len(u.ips))
	for ip := range u.ips {
		result[ip] = true
	}
	return result
}

// ─── ConnTracker ────────────────────────────────────────────────────────────

// ConnTracker provides per-user traffic counting, alive IP tracking, device
// limit gate-keeping, and per-user speed limiting for the sing-box kernel.
//
// Accounting uses per-user atomic counters and IP refcount sets (O(users)).
// A separate connection registry holds closers for TCP and UDP termination.
// This means:
//   - GetUserTraffic is O(users), not O(connections)
//   - No Snapshot/pending buffer needed
//   - No per-connection map lock contention
//   - Bytes are counted directly into per-user atomics via CountFunc callbacks
//
// The per-connection wrapper (trackedConn) is still needed for:
//   - Hooking into sing's ReadCounter/WriteCounter for zero-copy byte counting
//   - Close callback to decrement IP refcounts
//   - Per-connection rate limit token accumulation (amortized WaitN)
type ConnTracker struct {
	usersMu sync.RWMutex
	users   map[int]*userStats           // userID → stats
	uuidMap map[string]int               // UUID → userID (for lookup in RoutedConnection)
	connMap map[string]trackedConnection // connID → tracked wrapper, including UDP

	idCounter            atomic.Int64
	authorizationExpired atomic.Bool

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	speedLimitFunc atomic.Pointer[func(uuid string) *rate.Limiter]

	// deviceLimitFunc resolves a user UUID to their device limit.
	deviceLimitFunc atomic.Pointer[func(uuid string) (int, bool)]

	// Multi-node device state from panel
	globalDevices    map[int]map[string]bool // userID → IP → exists
	globalMu         sync.RWMutex
	globalLastUpdate time.Time

	// auditor is the tx-node audit reporter (nil = disabled, zero overhead).
	auditor *audit.Reporter
	// Fixed at construction; nil on the ordinary runtime path.
	eventBuckets   *usagebucket.Meter
	boundedUsage   boundedCollector
	nativeUsage    bool
	enforceBounded bool
}

type trackedConnection struct {
	uuid   string
	userID int
	closer io.Closer
}

// NewConnTracker creates a tracker.
func NewConnTracker(_ int) *ConnTracker {
	return &ConnTracker{
		users:         make(map[int]*userStats),
		uuidMap:       make(map[string]int),
		connMap:       make(map[string]trackedConnection),
		globalDevices: make(map[int]map[string]bool),
	}
}

// SetSpeedLimitFunc configures the per-user speed limit lookup.
func (t *ConnTracker) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	t.speedLimitFunc.Store(&fn)
}

// SetDeviceLimitFunc configures the per-user device limit lookup for gate-keeping.
func (t *ConnTracker) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	t.deviceLimitFunc.Store(&fn)
}

// SetUserMap replaces the UUID→userID mapping and ensures per-user stats
// structs exist for all users. Removed/reassigned identities cannot register
// another connection; their established TCP and UDP wrappers are closed.
// Cumulative stats are retained so the final bytes remain reportable.
func (t *ConnTracker) SetUserMap(m map[string]int) {
	if t.boundedUsage != nil {
		t.boundedUsage.CheckUsers(m)
	}
	next := make(map[string]int, len(m))
	for uuid, uid := range m {
		if uuid != "" && uid > 0 {
			next[uuid] = uid
		}
	}
	t.usersMu.Lock()
	t.uuidMap = next
	for _, uid := range next {
		if _, ok := t.users[uid]; !ok {
			t.users[uid] = &userStats{ips: make(map[string]int)}
		}
	}
	var removed []io.Closer
	for _, connection := range t.connMap {
		if next[connection.uuid] != connection.userID {
			removed = append(removed, connection.closer)
		}
	}
	t.usersMu.Unlock()
	// Close callbacks remove registry entries and IP references. Never perform
	// network I/O or invoke those callbacks while holding the registry lock.
	for _, connection := range removed {
		_ = connection.Close()
	}
}

func (t *ConnTracker) register(uuid, id string, uid int, us *userStats, sourceIP string, closer io.Closer) bool {
	t.usersMu.Lock()
	defer t.usersMu.Unlock()
	// Recheck after device/speed callbacks: user removal can happen while they
	// run. This check and insertion share the same lock as SetUserMap.
	if t.authorizationExpired.Load() || uid <= 0 || us == nil || t.uuidMap[uuid] != uid || t.users[uid] != us {
		return false
	}
	us.addConn(sourceIP)
	t.connMap[id] = trackedConnection{uuid: uuid, userID: uid, closer: closer}
	return true
}

// UpdateGlobalDevices syncs global device state from panel.
func (t *ConnTracker) UpdateGlobalDevices(users map[int][]string) {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		m := make(map[string]bool, len(ips))
		for _, ip := range ips {
			m[ip] = true
		}
		t.globalDevices[uid] = m
	}
	t.globalLastUpdate = time.Now()
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state updated", "users", len(users))
}

// ClearGlobalDevices resets global device state (on WS disconnect).
func (t *ConnTracker) ClearGlobalDevices() {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool)
	t.globalLastUpdate = time.Time{}
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state cleared")
}

// SetAuditor injects the tx-node audit reporter. Called once at Start.
func (t *ConnTracker) SetAuditor(r *audit.Reporter) {
	t.auditor = r
}

// auditTarget extracts the logical audit target from connection metadata:
// sniffed domain > destination FQDN > destination IP.
func auditTarget(metadata adapter.InboundContext) string {
	if metadata.Domain != "" {
		return metadata.Domain
	}
	if fqdn := metadata.Destination.Fqdn; fqdn != "" {
		return fqdn
	}
	if metadata.Destination.IsValid() {
		return metadata.Destination.Addr.String()
	}
	return ""
}

// ─── adapter.ConnectionTracker ──────────────────────────────────────────────

// RoutedConnection wraps a TCP conn to count bytes per-user, track IPs,
// and optionally rate-limit. Gate-keeps device limits at connection time.
func (t *ConnTracker) RoutedConnection(
	ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) net.Conn {
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	t.usersMu.RUnlock()
	if uid <= 0 || us == nil {
		if t.boundedUsage != nil {
			t.boundedUsage.Fail()
		}
		_ = conn.Close()
		return conn
	}

	// Device limit gate-keeping
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if limit, hasLimit := (*dlf)(uuid); hasLimit {
			if t.checkDeviceGate(us, uid, sourceIP, limit) {
				nlog.Core().Info("singbox: device limit gate-keep, rejecting connection",
					"user", uuid, "ip", sourceIP, "limit", limit)
				conn.Close()
				return conn
			}
		}
	}

	logicalTarget := ""
	if t.auditor != nil && uid > 0 {
		logicalTarget = auditTarget(metadata)
	}

	connID := t.nextID()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	connectionCtx, cancel := context.WithCancel(ctx)
	wrapped := &trackedConn{
		Conn:        conn,
		tracker:     t,
		us:          us,
		userID:      uid,
		connID:      connID,
		sourceIP:    sourceIP,
		auditTarget: logicalTarget,
		limiter:     lim,
		ctx:         connectionCtx,
		cancel:      cancel,
	}
	if t.eventBuckets != nil {
		wrapped.bucketSession = t.eventBuckets.Bind(uid, connID, "tcp")
	}
	if !t.register(uuid, connID, uid, us, sourceIP, wrapped) {
		if wrapped.bucketSession != nil {
			wrapped.bucketSession.Close()
		}
		cancel()
		_ = conn.Close()
		return conn
	}
	if t.boundedUsage != nil {
		return &boundedTCPView{base: wrapped}
	}
	return wrapped
}

// RoutedPacketConnection wraps and registers UDP with the same admission and
// termination semantics as TCP.
func (t *ConnTracker) RoutedPacketConnection(
	ctx context.Context, conn N.PacketConn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	if t.boundedUsage != nil {
		t.boundedUsage.Fail()
		if t.enforceBounded {
			_ = conn.Close()
			return conn
		}
	}
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	t.usersMu.RUnlock()
	if uid <= 0 || us == nil {
		_ = conn.Close()
		return conn
	}

	// Device limit gate-keeping
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if limit, hasLimit := (*dlf)(uuid); hasLimit {
			if t.checkDeviceGate(us, uid, sourceIP, limit) {
				nlog.Core().Info("singbox: device limit gate-keep, rejecting UDP connection",
					"user", uuid, "ip", sourceIP, "limit", limit)
				conn.Close()
				return conn
			}
		}
	}

	logicalTarget := ""
	if t.auditor != nil && uid > 0 {
		logicalTarget = auditTarget(metadata)
	}

	connID := t.nextID()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	connectionCtx, cancel := context.WithCancel(ctx)
	wrapped := &trackedPacketConn{
		PacketConn:  conn,
		tracker:     t,
		us:          us,
		userID:      uid,
		connID:      connID,
		sourceIP:    sourceIP,
		auditTarget: logicalTarget,
		limiter:     lim,
		ctx:         connectionCtx,
		cancel:      cancel,
	}
	if t.eventBuckets != nil {
		wrapped.bucketSession = t.eventBuckets.Bind(uid, connID, "udp")
	}
	if !t.register(uuid, connID, uid, us, sourceIP, wrapped) {
		if wrapped.bucketSession != nil {
			wrapped.bucketSession.Close()
		}
		cancel()
		_ = conn.Close()
		return conn
	}
	return wrapped
}

// checkDeviceGate rejects connections exceeding device limit.
// Strategy: merge local + global state when fresh; local-only when stale.
func (t *ConnTracker) checkDeviceGate(us *userStats, userID int, sourceIP string, limit int) bool {
	if us == nil || limit <= 0 {
		return false
	}

	us.mu.RLock()
	localIPs := make(map[string]bool, len(us.ips))
	for ip := range us.ips {
		localIPs[ip] = true
	}
	localCount := len(us.ips)
	us.mu.RUnlock()

	// Already known locally
	if localIPs[sourceIP] {
		return false
	}

	// Check global state freshness
	t.globalMu.RLock()
	globalStale := time.Since(t.globalLastUpdate) > 60*time.Second
	globalIPs := t.globalDevices[userID]
	t.globalMu.RUnlock()

	// Stale or missing global state → local-only check
	if globalStale || globalIPs == nil {
		if localCount < limit {
			return false
		}
		ipList := make([]string, 0, localCount+1)
		for ip := range localIPs {
			ipList = append(ipList, ip)
		}
		ipList = append(ipList, sourceIP)
		sort.Strings(ipList)
		for i := 0; i < limit && i < len(ipList); i++ {
			if ipList[i] == sourceIP {
				return false
			}
		}
		nlog.Core().Debug("device limit: local over limit, rejecting",
			"userID", userID, "ip", sourceIP, "localIPs", localCount, "limit", limit)
		return true
	}

	// Known globally (from other node)
	if globalIPs[sourceIP] {
		return false
	}

	// Merge local + global
	allIPs := make(map[string]bool)
	for ip := range localIPs {
		allIPs[ip] = true
	}
	for ip := range globalIPs {
		allIPs[ip] = true
	}

	if len(allIPs) < limit {
		return false
	}

	// Over limit → lexicographic selection
	ipList := make([]string, 0, len(allIPs)+1)
	for ip := range allIPs {
		ipList = append(ipList, ip)
	}
	ipList = append(ipList, sourceIP)
	sort.Strings(ipList)

	for i := 0; i < limit && i < len(ipList); i++ {
		if ipList[i] == sourceIP {
			return false
		}
	}
	nlog.Core().Debug("device limit: total over limit, rejecting",
		"userID", userID, "ip", sourceIP, "totalIPs", len(allIPs), "limit", limit)
	return true
}

func (t *ConnTracker) nextID() string {
	return "sb-" + formatInt36(t.idCounter.Add(1))
}

func formatInt36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var buf [13]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}
	return string(buf[i:])
}

// ─── Public API ─────────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic and alive IPs.
// This is O(users), not O(connections).
func (t *ConnTracker) GetUserTraffic() (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int) {
	t.usersMu.RLock()
	traffic = make(map[int][2]int64, len(t.users))
	aliveIPs = make(map[int]map[string]bool, len(t.users))
	for uid, us := range t.users {
		up := us.upload.Load()
		down := us.download.Load()
		if up > 0 || down > 0 {
			traffic[uid] = [2]int64{up, down}
		}

		ips := us.aliveIPList()
		if ips != nil {
			aliveIPs[uid] = ips
		}

		us.mu.Lock()
		connCount += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return
}

// CloseByID force-closes a connection by its ID.
func (t *ConnTracker) CloseByID(id string) bool {
	t.usersMu.RLock()
	connection, ok := t.connMap[id]
	t.usersMu.RUnlock()
	if !ok {
		return false
	}
	_ = connection.closer.Close()
	return true
}

// CloseByUUID force-closes ALL connections for a given user UUID.
func (t *ConnTracker) CloseByUUID(uuid string) int {
	t.usersMu.RLock()
	var connections []io.Closer
	for _, connection := range t.connMap {
		if connection.uuid == uuid {
			connections = append(connections, connection.closer)
		}
	}
	t.usersMu.RUnlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	return len(connections)
}

// StopAuthorization closes physical I/O before observer/session bookkeeping.
// The terminal latch is also checked under the registration lock, so a delayed
// routing callback cannot register a connection after the cohort is expired.
func (t *ConnTracker) StopAuthorization() {
	t.authorizationExpired.Store(true)
	t.usersMu.RLock()
	connections := make([]io.Closer, 0, len(t.connMap))
	for _, connection := range t.connMap {
		connections = append(connections, connection.closer)
	}
	t.usersMu.RUnlock()
	for _, connection := range connections {
		switch c := connection.(type) {
		case *trackedConn:
			c.cancel()
			_ = c.Conn.Close()
		case *trackedPacketConn:
			c.cancel()
			_ = c.PacketConn.Close()
		default:
			_ = connection.Close()
		}
	}
}

// ActiveCount returns the total number of active connections.
func (t *ConnTracker) ActiveCount() int {
	t.usersMu.RLock()
	total := 0
	for _, us := range t.users {
		us.mu.Lock()
		total += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return total
}

// removeConnRef removes the connection reference from connMap on close.
func (t *ConnTracker) removeConnRef(connID string) {
	t.usersMu.Lock()
	delete(t.connMap, connID)
	t.usersMu.Unlock()
}

// ─── trackedConn (TCP) ──────────────────────────────────────────────────────

// RateLimitedWriter wraps a Writer with non-blocking rate limiting.
// Uses AllowN for instant checks and context-aware waiting when needed.
type RateLimitedWriter struct {
	writer  io.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

// Write implements io.Writer with rate limiting.
func (w *RateLimitedWriter) Write(b []byte) (int, error) {
	// Truncate to burst size
	if burst := w.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	// Fast path: check if tokens available (non-blocking)
	if w.limiter.AllowN(time.Now(), len(b)) {
		return w.writer.Write(b)
	}

	// Slow path: wait for tokens with context cancellation support
	resv := w.limiter.ReserveN(time.Now(), len(b))
	if delay := resv.Delay(); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			// Tokens available, proceed
		case <-w.ctx.Done():
			resv.Cancel()
			return 0, w.ctx.Err()
		}
	}

	return w.writer.Write(b)
}

// RateLimitedReadCloser wraps a Reader with non-blocking rate limiting.
type RateLimitedReadCloser struct {
	reader  io.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

// Read implements io.Reader with rate limiting.
func (r *RateLimitedReadCloser) Read(b []byte) (int, error) {
	// Truncate to burst size
	if burst := r.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	n, err := r.reader.Read(b)
	if n > 0 && r.limiter != nil {
		// Fast path: check if tokens available
		if !r.limiter.AllowN(time.Now(), n) {
			// Slow path: wait with context cancellation
			resv := r.limiter.ReserveN(time.Now(), n)
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-r.ctx.Done():
					resv.Cancel()
					return n, r.ctx.Err()
				}
			}
		}
	}
	return n, err
}

type trackedConn struct {
	net.Conn
	tracker       *ConnTracker
	us            *userStats // per-user stats (upload/download atomics + IP tracking)
	userID        int        // user ID for device tracking
	connID        string
	sourceIP      string
	auditTarget   string
	auditOnce     sync.Once
	limiter       *rate.Limiter
	ctx           context.Context
	cancel        context.CancelFunc
	closeOnce     sync.Once
	closeErr      error
	bucketSession *usagebucket.Session
	boundedClosed atomic.Bool
}

func (c *trackedConn) reportAudit(targetIP string) {
	if c.auditTarget == "" || c.userID <= 0 || c.tracker == nil || c.tracker.auditor == nil {
		return
	}
	c.auditOnce.Do(func() {
		c.tracker.auditor.ObserveWithTargetIP(c.userID, c.auditTarget, targetIP, c.sourceIP)
	})
}

// ReportTargetIP is discovered by the TX sing-box fork after a successful
// outbound dial. The address is the exact remote selected by the dialer, not a
// DNS candidate. Existing sing-box trackers that do not implement this method
// are unaffected.
func (c *trackedConn) ReportTargetIP(address netip.Addr) {
	if address.IsValid() {
		c.reportAudit(address.String())
	}
}

func (c *trackedConn) Read(b []byte) (int, error) {
	// Fallback for handler-based outbounds that bypass ConnectionManager and
	// therefore cannot expose an exact remote address.
	c.reportAudit("")
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
	}
	var operation usagebucket.Operation
	if c.bucketSession != nil {
		operation = c.bucketSession.Begin()
	}
	var bounded *usageinterval.Operation
	if c.tracker.boundedUsage != nil {
		if c.boundedClosed.Load() {
			if c.tracker.nativeUsage {
				return 0, usageinterval.ErrUnknown
			}
			c.tracker.boundedUsage.Fail()
		}
		if native, ok := c.tracker.boundedUsage.(*usageinterval.NativeCollector); ok {
			bounded = native.BeginIO(c.userID, "upload", int64(len(b)))
		} else {
			bounded = c.tracker.boundedUsage.Begin(c.userID)
		}
		if bounded == nil && c.tracker.enforceBounded {
			return 0, usageinterval.ErrUnknown
		}
	}
	n, err := c.Conn.Read(b)
	if c.tracker.boundedUsage != nil {
		if c.boundedClosed.Load() && !c.tracker.nativeUsage {
			c.tracker.boundedUsage.Fail()
		}
		if native, ok := c.tracker.boundedUsage.(*usageinterval.NativeCollector); ok {
			if durableErr := native.CompleteIO(bounded, "upload", int64(n), err != nil); durableErr != nil {
				err = durableErr
			}
		} else {
			c.tracker.boundedUsage.Complete(bounded, "upload", int64(n), err != nil)
		}
	}
	if n > 0 {
		if c.us != nil {
			c.us.upload.Add(int64(n)) // 从入站读取 = 用户上传
		}
		if c.bucketSession != nil {
			c.bucketSession.Complete(operation, usagebucket.TCPRead, usagebucket.Upload, usagebucket.Upload, int64(n), err != nil, true)
		}
		if c.limiter != nil {
			// Non-blocking rate limiting
			if !c.limiter.AllowN(time.Now(), n) {
				resv := c.limiter.ReserveN(time.Now(), n)
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return n, c.ctx.Err()
					}
				}
			}
		}
	}
	if n == 0 && c.bucketSession != nil {
		c.bucketSession.Complete(operation, usagebucket.TCPRead, usagebucket.Upload, usagebucket.Upload, 0, err != nil, true)
	}
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	c.reportAudit("")
	// Apply rate limiting before write
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
		// Non-blocking check first
		if !c.limiter.AllowN(time.Now(), len(b)) {
			resv := c.limiter.ReserveN(time.Now(), len(b))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return 0, c.ctx.Err()
				}
			}
		}
	}

	var operation usagebucket.Operation
	if c.bucketSession != nil {
		operation = c.bucketSession.Begin()
	}
	var bounded *usageinterval.Operation
	if c.tracker.boundedUsage != nil {
		if c.boundedClosed.Load() {
			if c.tracker.nativeUsage {
				return 0, usageinterval.ErrUnknown
			}
			c.tracker.boundedUsage.Fail()
		}
		if native, ok := c.tracker.boundedUsage.(*usageinterval.NativeCollector); ok {
			bounded = native.BeginIO(c.userID, "download", int64(len(b)))
		} else {
			bounded = c.tracker.boundedUsage.Begin(c.userID)
		}
		if bounded == nil && c.tracker.enforceBounded {
			return 0, usageinterval.ErrUnknown
		}
	}
	n, err := c.Conn.Write(b)
	if c.tracker.boundedUsage != nil {
		if c.boundedClosed.Load() && !c.tracker.nativeUsage {
			c.tracker.boundedUsage.Fail()
		}
		if native, ok := c.tracker.boundedUsage.(*usageinterval.NativeCollector); ok {
			if durableErr := native.CompleteIO(bounded, "download", int64(n), err != nil); durableErr != nil {
				err = durableErr
			}
		} else {
			c.tracker.boundedUsage.Complete(bounded, "download", int64(n), err != nil)
		}
	}
	if n > 0 && c.us != nil {
		c.us.download.Add(int64(n)) // 向入站写入 = 用户下载
	}
	if c.bucketSession != nil {
		c.bucketSession.Complete(operation, usagebucket.TCPWrite, usagebucket.Download, usagebucket.Download, int64(n), err != nil, true)
	}
	return n, err
}

func (c *trackedConn) Close() error {
	c.reportAudit("")
	c.closeOnce.Do(func() {
		if c.tracker.boundedUsage != nil {
			c.boundedClosed.Store(true)
		}
		if c.bucketSession != nil {
			c.bucketSession.Close()
		}
		c.cancel()
		c.closeErr = c.Conn.Close()
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.connID)
	})
	return c.closeErr
}

// makeCountFunc builds a CountFunc for zero-copy byte counting via sing's
// ReadCounter/WriteCounter unwrap interfaces.
func (c *trackedConn) makeCountFunc(counter *atomic.Int64, path usagebucket.Path, direction usagebucket.Direction) N.CountFunc {
	if c.bucketSession == nil {
		return c.makeLegacyCountFunc(counter)
	}
	if c.limiter == nil {
		return func(n int64) {
			counter.Add(n)
			if c.bucketSession != nil {
				c.bucketSession.Callback(path, direction, direction, n)
			}
		}
	}
	return func(n int64) {
		counter.Add(n)
		if c.bucketSession != nil {
			c.bucketSession.Callback(path, direction, direction, n)
		}
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

// Retain the original callback on the default-off path, including its closure
// captures. No observer clock, session, allocation or mutex is introduced there.
func (c *trackedConn) makeLegacyCountFunc(counter *atomic.Int64) N.CountFunc {
	if c.limiter == nil {
		return func(n int64) { counter.Add(n) }
	}
	return func(n int64) {
		counter.Add(n)
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	if c.tracker.boundedUsage != nil {
		return &boundedTCPView{base: c}, nil
	}
	c.reportAudit("")
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.upload, usagebucket.TCPReadCallback, usagebucket.Upload)} // 从入站读取 = 用户上传
}

func (c *trackedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if c.tracker.boundedUsage != nil {
		return &boundedTCPView{base: c}, nil
	}
	c.reportAudit("")
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.download, usagebucket.TCPWriteCallback, usagebucket.Download)} // 向入站写入 = 用户下载
}

func (c *trackedConn) Upstream() any {
	if c.tracker.boundedUsage != nil {
		return nil
	}
	return c.Conn
}
func (c *trackedConn) ReaderReplaceable() bool { return c.tracker.boundedUsage == nil }
func (c *trackedConn) WriterReplaceable() bool { return c.tracker.boundedUsage == nil }

// ─── trackedPacketConn (UDP / QUIC) ─────────────────────────────────────────

type trackedPacketConn struct {
	N.PacketConn
	tracker       *ConnTracker
	us            *userStats
	userID        int
	connID        string
	sourceIP      string
	auditTarget   string
	auditOnce     sync.Once
	limiter       *rate.Limiter
	ctx           context.Context
	cancel        context.CancelFunc
	closeOnce     sync.Once
	closeErr      error
	bucketSession *usagebucket.Session
}

func (c *trackedPacketConn) reportAudit(targetIP string) {
	if c.auditTarget == "" || c.userID <= 0 || c.tracker == nil || c.tracker.auditor == nil {
		return
	}
	c.auditOnce.Do(func() {
		c.tracker.auditor.ObserveWithTargetIP(c.userID, c.auditTarget, targetIP, c.sourceIP)
	})
}

// ReportTargetIP implements the optional capability consumed by the TX
// sing-box fork after UDP destination selection.
func (c *trackedPacketConn) ReportTargetIP(address netip.Addr) {
	if address.IsValid() {
		c.reportAudit(address.String())
	}
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (singM.Socksaddr, error) {
	c.reportAudit("")
	var operation usagebucket.Operation
	if c.bucketSession != nil {
		operation = c.bucketSession.Begin()
	}
	dest, err := c.PacketConn.ReadPacket(buffer)
	if err == nil {
		n := int64(buffer.Len())
		if c.us != nil {
			c.us.upload.Add(n) // 从入站读取 = 用户上传
		}
		if c.bucketSession != nil {
			c.bucketSession.Complete(operation, usagebucket.UDPRead, usagebucket.Upload, usagebucket.Upload, n, false, true)
		}
		if c.limiter != nil {
			// Non-blocking rate limiting with context cancellation
			if !c.limiter.AllowN(time.Now(), int(n)) {
				resv := c.limiter.ReserveN(time.Now(), int(n))
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return dest, c.ctx.Err()
					}
				}
			}
		}
	}
	if err != nil && c.bucketSession != nil {
		c.bucketSession.Complete(operation, usagebucket.UDPRead, usagebucket.Upload, usagebucket.Upload, 0, true, false)
	}
	return dest, err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, dest singM.Socksaddr) error {
	c.reportAudit("")
	n := int64(buffer.Len())

	// Apply rate limiting before write
	if c.limiter != nil {
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return c.ctx.Err()
				}
			}
		}
	}

	var operation usagebucket.Operation
	if c.bucketSession != nil {
		operation = c.bucketSession.Begin()
	}
	err := c.PacketConn.WritePacket(buffer, dest)
	if err == nil && c.us != nil {
		c.us.download.Add(n) // 向入站写入 = 用户下载
	}
	if c.bucketSession != nil {
		counted := n
		if err != nil {
			counted = 0
		}
		c.bucketSession.Complete(operation, usagebucket.UDPWrite, usagebucket.Download, usagebucket.Download, counted, err != nil, err == nil)
	}
	return err
}

func (c *trackedPacketConn) Close() error {
	c.reportAudit("")
	c.closeOnce.Do(func() {
		if c.bucketSession != nil {
			c.bucketSession.Close()
		}
		c.cancel()
		c.closeErr = c.PacketConn.Close()
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.connID)
	})
	return c.closeErr
}

func (c *trackedPacketConn) makeCountFunc(counter *atomic.Int64, path usagebucket.Path, physical, legacy usagebucket.Direction) N.CountFunc {
	if c.bucketSession == nil {
		return c.makeLegacyCountFunc(counter)
	}
	if c.limiter == nil {
		return func(n int64) {
			counter.Add(n)
			if c.bucketSession != nil {
				c.bucketSession.Callback(path, physical, legacy, n)
			}
		}
	}
	return func(n int64) {
		counter.Add(n)
		if c.bucketSession != nil {
			c.bucketSession.Callback(path, physical, legacy, n)
		}
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedPacketConn) makeLegacyCountFunc(counter *atomic.Int64) N.CountFunc {
	if c.limiter == nil {
		return func(n int64) { counter.Add(n) }
	}
	return func(n int64) {
		counter.Add(n)
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedPacketConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	c.reportAudit("")
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.download, usagebucket.UDPReadCallback, usagebucket.Upload, usagebucket.Download)}
}

func (c *trackedPacketConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	c.reportAudit("")
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.upload, usagebucket.UDPWriteCallback, usagebucket.Download, usagebucket.Upload)}
}

func (c *trackedPacketConn) Upstream() any           { return c.PacketConn }
func (c *trackedPacketConn) ReaderReplaceable() bool { return true }

// sing 0.8.2 unwraps replaceable packet writers before looking for their
// PacketWriteCounter. Keep this boundary so CopyPacket extracts our counter
// once through UnwrapPacketWriter instead of silently bypassing it.
func (c *trackedPacketConn) WriterReplaceable() bool { return false }
