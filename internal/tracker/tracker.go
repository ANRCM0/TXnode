package tracker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nlog"
)

// snapshot is an immutable point-in-time view of tracker state.
// It is swapped atomically so readers never block writers.
type snapshot struct {
	traffic   map[int][2]int64        // userID → [upload, download] delta
	aliveIPs  map[int]map[string]bool // userID → set of source IPs
	online    map[int]int             // userID → distinct IP count
	connCount int
	inSpeed   int64
	outSpeed  int64
}

// Tracker computes per-user traffic deltas from cumulative counters
// provided by the kernel, and accumulates totals for panel reporting.
//
// Architecture: the kernel maintains per-user atomic counters and IP sets.
// Each tick, the service calls Process() with cumulative per-user traffic.
// Tracker computes deltas against the previous cycle's values — O(users),
// not O(connections).
//
// Thread safety: Process() acquires mu to update internal state, then
// atomically publishes a new snapshot. All read methods (Flush*,
// CurrentOnline, LogStats, *Speed) read the snapshot lock-free.
// This eliminates contention between the 10s Process tick and the 60s
// flush/push tick.
type Tracker struct {
	mu sync.Mutex

	// lastSeen stores the cumulative traffic from the previous Process() call.
	// Protected by mu — only written by Process.
	lastSeen map[int][2]int64 // userID → [upload, download] cumulative

	// pending accumulates deltas between flushes.
	// Protected by mu — written by Process, drained by FlushTraffic.
	pendingTraffic  map[int][2]int64
	pendingSegments map[trafficSegmentKey][2]int64
	observedPeriods map[int]string
	activeSigned    bool
	activeModeKnown bool

	// live holds the current snapshot, swapped atomically.
	// Readers load this pointer without any lock.
	live atomic.Pointer[snapshot]

	// aliveIPsBuf is a reusable buffer for FlushAliveIPs output.
	// Avoids allocating a new map+slice every 60s.
	aliveIPsBuf map[int][]string

	// lastAliveIPsHash detects changes to avoid duplicate reports.
	lastAliveIPsHash string
}

func New() *Tracker {
	t := &Tracker{
		lastSeen:        make(map[int][2]int64),
		pendingTraffic:  make(map[int][2]int64),
		pendingSegments: make(map[trafficSegmentKey][2]int64), observedPeriods: make(map[int]string),
		aliveIPsBuf: make(map[int][]string),
	}
	// Publish initial empty snapshot.
	t.live.Store(&snapshot{
		traffic:  make(map[int][2]int64),
		aliveIPs: make(map[int]map[string]bool),
		online:   make(map[int]int),
	})
	return t
}

// BeginCumulativeGeneration is an explicit successful producer-reconstruction
// boundary. New producer counters start at zero even if their first sample is
// larger than the old producer's final value. Preserve pending report deltas;
// caller must sample the retired producer before advancing this boundary.
func (t *Tracker) BeginCumulativeGeneration() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.lastSeen = make(map[int][2]int64)
	t.mu.Unlock()
}

// Process computes per-user traffic deltas from cumulative kernel counters.
// Also stores alive IPs and connection count. O(users).
//
// This is the only writer to lastSeen and pendingTraffic.
// After computing deltas, it publishes a new snapshot for lock-free reads.
func (t *Tracker) Process(
	cumTraffic map[int][2]int64,
	kernelAliveIPs map[int]map[string]bool,
	connCount int,
) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var cycleIn, cycleOut int64

	for uid, cum := range cumTraffic {
		prev := t.lastSeen[uid]
		deltaUp := cum[0] - prev[0]
		deltaDown := cum[1] - prev[1]

		// Guard against counter reset (kernel restart).
		if deltaUp < 0 {
			deltaUp = cum[0]
		}
		if deltaDown < 0 {
			deltaDown = cum[1]
		}

		t.lastSeen[uid] = cum

		if deltaUp > 0 || deltaDown > 0 {
			cur := t.pendingTraffic[uid]
			cur[0] += deltaUp
			cur[1] += deltaDown
			t.pendingTraffic[uid] = cur
			key := trafficSegmentKey{userID: uid, period: t.observedPeriods[uid]}
			segment := t.pendingSegments[key]
			segment[0] += deltaUp
			segment[1] += deltaDown
			t.pendingSegments[key] = segment

			cycleOut += deltaUp
			cycleIn += deltaDown
		}
	}

	// Compute online from alive IPs.
	online := make(map[int]int, len(kernelAliveIPs))
	for uid, ips := range kernelAliveIPs {
		online[uid] = len(ips)
	}

	// Publish new snapshot (readers will see this atomically).
	t.live.Store(&snapshot{
		traffic:   copyTrafficMap(t.pendingTraffic),
		aliveIPs:  kernelAliveIPs, // kernel provides fresh copy each tick
		online:    online,
		connCount: connCount,
		inSpeed:   cycleIn,
		outSpeed:  cycleOut,
	})
}

// FlushTraffic returns accumulated per-user traffic and resets the pending buffer.
// Lock-free: reads from live snapshot, then acquires mu only to drain.
func (t *Tracker) FlushTraffic() map[int][2]int64 { traffic, _ := t.FlushBatch(); return traffic }

type trafficSegmentKey struct {
	userID int
	period string
}

// BindPeriods follows successful admission reconstruction. Removed users retain
// their last binding so the final producer sample cannot acquire a new period.
type PeriodBindings struct {
	periods       map[int]string
	signed, known bool
}

func (t *Tracker) BindPeriods(users []model.UserSpec) PeriodBindings {
	if t == nil {
		return PeriodBindings{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	previous := PeriodBindings{periods: make(map[int]string, len(t.observedPeriods)), signed: t.activeSigned, known: t.activeModeKnown}
	for uid, period := range t.observedPeriods {
		previous.periods[uid] = period
	}
	for _, u := range users {
		t.observedPeriods[u.ID] = u.TrafficPeriod
	}
	if len(users) > 0 {
		signed, mixed := AdmissionPeriodMode(users)
		if !mixed {
			t.activeSigned = signed
			t.activeModeKnown = true
		}
	}
	return previous
}
func (t *Tracker) RestorePeriodBindings(previous PeriodBindings) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.observedPeriods = make(map[int]string, len(previous.periods))
	for uid, period := range previous.periods {
		t.observedPeriods[uid] = period
	}
	t.activeSigned = previous.signed
	t.activeModeKnown = previous.known
}

func (t *Tracker) PeriodsChanged(users []model.UserSpec) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, u := range users {
		if old, ok := t.observedPeriods[u.ID]; ok && old != u.TrafficPeriod {
			return true
		}
	}
	return false
}

// FlushBatch atomically removes the aggregate and exactly matching attribution.
// Pure legacy traffic retains nil segments. Mixed traffic drains legacy first
// with its own batch ID; signed segments remain for the next batch.
func (t *Tracker) FlushBatch() (map[int][2]int64, []model.TrafficSegment) {
	t.mu.Lock()
	defer t.mu.Unlock()
	legacy, aware := false, false
	for key := range t.pendingSegments {
		if key.period == "" {
			legacy = true
		} else {
			aware = true
		}
	}
	if legacy && aware {
		// Legacy/unbound and signed bytes cannot share a period-aware wire body.
		// Drain only the legacy cohort now; retain every signed segment for next ID.
		traffic := make(map[int][2]int64)
		for key, value := range t.pendingSegments {
			if key.period != "" {
				continue
			}
			cur := traffic[key.userID]
			cur[0] += value[0]
			cur[1] += value[1]
			traffic[key.userID] = cur
			remaining := t.pendingTraffic[key.userID]
			remaining[0] -= value[0]
			remaining[1] -= value[1]
			if remaining == [2]int64{} {
				delete(t.pendingTraffic, key.userID)
			} else {
				t.pendingTraffic[key.userID] = remaining
			}
			delete(t.pendingSegments, key)
		}
		return traffic, nil
	}
	if aware {
		keys := make([]trafficSegmentKey, 0, len(t.pendingSegments))
		for key := range t.pendingSegments {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].userID == keys[j].userID {
				return keys[i].period < keys[j].period
			}
			return keys[i].userID < keys[j].userID
		})
		if len(keys) > 10000 {
			keys = keys[:10000]
		}
		traffic := make(map[int][2]int64)
		segments := make([]model.TrafficSegment, 0, len(keys))
		// Leave at least 512 KiB for status, alive/device metrics and the outer envelope.
		encodedBudget := 1024
		for _, key := range keys {
			value := t.pendingSegments[key]
			candidate := model.TrafficSegment{UserID: key.userID, Period: key.period, Upload: value[0], Download: value[1]}
			encoded, _ := json.Marshal(candidate)
			cost := len(encoded) + 1
			if _, exists := traffic[key.userID]; !exists {
				cost += 72
			} // worst-case int64 aggregate key/directions
			if len(segments) > 0 && encodedBudget+cost > 512<<10 {
				break
			}
			encodedBudget += cost
			sum := traffic[key.userID]
			sum[0] += value[0]
			sum[1] += value[1]
			traffic[key.userID] = sum
			segments = append(segments, model.TrafficSegment{UserID: key.userID, Period: key.period, Upload: value[0], Download: value[1]})
			remaining := t.pendingTraffic[key.userID]
			remaining[0] -= value[0]
			remaining[1] -= value[1]
			if remaining == [2]int64{} {
				delete(t.pendingTraffic, key.userID)
			} else {
				t.pendingTraffic[key.userID] = remaining
			}
			delete(t.pendingSegments, key)
		}
		return traffic, segments
	}
	traffic := t.pendingTraffic
	t.pendingTraffic = make(map[int][2]int64, len(traffic))
	t.pendingSegments = make(map[trafficSegmentKey][2]int64)
	return traffic, nil
}

// AdmissionPeriodMode validates the entire desired cohort, not just same UIDs.
func AdmissionPeriodMode(users []model.UserSpec) (signed bool, mixed bool) {
	legacy := false
	for _, u := range users {
		if u.TrafficPeriod == "" {
			legacy = true
		} else {
			signed = true
		}
	}
	return signed, legacy && signed
}
func (t *Tracker) PeriodModeChanged(users []model.UserSpec) bool {
	if t == nil || len(users) == 0 {
		return false
	}
	signed, mixed := AdmissionPeriodMode(users)
	if mixed {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.activeModeKnown && t.activeSigned != signed {
		return true
	}
	for key := range t.pendingSegments {
		if (key.period != "") != signed {
			return true
		}
	}
	return false
}

func (t *Tracker) HasLegacyPending() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, value := range t.pendingSegments {
		if key.period == "" && (value[0] != 0 || value[1] != 0) {
			return true
		}
	}
	return false
}

func (t *Tracker) RestoreTraffic(data map[int][2]int64) { t.RestoreBatch(data, nil) }

// RestoreBatch never looks at current bindings: failed immutable report bytes
// retain their supplied period; nil is explicitly historical legacy semantics.
func (t *Tracker) RestoreBatch(data map[int][2]int64, segments []model.TrafficSegment) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for uid, value := range data {
		cur := t.pendingTraffic[uid]
		cur[0] += value[0]
		cur[1] += value[1]
		t.pendingTraffic[uid] = cur
	}
	if len(segments) == 0 {
		for uid, value := range data {
			key := trafficSegmentKey{userID: uid}
			cur := t.pendingSegments[key]
			cur[0] += value[0]
			cur[1] += value[1]
			t.pendingSegments[key] = cur
		}
		return
	}
	for _, segment := range segments {
		key := trafficSegmentKey{userID: segment.UserID, period: segment.Period}
		cur := t.pendingSegments[key]
		cur[0] += segment.Upload
		cur[1] += segment.Download
		t.pendingSegments[key] = cur
	}
}

// HasTraffic returns true if there is accumulated traffic to report.
func (t *Tracker) HasTraffic() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pendingTraffic) > 0
}

// FlushAliveIPs returns per-user alive IPs.
// Reuses internal buffer. Returns nil if unchanged.
func (t *Tracker) FlushAliveIPs() map[int][]string {
	s := t.live.Load()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Calculate hash of current aliveIPs
	currentHash := calcAliveIPsHash(s.aliveIPs)

	// If no changes, return nil to avoid duplicate reporting
	if currentHash == t.lastAliveIPsHash {
		return nil
	}

	t.lastAliveIPsHash = currentHash

	// Clear old buffer entries.
	for k := range t.aliveIPsBuf {
		delete(t.aliveIPsBuf, k)
	}

	// Fill buffer from snapshot.
	for uid, ips := range s.aliveIPs {
		buf := t.aliveIPsBuf[uid]
		if buf == nil {
			buf = make([]string, 0, len(ips))
		}
		buf = buf[:0]
		for ip := range ips {
			buf = append(buf, ip)
		}
		t.aliveIPsBuf[uid] = buf
	}

	return t.aliveIPsBuf
}

// calcAliveIPsHash computes a deterministic hash for change detection.
func calcAliveIPsHash(aliveIPs map[int]map[string]bool) string {
	if len(aliveIPs) == 0 {
		return ""
	}

	h := sha256.New()

	// Sort user IDs for consistent hashing
	userIDs := make([]int, 0, len(aliveIPs))
	for uid := range aliveIPs {
		userIDs = append(userIDs, uid)
	}
	sort.Ints(userIDs)

	for _, uid := range userIDs {
		ips := aliveIPs[uid]
		// Sort IPs for consistent hashing
		ipList := make([]string, 0, len(ips))
		for ip := range ips {
			ipList = append(ipList, ip)
		}
		sort.Strings(ipList)

		// Write user ID and IPs to hash
		h.Write([]byte{byte(uid >> 24), byte(uid >> 16), byte(uid >> 8), byte(uid)})
		for _, ip := range ipList {
			h.Write([]byte(ip))
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

// CurrentOnline returns a snapshot copy of user_id → device count (distinct IPs).
// Lock-free: reads from live snapshot.
func (t *Tracker) CurrentOnline() map[int]int {
	s := t.live.Load()
	cp := make(map[int]int, len(s.online))
	for k, v := range s.online {
		cp[k] = v
	}
	return cp
}

// RestoreAliveIPs merges alive IPs back in (used when push to panel fails).
// Note: this operates on the buffer, which will be overwritten next Process().
func (t *Tracker) RestoreAliveIPs(data map[int][]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for uid, ipList := range data {
		ips := t.aliveIPsBuf[uid]
		if ips == nil {
			ips = make([]string, 0, len(ipList))
		}
		// Use map for O(n) dedup instead of O(n²) linear search
		existMap := make(map[string]struct{}, len(ips)+len(ipList))
		for _, existing := range ips {
			existMap[existing] = struct{}{}
		}
		for _, ip := range ipList {
			if _, exists := existMap[ip]; !exists {
				ips = append(ips, ip)
				existMap[ip] = struct{}{}
			}
		}
		t.aliveIPsBuf[uid] = ips
	}
}

// LogStats logs current tracking statistics.
// Lock-free: reads from live snapshot.
func (t *Tracker) LogStats() {
	s := t.live.Load()
	nlog.TrackerStats(s.connCount, len(s.online))
}

// ActiveConnections returns the last observed active connection count.
// Lock-free: reads from live snapshot.
func (t *Tracker) ActiveConnections() int {
	return t.live.Load().connCount
}

// TotalConnections is deprecated — no longer tracked per-connection.
// Returns 0 for backward compatibility.
func (t *Tracker) TotalConnections() int64 {
	return 0
}

// InboundSpeed returns the last observed inbound (download) speed in bytes/second.
// Lock-free: reads from live snapshot.
func (t *Tracker) InboundSpeed() int64 {
	return t.live.Load().inSpeed / 10
}

// OutboundSpeed returns the last observed outbound (upload) speed in bytes/second.
// Lock-free: reads from live snapshot.
func (t *Tracker) OutboundSpeed() int64 {
	return t.live.Load().outSpeed / 10
}

// copyTrafficMap creates a shallow copy of the traffic map.
func copyTrafficMap(src map[int][2]int64) map[int][2]int64 {
	dst := make(map[int][2]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (t *Tracker) EmptyForUsageHandoff() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, v := range t.pendingTraffic {
		if v[0] != 0 || v[1] != 0 {
			return false
		}
	}
	for _, v := range t.lastSeen {
		if v[0] != 0 || v[1] != 0 {
			return false
		}
	}
	live := t.live.Load()
	return live != nil && live.connCount == 0 && len(live.online) == 0
}

// ProcessUsageV2Metrics preserves cumulative observations for runtime metrics
// without constructing a second v1 billing queue. It requires an empty pending
// v1 state; unexpected residual counters cannot be silently discarded.
func (t *Tracker) ProcessUsageV2Metrics(cumulative map[int][2]int64, alive map[int]map[string]bool, connections int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.pendingTraffic) != 0 {
		return false
	}
	var up, down int64
	for id, current := range cumulative {
		previous := t.lastSeen[id]
		if current[0] < previous[0] || current[1] < previous[1] || current[0] < 0 || current[1] < 0 {
			return false
		}
		du, dd := current[0]-previous[0], current[1]-previous[1]
		if du > math.MaxInt64-up || dd > math.MaxInt64-down {
			return false
		}
		up += du
		down += dd
		t.lastSeen[id] = current
	}
	online := make(map[int]int, len(alive))
	for id, ips := range alive {
		online[id] = len(ips)
	}
	t.live.Store(&snapshot{traffic: map[int][2]int64{}, aliveIPs: alive, online: online, connCount: connections, inSpeed: down, outSpeed: up})
	return true
}

func (t *Tracker) HasPeriodAttribution() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.activeModeKnown && t.activeSigned {
		return true
	}
	for key := range t.pendingSegments {
		if key.period != "" {
			return true
		}
	}
	return false
}
