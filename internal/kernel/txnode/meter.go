package txnode

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/model"
)

// deviceGlobalTTL is how long a panel device snapshot stays authoritative. The
// sing-box runtime used 60 s; past it the gate degrades to the local view.
const deviceGlobalTTL = 60 * time.Second

// deviceGate is the multi-node anti-sharing check: the union of the locally live
// device keys and the panel's global device set, with a deterministic
// lexicographic selection when the union is over the limit.
//
// It owns its own state (user map, global snapshot, limit lookup) because it is
// called from Tracker.Acquire while the tracker is locked: it must never call
// back into the kernel or the tracker.
type deviceGate struct {
	mu           sync.RWMutex
	uuid         map[int]string
	global       map[int]map[string]bool
	globalAt     time.Time
	limitFn      func(uuid string) (int, bool)
	defaultLimit int
	ipv6Prefix   int
}

func newDeviceGate() *deviceGate {
	return &deviceGate{uuid: make(map[int]string), global: make(map[int]map[string]bool), ipv6Prefix: 64}
}

func newRuntimeDeviceGate(rt RuntimeConfig) *deviceGate {
	g := newDeviceGate()
	g.defaultLimit = rt.DeviceLimit
	if rt.DeviceIPv6Prefix > 0 && rt.DeviceIPv6Prefix <= 128 {
		g.ipv6Prefix = rt.DeviceIPv6Prefix
	}
	return g
}

func (g *deviceGate) setUsers(users []model.UserSpec) {
	g.mu.Lock()
	defer g.mu.Unlock()
	next := make(map[int]string, len(users))
	for _, u := range users {
		next[u.ID] = u.UUID
	}
	g.uuid = next
}

func (g *deviceGate) setLimitFunc(fn func(uuid string) (int, bool)) {
	g.mu.Lock()
	g.limitFn = fn
	g.mu.Unlock()
}

// setGlobal installs the panel's per-user device address set.
func (g *deviceGate) setGlobal(users map[int][]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	next := make(map[int]map[string]bool, len(users))
	for id, addrs := range users {
		set := make(map[string]bool, len(addrs))
		for _, a := range addrs {
			addr, _ := netip.ParseAddr(a)
			if key := deviceKeyWithPrefix(addr, g.ipv6Prefix); key != "" {
				set[key] = true
			}
		}
		next[id] = set
	}
	g.global = next
	g.globalAt = time.Now()
}

func (g *deviceGate) clearGlobal() {
	g.mu.Lock()
	g.global = make(map[int]map[string]bool)
	g.globalAt = time.Time{}
	g.mu.Unlock()
}

// Allow implements core.DeviceGate.
func (g *deviceGate) Allow(userID int, src netip.Addr, local map[string]int) bool {
	key := deviceKeyWithPrefix(src, g.ipv6Prefix)
	if key == "" {
		return true
	}

	g.mu.RLock()
	limitFn := g.limitFn
	uuid := g.uuid[userID]
	globalSet := g.global[userID]
	globalAt := g.globalAt
	g.mu.RUnlock()

	limit := g.defaultLimit
	if limitFn != nil {
		if n, ok := limitFn(uuid); ok && n > 0 && (limit <= 0 || n < limit) {
			limit = n
		}
	}
	if limit <= 0 {
		return true
	}
	if local[key] > 0 {
		return true
	}

	// Stale or missing panel state: local-only decision.
	if globalSet == nil || time.Since(globalAt) > deviceGlobalTTL {
		if len(local) < limit {
			return true
		}
		return false
	}
	if globalSet[key] {
		return len(local) < limit
	}
	union := make(map[string]struct{}, len(local)+len(globalSet)+1)
	for k := range local {
		union[k] = struct{}{}
	}
	for k := range globalSet {
		union[k] = struct{}{}
	}
	if len(union) < limit {
		return true
	}
	// Locally live sessions cannot be evicted by a lexicographically earlier
	// newcomer, so admitting that newcomer would exceed the actual quota.
	if len(local) >= limit {
		return false
	}
	return admitsLexicographicallySet(union, key, limit)
}

func admitsLexicographically(local map[string]int, key string, limit int) bool {
	union := make(map[string]struct{}, len(local)+1)
	for k := range local {
		union[k] = struct{}{}
	}
	return admitsLexicographicallySet(union, key, limit)
}

func admitsLexicographicallySet(union map[string]struct{}, key string, limit int) bool {
	keys := make([]string, 0, len(union)+1)
	for k := range union {
		keys = append(keys, k)
	}
	keys = append(keys, key)
	sort.Strings(keys)
	for i := 0; i < limit && i < len(keys); i++ {
		if keys[i] == key {
			return true
		}
	}
	return false
}

// deviceKeyOf normalises a source address the same way core.Tracker.deviceKey
// does: IPv6 collapses to its /64 prefix.
func deviceKeyOf(a netip.Addr) string {
	return deviceKeyWithPrefix(a, 64)
}

func deviceKeyWithPrefix(a netip.Addr, prefix int) string {
	if !a.IsValid() {
		return ""
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is6() {
		if p, err := a.Prefix(prefix); err == nil {
			return p.String()
		}
	}
	return a.String()
}

func normalizeDeviceAddr(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return deviceKeyOf(a)
}
