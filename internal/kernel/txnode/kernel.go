package txnode

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/audit"
	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/transport"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"golang.org/x/time/rate"
)

// Kernel is the native txnode runtime: a thin, stateful adapter over
// internal/dataplane. It owns the node's listeners and user table; TX-Node keeps
// ownership of the panel, certificates, authorization and reporting.
type Kernel struct {
	rt  RuntimeConfig
	log *slog.Logger

	mu       sync.Mutex
	spec     *spec
	tracker  *core.Tracker
	srv      *core.Server
	bind     *bindResult
	auth     *liveHandler
	retiring map[*core.Server]*nativeMeter
	users    map[int]model.UserSpec
	gate     *deviceGate
	running  bool

	router atomic.Pointer[core.Router]

	limitFn  func(uuid string) *rate.Limiter
	deviceFn func(uuid string) (int, bool)

	auditor   atomic.Pointer[audit.Reporter]
	admission atomic.Bool

	// meter is the per-chunk accountant. It is attached before Start by the
	// usage_v2 runtime and/or the local event store.
	meter           *nativeMeter
	localCoord      *usagebucket.Coordinator
	localEventMeter *usagebucket.Meter
}

// New builds an idle kernel. Start binds the node.
func New(rt RuntimeConfig) *Kernel {
	rt = rt.normalized()
	k := &Kernel{
		rt:       rt,
		log:      rt.logger(),
		tracker:  core.NewTracker(),
		users:    make(map[int]model.UserSpec),
		gate:     newRuntimeDeviceGate(rt),
		retiring: make(map[*core.Server]*nativeMeter),
	}
	k.tracker.SetDeviceGate(k.gate)
	if rt.UserTCPLimit > 0 {
		k.tracker.SetConnLimit(rt.UserTCPLimit)
	}
	if rt.DeviceLimit > 0 {
		k.tracker.SetGlobalDeviceLimit(rt.DeviceLimit)
	}
	if rt.DeviceIPv6Prefix > 0 {
		k.tracker.SetIPv6Prefix(rt.DeviceIPv6Prefix)
	}
	k.admission.Store(true)
	return k
}

// Name implements kernel.Kernel.
func (k *Kernel) Name() string { return "txnode" }

// Protocols returns the panel-facing protocol names. hysteria2 is an alias of
// the hysteria v2 handler and is listed so validateNodeRuntime accepts it.
func (k *Kernel) Protocols() []string {
	return []string{
		"vless", "vmess", "trojan", "shadowsocks",
		"hysteria", "hysteria2", "tuic", "naive",
		"socks", "http", "anytls", "mieru", "snell",
	}
}

// Capabilities implements kernel.Kernel. CloseConnection by id is not part of the
// native runtime yet, so ForceCloseConnection stays false.
func (k *Kernel) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  true,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       true,
	}
}

// Start builds and binds the node. Reload preserves established sessions.
func (k *Kernel) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	sp, err := specFromNode(nodeConfig)
	if err != nil {
		return err
	}
	if k.running && k.meter != nil && k.meter.collector != nil {
		return fmt.Errorf("txnode: stop bounded runtime and install a fresh meter before Start")
	}
	if k.running {
		k.stopLocked()
	}
	if k.meter != nil && k.meter.stopped.Load() {
		if k.meter.collector != nil {
			return fmt.Errorf("txnode: stopped bounded runtime requires a fresh meter")
		}
		k.installEventMeterLocked(k.localEvents())
	}
	if k.meter != nil && k.meter.collector != nil && !k.meter.enforcingNow() {
		return fmt.Errorf("txnode: bounded runtime requires an enforcing meter")
	}
	k.admission.Store(false)

	_, router, _, _, srv, res, err := k.buildLocked(nodeConfig, sp, users, tls)
	if err != nil {
		return err
	}
	if err := res.activateDatagrams(); err != nil {
		res.closeAll()
		_ = srv.Close()
		return err
	}
	k.publishUsersLocked(users)
	if err := k.installLocked(sp, router, srv, res); err != nil {
		res.closeAll()
		return err
	}
	k.admission.Store(true)
	k.log.Info("node listening", "protocol", sp.Protocol, "addr", sp.Addr(), "transport", sp.Network)
	return nil
}

// Reload swaps listeners without losing counters or the online table.
func (k *Kernel) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.running {
		return fmt.Errorf("txnode: Reload requires a running runtime")
	}
	if k.meter != nil && k.meter.stopped.Load() {
		return fmt.Errorf("txnode: stopped meter requires a fresh runtime")
	}

	sp, err := specFromNode(nodeConfig)
	if err != nil {
		return err
	}
	_, router, _, _, srv, res, err := k.buildLocked(nodeConfig, sp, users, tls)
	if err != nil {
		return err
	}
	oldSrv, oldBind, oldAuth, oldMeter := k.srv, k.bind, k.auth, k.meter
	wasAdmitted := k.admission.Swap(false)
	if err := switchDatagrams(oldBind, res); err != nil {
		res.closeAll()
		_ = srv.Close()
		k.admission.Store(wasAdmitted)
		return err
	}
	if oldAuth != nil {
		oldAuth.Retire()
	}
	k.publishUsersLocked(users)
	if err := k.installLocked(sp, router, srv, res); err != nil {
		res.closeAll()
		return err
	}
	if oldBind != nil {
		oldBind.closeAll()
	}
	if oldSrv != nil {
		k.retiring[oldSrv] = oldMeter
		go func() {
			// Let sessions accepted by the old generation finish on their old
			// handler, then release its resources.
			time.Sleep(k.rt.DrainTimeout)
			drainServer(oldSrv, k.rt.DrainTimeout)
			oldMeter.detachServer(oldSrv)
			k.mu.Lock()
			delete(k.retiring, oldSrv)
			k.mu.Unlock()
		}()
	}
	k.admission.Store(wasAdmitted)
	k.log.Info("node reloaded", "protocol", sp.Protocol, "addr", sp.Addr())
	return nil
}

// buildLocked constructs a server and its sockets without publishing them.
func (k *Kernel) buildLocked(nc *model.NodeSpec, sp *spec, users []model.UserSpec, cert kernel.TLSCert) (
	core.Handler, *core.Router, *tls.Config, *transport.Reality, *core.Server, *bindResult, error) {

	// A mux-enabled client sends every stream to the mux pseudo-host, so the
	// server side has to be installed before the first listener accepts.
	installMuxServer()
	cu := coreUsers(users)
	handler, err := newLiveHandler(sp, cu, k.log)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	handler.Inherit(k.auth)
	router, err := compileRouter(nc, k.rt, k.log)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	tlsCfg, re, err := security(cert, sp, k.log)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	trust, err := core.ParseTrust(k.rt.TrustedProxies)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	guard := core.NewGuard(core.GuardConfig{
		Enable:    k.rt.InvalidAccessEnable,
		Count:     k.rt.InvalidAccessCount,
		Duration:  k.rt.InvalidAccessDuration,
		Forbidden: k.rt.InvalidAccessForbidden,
	}, k.log)

	meter := k.meter
	srv := core.NewServer(core.ServerOptions{
		Handler:              handler,
		Tracker:              k.tracker,
		Router:               func() *core.Router { return k.router.Load() },
		Trust:                trust,
		Guard:                guard,
		Logger:               k.log,
		HandshakeTimeout:     k.rt.HandshakeTimeout,
		TCPTimeout:           k.rt.TCPTimeout,
		UDPTimeout:           k.rt.UDPTimeout,
		MaxFresh:             k.rt.MaxFresh,
		ProxyProtocol:        sp.ProxyProtocol || k.rt.ProxyProtocol,
		RequireProxyProtocol: sp.RequireProxyProtocol || k.rt.RequireProxyProtocol,
		BindLocal:            k.rt.AutoOutIP,
		Admission:            func() bool { return k.admitted() && (meter == nil || !meter.stopped.Load()) },
		OnAudit:              k.auditSession,
		Hooks:                k.chunkHook(),
	})
	res, err := bindNode(sp, handler, cu, tlsCfg, re, srv, k.rt, k.log)
	if err != nil {
		_ = srv.Close()
		return nil, nil, nil, nil, nil, nil, err
	}
	res.auth = handler
	return handler, router, tlsCfg, re, srv, res, nil
}

// installLocked publishes a built runtime and starts serving.
func (k *Kernel) installLocked(sp *spec, router *core.Router, srv *core.Server, res *bindResult) error {
	k.router.Store(router)
	k.srv = srv
	k.bind = res
	k.auth = res.auth
	publishMux(k)
	k.meter.attachServer(srv)
	k.spec = sp
	k.running = true
	serveTCP(srv, res.ln, k.log)
	return nil
}

// Stop closes listeners and drains sessions.
func (k *Kernel) Stop() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.stopLocked()
}

func (k *Kernel) stopLocked() {
	k.admission.Store(false)
	if k.auth != nil {
		k.auth.Retire()
	}
	unpublishMux(k)
	if k.bind != nil {
		k.bind.closeAll()
		k.bind = nil
	}
	if k.srv != nil {
		drainServer(k.srv, k.rt.DrainTimeout)
		k.meter.detachServer(k.srv)
		k.srv = nil
	}
	for srv, meter := range k.retiring {
		drainServer(srv, k.rt.DrainTimeout)
		meter.detachServer(srv)
		delete(k.retiring, srv)
	}
	k.meter.retire()
	if k.running {
		k.log.Info("node stopped")
	}
	k.running = false
}

// IsRunning reports whether the node currently accepts connections.
func (k *Kernel) IsRunning() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.running
}

// AddUsers registers new users without touching listeners.
func (k *Kernel) AddUsers(users []model.UserSpec) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	next := make(map[int]model.UserSpec, len(k.users)+len(users))
	for id, u := range k.users {
		next[id] = u
	}
	added := 0
	for _, u := range users {
		if _, exists := next[u.ID]; exists {
			continue
		}
		next[u.ID] = u
		added++
	}
	if added > 0 {
		if err := k.replaceUsersLocked(sortedUsers(next)); err != nil {
			return 0, err
		}
	}
	return added, nil
}

// RemoveUsers drops users and closes their live sessions immediately.
func (k *Kernel) RemoveUsers(users []model.UserSpec) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	next := make(map[int]model.UserSpec, len(k.users))
	for id, u := range k.users {
		next[id] = u
	}
	removed := 0
	for _, u := range users {
		if _, exists := next[u.ID]; !exists {
			continue
		}
		delete(next, u.ID)
		removed++
	}
	if removed > 0 {
		if err := k.replaceUsersLocked(sortedUsers(next)); err != nil {
			return 0, err
		}
	}
	return removed, nil
}

// UpdateUsers replaces the whole table.
func (k *Kernel) UpdateUsers(users []model.UserSpec) (int, int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	next := make(map[int]model.UserSpec, len(users))
	for _, u := range users {
		next[u.ID] = u
	}
	added, removed := 0, make([]int, 0)
	for id := range next {
		if _, ok := k.users[id]; !ok {
			added++
		}
	}
	for id := range k.users {
		if _, ok := next[id]; !ok {
			removed = append(removed, id)
		}
	}
	if err := k.replaceUsersLocked(sortedUsers(next)); err != nil {
		return 0, 0, err
	}
	return added, len(removed), nil
}

// GetUserTraffic reports cumulative counters, live addresses and the session
// count from the data plane tracker.
func (k *Kernel) GetUserTraffic(_ context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	if k.tracker == nil {
		return nil, nil, 0, nil
	}
	traffic := k.tracker.Snapshot()
	alive := make(map[int]map[string]bool)
	for id, addrs := range k.tracker.Alive() {
		set := make(map[string]bool, len(addrs))
		for _, a := range addrs {
			set[a] = true
		}
		alive[id] = set
	}
	count := 0
	for _, n := range k.tracker.Connections() {
		count += n
	}
	return traffic, alive, count, nil
}

// CloseConnection is not supported by the native runtime: sessions are closed by
// user (CloseUserConnections). Capabilities.ForceCloseConnection is false.
func (k *Kernel) CloseConnection(_ context.Context, connID string) error {
	return fmt.Errorf("txnode: CloseConnection(%q) is not supported", connID)
}

// CloseUserConnections closes every live session of one user UUID.
func (k *Kernel) CloseUserConnections(_ context.Context, uuid string) error {
	k.mu.Lock()
	id := 0
	for _, u := range k.users {
		if u.UUID == uuid {
			id = u.ID
			break
		}
	}
	k.mu.Unlock()
	if id > 0 {
		k.tracker.CloseUserConns(id)
	}
	return nil
}

// SetSpeedLimitFunc installs TX-Node's per-user limiter source and applies it to
// every known user.
func (k *Kernel) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	k.mu.Lock()
	k.limitFn = fn
	k.applyLimitsLocked()
	k.mu.Unlock()
}

// SetDeviceLimitFunc installs TX-Node's device-limit source.
func (k *Kernel) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	k.mu.Lock()
	k.deviceFn = fn
	if k.gate != nil {
		k.gate.setLimitFunc(fn)
	}
	k.applyLimitsLocked()
	k.mu.Unlock()
}

// UpdateGlobalDevices installs the panel's global device address set.
func (k *Kernel) UpdateGlobalDevices(users map[int][]string) {
	if k.gate != nil {
		k.gate.setGlobal(users)
	}
}

// ClearGlobalDevices drops the panel snapshot (WS disconnect).
func (k *Kernel) ClearGlobalDevices() {
	if k.gate != nil {
		k.gate.clearGlobal()
	}
}

// SetAuditor installs the access-audit reporter observed by the relay.
func (k *Kernel) SetAuditor(r *audit.Reporter) { k.auditor.Store(r) }

// StopAuthorization refuses new sessions immediately (admission gate) and stops
// accepting on the listeners. Existing sessions finish through the normal drain.
func (k *Kernel) StopAuthorization() {
	k.admission.Store(false)
	k.mu.Lock()
	if k.srv != nil {
		k.srv.CloseAllSessions()
	}
	for srv := range k.retiring {
		srv.CloseAllSessions()
	}
	if k.bind != nil {
		if k.bind.ln != nil {
			_ = k.bind.ln.Close()
		}
		if k.bind.pc != nil {
			_ = k.bind.pc.Close()
		}
		for _, c := range k.bind.closers {
			_ = c.Close()
		}
	}
	k.mu.Unlock()
	k.log.Warn("authorization denied: new sessions refused")
}

// NewNativeMeter implements service.nativeUsageKernel: it builds the usage_v2
// meter over the caller-owned collector. It must be called before Start, because
// the relay installs its hook when the server is built.
func (k *Kernel) NewNativeMeter(collector *usageinterval.NativeCollector, users map[string]int) (usageinterval.Meter, bool) {
	if collector == nil {
		return nil, false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	meter, ok := k.replaceNativeMeterLocked(collector, users)
	if !ok {
		return nil, false
	}
	return meter, true
}

// SetNativeUsageTracker implements service.nativeUsageKernel: it turns the meter
// into an enforcing one. Replacing it while the node runs is refused because the
// relay already holds the hook.
func (k *Kernel) SetNativeUsageTracker(m usageinterval.Meter) bool {
	nm, ok := m.(*nativeMeter)
	if !ok || nm == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.running || k.meter != nm {
		return false
	}
	return nm.EnableEnforcingBounded()
}

// SetLocalEventConsumer implements service.localEventKernel: it creates the
// local meter and registers it with the process coordinator. It must be called
// before Start.
func (k *Kernel) SetLocalEventConsumer(consumer *usagebucket.Coordinator) bool {
	if consumer == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.running || k.localCoord != nil {
		return false
	}
	meter, err := usagebucket.New(usagebucket.Options{Enabled: true, Window: time.Second, MaxEvents: 128, MaxSealed: 8})
	if err != nil {
		return false
	}
	if err := consumer.Add(meter); err != nil {
		return false
	}
	k.localCoord = consumer
	k.localEventMeter = meter
	k.installEventMeterLocked(meter)
	return true
}

func (k *Kernel) localEvents() *usagebucket.Meter { return k.localEventMeter }

// chunkHook returns the installed accountant, or nil when neither usage_v2 nor
// the local event store is active.
func (k *Kernel) chunkHook() core.ChunkHook {
	if k.meter == nil {
		return nil
	}
	return k.meter
}

// syncLocked refreshes the tracker, the device gate and the limit buckets from
// the current user table.
func (k *Kernel) syncLocked() error {
	wasAdmitted := k.admission.Swap(false)
	defer k.admission.Store(wasAdmitted)
	users := sortedUsers(k.users)
	cu := coreUsers(users)
	if k.auth != nil {
		if err := k.auth.SetUsers(cu); err != nil {
			return err
		}
	}
	if k.bind != nil {
		k.bind.datagramUsers = append([]core.User(nil), cu...)
		for _, setter := range k.bind.userSetters {
			setter.SetUsers(cu)
		}
	}
	k.refreshPolicyLocked(users)
	return nil
}

func (k *Kernel) refreshPolicyLocked(users []model.UserSpec) {
	if k.gate != nil {
		k.gate.setUsers(users)
	}
	k.tracker.SetUsers(coreUsers(users))
	for _, u := range users {
		k.applyUserLimitLocked(u)
	}
}

func (k *Kernel) replaceUsersLocked(users []model.UserSpec) error {
	previous := k.users
	k.publishUserMapLocked(users)
	if err := k.syncLocked(); err != nil {
		k.users = previous
		return err
	}
	return nil
}

func (k *Kernel) publishUsersLocked(users []model.UserSpec) {
	k.publishUserMapLocked(users)
	k.refreshPolicyLocked(users)
}

func (k *Kernel) publishUserMapLocked(users []model.UserSpec) {
	next := make(map[int]model.UserSpec, len(users))
	for _, u := range users {
		next[u.ID] = u
	}
	k.users = next
}

func (k *Kernel) applyLimitsLocked() {
	for _, u := range sortedUsers(k.users) {
		k.applyUserLimitLocked(u)
	}
}

func (k *Kernel) applyUserLimitLocked(u model.UserSpec) {
	if k.limitFn != nil {
		if lim := k.limitFn(u.UUID); lim != nil && lim.Limit() > 0 {
			bps := int64(lim.Limit())
			burst := int64(lim.Burst())
			k.tracker.SetUserLimit(u.ID, bps, bps, burst)
		} else {
			k.tracker.SetUserLimit(u.ID, 0, 0, 0)
		}
	}
	if k.deviceFn != nil {
		if n, ok := k.deviceFn(u.UUID); ok {
			k.tracker.SetUserDeviceLimit(u.ID, n)
		}
	}
}

func sortedUsers(m map[int]model.UserSpec) []model.UserSpec {
	out := make([]model.UserSpec, 0, len(m))
	for _, u := range m {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// audit forwards one routed session to TX-Node's audit reporter.
func (k *Kernel) auditSession(userID int, target, targetIP, sourceIP string) {
	r := k.auditor.Load()
	if r == nil || !r.Enabled() || userID <= 0 {
		return
	}
	if target == "" {
		target = targetIP
	}
	if target == "" {
		return
	}
	r.ObserveWithTargetIP(userID, target, targetIP, sourceIP)
}

// admitted is the ServerOptions.Admission callback.
func (k *Kernel) admitted() bool { return k.admission.Load() }

var _ kernel.Kernel = (*Kernel)(nil)
