// Package machine implements the machine-mode orchestrator that dynamically
// discovers nodes from the panel's machine API and manages their lifecycles.
package machine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/buildinfo"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/monitor"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/runtimeupdate"
	"github.com/ANRCM0/TX-Node/internal/service"
)

// nodeHandle tracks a running node service.
type nodeHandle struct {
	cancel  context.CancelFunc
	done    chan struct{}
	mailbox *controlplane.NodeMailbox
}

// Orchestrator manages all nodes bound to a panel machine. It:
//   - discovers nodes via GET /machine/nodes
//   - starts / stops Service instances as nodes are added / removed
//   - maintains a shared WS connection that demuxes events by node_id
//   - reports machine-level load via POST /machine/status
type Orchestrator struct {
	cfg    *config.Config
	client machineControlPlane // machine transport boundary

	mu    sync.Mutex
	nodes map[int]*nodeHandle // node_id → handle

	// Per-node mailbox keyed by node_id. Shared WS events are aggregated here
	// and each node service drains the latest state when ready.
	eventsMu  sync.RWMutex
	mailboxes map[int]*controlplane.NodeMailbox
	statuses  map[int]chan<- controlplane.StatusChange

	// The shared transport may be installed after startup when the initial
	// handshake fails or the panel enables WS later. Node pushes look it up live.
	wsMu     sync.RWMutex
	ws       machineSocket
	wsCancel context.CancelFunc

	// Discovery may be triggered by both the ticker and an incoming WS event.
	rediscoverMu sync.Mutex

	// runCtx is stored from Run() so that onMachineEvent can trigger rediscover
	// for sync.nodes events without blocking the main loop.
	runCtx context.Context

	// wantedNodes is the number of nodes the panel last told us to run. It is
	// the denominator for the health snapshot.
	wantedNodes int

	// failures tracks backoff state for nodes whose service exited with an
	// error. Guarded by mu.
	failures map[int]*nodeFailure

	// reportedFailed is the last failure count written to the log, so the
	// warning is emitted on change only instead of once per discovery tick.
	// Guarded by mu.
	reportedFailed int

	pullInterval time.Duration
	pushInterval time.Duration

	// runtimeUpdater is a bounded client for the Installer-owned host bridge.
	// It never executes shell/Docker operations inside the TX-Node container.
	runtimeUpdater *runtimeupdate.Manager
}

// nodeFailure is the backoff bookkeeping for one node.
type nodeFailure struct {
	count     int
	nextRetry time.Time
	lastErr   error
}

const (
	// First retry after a failed start waits this long.
	failureBackoffInitial = 15 * time.Second
	// ...and never longer than this, no matter how many attempts failed.
	failureBackoffMax = 5 * time.Minute
	// Caps the shift so the exponential curve cannot overflow.
	backoffMaxShift = 10
	// A node that stayed up at least this long before failing was healthy at
	// some point, so its backoff counter restarts instead of compounding.
	stableRunThreshold = 60 * time.Second
)

// backoffFor returns how long to wait before the nth retry (1-based).
// Pure function, kept separate so it can be tested without a panel.
func backoffFor(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > backoffMaxShift {
		shift = backoffMaxShift
	}
	d := failureBackoffInitial << shift
	if d <= 0 || d > failureBackoffMax {
		d = failureBackoffMax
	}
	return d
}

// New creates a machine orchestrator from the given config.
func NewChecked(cfg *config.Config) (*Orchestrator, error) {
	panelCfg := config.PanelConfig{
		URL:       cfg.Panel.URL,
		Token:     cfg.Machine.Token,
		MachineID: cfg.Machine.MachineID,
	}
	cp, err := newMachineControlPlane(cfg.Panel.Provider, panelCfg)
	if err != nil {
		return nil, err
	}
	return &Orchestrator{
		cfg:            cfg,
		client:         cp,
		nodes:          make(map[int]*nodeHandle),
		mailboxes:      make(map[int]*controlplane.NodeMailbox),
		statuses:       make(map[int]chan<- controlplane.StatusChange),
		failures:       make(map[int]*nodeFailure),
		runtimeUpdater: runtimeupdate.New(runtimeupdate.DefaultDir),
	}, nil
}

// New retains the original constructor for validated configs.
func New(cfg *config.Config) *Orchestrator {
	orch, _ := NewChecked(cfg)
	return orch
}

// Run is the main loop. It blocks until ctx is cancelled.
func (o *Orchestrator) Run(ctx context.Context) error {
	o.runCtx = ctx
	nodesResp, err := o.client.GetMachineNodes()
	if err != nil {
		return fmt.Errorf("initial node discovery: %w", err)
	}

	o.applyIntervals(nodesResp.BaseConfig)
	o.setWanted(len(nodesResp.Nodes))
	nlog.Core().Info(fmt.Sprintf("machine %d: discovered %d nodes",
		o.cfg.Machine.MachineID, len(nodesResp.Nodes)))

	// Stop contributing to /healthz once this orchestrator is gone, otherwise a
	// stale "degraded" snapshot would outlive the instance that produced it.
	defer globalHealth.Remove(o.cfg.InstanceID)

	// Start machine-level WS as early as possible so sync.nodes can reach an
	// empty machine before the first node is attached.
	o.tryStartWS(ctx)

	// Start initial nodes.
	for _, n := range nodesResp.Nodes {
		o.startNode(ctx, n)
	}
	o.reportHealth()

	discoveryTicker := time.NewTicker(o.pullInterval)
	statusTicker := time.NewTicker(o.pushInterval)
	defer discoveryTicker.Stop()
	defer statusTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			o.stopAll()
			return nil

		case <-discoveryTicker.C:
			o.rediscover(ctx)
			// If the initial handshake failed (or WS was disabled), retry discovery.
			// Once a WS client exists, its own Run loop handles reconnects.
			o.tryStartWS(ctx)

		case <-statusTicker.C:
			o.reportMachineStatus()
		}
	}
}

// ─── Node lifecycle ──────────────────────────────────────────────────────

func (o *Orchestrator) startNode(ctx context.Context, mn machineNode) {
	o.mu.Lock()
	if _, exists := o.nodes[mn.ID]; exists {
		o.mu.Unlock()
		return
	}
	// Still serving a backoff from an earlier failure: leave it parked until
	// the window expires. Without this a node that dies instantly (port
	// already in use) would be restarted on every single discovery tick.
	if f, ok := o.failures[mn.ID]; ok && time.Now().Before(f.nextRetry) {
		o.mu.Unlock()
		return
	}

	nodeCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	mb := controlplane.NewNodeMailbox()
	o.nodes[mn.ID] = &nodeHandle{cancel: cancel, done: done, mailbox: mb}
	o.mu.Unlock()

	o.eventsMu.Lock()
	o.mailboxes[mn.ID] = mb
	o.eventsMu.Unlock()

	nodeCfg := o.cfg.ExpandMachineNode(mn.ID, mn.Type)

	perNodeClient := o.client.ForNode(mn.ID)

	// Pre-fetch node config to detect transport-based kernel requirements.
	// If the transport (e.g. xhttp) is incompatible with the configured kernel
	// (e.g. singbox), auto-switch to the required kernel for this node.
	if cfgSnapshot, err := perNodeClient.GetConfig(); err == nil && cfgSnapshot != nil {
		if resolved := model.ResolveKernelForTransport(cfgSnapshot.Network, nodeCfg.Kernel.Type); resolved != nodeCfg.Kernel.Type {
			nlog.Core().Info(fmt.Sprintf("machine: auto-switching kernel for node %d (%s→%s, transport=%s)",
				mn.ID, nodeCfg.Kernel.Type, resolved, cfgSnapshot.Network))
			nodeCfg.Kernel.Type = resolved
		}
	}
	// Reset cached ETag so the subsequent GetConfig in Initial() gets a full response.
	perNodeClient.ResetConfigETag()

	// Always register a virtual push and mailbox, including REST-only startup.
	// A recovered machine WS must be usable by nodes already running.
	push := &machineNodePush{nodeID: mn.ID, wsLookup: o.currentWS}

	// The registerFn is called by MachineXboardControlPlane.Initial() to expose
	// the node mailbox + status channel to the Service.
	nodeID := mn.ID
	registerFn := func(st chan<- controlplane.StatusChange) *controlplane.NodeMailbox {
		o.registerNode(nodeID, st)
		return mb
	}

	cp := perNodeClient.ControlPlane(nodeCfg.Kernel, push, registerFn)
	svc := service.NewWithControlPlane(nodeCfg, cp)

	nlog.Core().Info(fmt.Sprintf("machine: starting node %d (%s/%s)",
		mn.ID, mn.Type, mn.Name))

	startedAt := time.Now()
	go func() {
		defer close(done)
		defer o.unregisterNode(mn.ID)
		if err := svc.Run(nodeCtx); err != nil {
			o.recordFailure(mn.ID, err, startedAt)
			return
		}
		// Clean exit (context cancelled by stopNode / stopAll), not a failure.
		o.clearFailure(mn.ID)
	}()
}

// recordFailure parks a node in exponential backoff and logs the attempt.
// startedAt is when the node was launched: if it ran long enough to count as
// stable, the backoff counter restarts rather than compounding old failures.
func (o *Orchestrator) recordFailure(nodeID int, err error, startedAt time.Time) {
	o.mu.Lock()
	f, ok := o.failures[nodeID]
	if !ok {
		f = &nodeFailure{}
		o.failures[nodeID] = f
	}
	if time.Since(startedAt) > stableRunThreshold {
		f.count = 0
	}
	f.count++
	f.lastErr = err
	f.nextRetry = time.Now().Add(backoffFor(f.count))
	count, retryIn := f.count, time.Until(f.nextRetry)
	o.mu.Unlock()

	nlog.Core().Error("machine node exited with error",
		"node_id", nodeID, "error", err,
		"attempt", count, "retry_in", retryIn.Round(time.Second).String())
	o.reportHealth()
}

// clearFailure drops a node's backoff state after a clean run.
func (o *Orchestrator) clearFailure(nodeID int) {
	o.mu.Lock()
	delete(o.failures, nodeID)
	o.mu.Unlock()
	o.reportHealth()
}

// reportHealth publishes the current node counts for /healthz.
func (o *Orchestrator) reportHealth() {
	o.mu.Lock()
	wanted := o.wantedNodes
	failed := 0
	now := time.Now()
	for _, f := range o.failures {
		if now.Before(f.nextRetry) {
			failed++
		}
	}
	changed := failed != o.reportedFailed
	o.reportedFailed = failed
	o.mu.Unlock()
	if failed > wanted {
		failed = wanted
	}
	globalHealth.Report(o.cfg.InstanceID, NodeHealth{Total: wanted, Failed: failed})

	// Without this the only trace of a fully broken machine would be one ERROR
	// line per node at startup, which is easy to miss in a long log.
	if changed && failed > 0 {
		nlog.Core().Warn("machine has failing nodes, they will be retried with backoff",
			"failed", failed, "total", wanted, "machine_id", o.machineIDForLog())
	}
}

// machineIDForLog reads the machine id tolerating a nil Machine section, which
// is possible for configs that never ran in machine mode. reportHealth is a
// logging path and must never be the thing that takes the process down.
func (o *Orchestrator) machineIDForLog() int {
	if o.cfg == nil || o.cfg.Machine == nil {
		return 0
	}
	return o.cfg.Machine.MachineID
}

// setWanted records how many nodes the panel expects this machine to run.
func (o *Orchestrator) setWanted(n int) {
	o.mu.Lock()
	o.wantedNodes = n
	o.mu.Unlock()
}

func (o *Orchestrator) stopNode(nodeID int) {
	o.mu.Lock()
	h, ok := o.nodes[nodeID]
	if !ok {
		o.mu.Unlock()
		return
	}
	delete(o.nodes, nodeID)
	o.mu.Unlock()

	o.eventsMu.Lock()
	delete(o.mailboxes, nodeID)
	o.eventsMu.Unlock()

	nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", nodeID))
	h.cancel()
	<-h.done
}

func (o *Orchestrator) stopAll() {
	o.mu.Lock()
	handles := make(map[int]*nodeHandle, len(o.nodes))
	for id, h := range o.nodes {
		handles[id] = h
	}
	o.mu.Unlock()

	for id, h := range handles {
		nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", id))
		h.cancel()
	}
	for _, h := range handles {
		<-h.done
	}

	if o.wsCancel != nil {
		o.wsCancel()
	}
}

// ─── Node discovery ──────────────────────────────────────────────────────

func (o *Orchestrator) rediscover(ctx context.Context) {
	o.rediscoverMu.Lock()
	defer o.rediscoverMu.Unlock()
	nodesResp, err := o.client.GetMachineNodes()
	if err != nil {
		nlog.Core().Warn("machine node discovery failed", "error", err)
		return
	}

	o.setWanted(len(nodesResp.Nodes))

	wanted := make(map[int]machineNode, len(nodesResp.Nodes))
	for _, n := range nodesResp.Nodes {
		wanted[n.ID] = n
	}

	o.mu.Lock()
	var toRemove []int
	seen := make(map[int]bool)
	for id := range o.nodes {
		if _, ok := wanted[id]; !ok {
			if !seen[id] {
				seen[id] = true
				toRemove = append(toRemove, id)
			}
		}
	}
	// Nodes parked in backoff are absent from o.nodes (unregisterNode removed
	// them), so they must be collected separately or their backoff state would
	// leak for the lifetime of the process.
	for id := range o.failures {
		if _, ok := wanted[id]; !ok {
			if !seen[id] {
				seen[id] = true
				toRemove = append(toRemove, id)
			}
		}
	}
	o.mu.Unlock()

	for _, id := range toRemove {
		o.stopNode(id)     // no-op when only backoff state remains
		o.clearFailure(id) // node is gone from the panel; drop its backoff too
	}

	for _, n := range nodesResp.Nodes {
		o.startNode(ctx, n) // no-op if already running or still in backoff
	}
	o.reportHealth()
}

// ─── Machine status reporting ────────────────────────────────────────────

func (o *Orchestrator) reportMachineStatus() {
	s := monitor.Collect()
	runtimeStatus := &machineRuntimeStatus{
		Version:    buildinfo.Version,
		BuildTime:  buildinfo.BuildTime,
		Deployment: "unknown",
	}
	if o.runtimeUpdater != nil {
		runtimeStatus.UpdaterAvailable = o.runtimeUpdater.Available()
		runtimeStatus.UpdateTargets = o.runtimeUpdater.SupportedTargets()
		if runtimeStatus.UpdaterAvailable {
			runtimeStatus.Deployment = "docker"
		}
		if last := o.runtimeUpdater.LastStatus(); last != nil {
			runtimeStatus.Update = &machineRuntimeUpdateStatus{
				RequestID: last.RequestID,
				Target:    last.Target,
				Status:    last.Status,
				UpdatedAt: last.UpdatedAt,
				Message:   last.Message,
			}
		}
	}

	if err := o.client.ReportMachineStatus(
		s.CPU,
		[2]uint64{s.MemTotal, s.MemUsed},
		[2]uint64{s.SwapTotal, s.SwapUsed},
		[2]uint64{s.DiskTotal, s.DiskUsed},
		s.NetInSpeed, s.NetOutSpeed,
		runtimeStatus,
	); err != nil {
		nlog.Core().Warn("machine status report failed", "error", err)
	}
}

// ─── WS mux ─────────────────────────────────────────────────────────────

func (o *Orchestrator) currentWS() machineSocket {
	o.wsMu.RLock()
	defer o.wsMu.RUnlock()
	return o.ws
}

func (o *Orchestrator) tryStartWS(ctx context.Context) {
	if ctx.Err() != nil || o.currentWS() != nil {
		return
	}
	hs, err := o.client.Handshake()
	if err != nil {
		nlog.Core().Warn("machine ws handshake failed, REST only", "error", err)
		return
	}
	if !hs.Enabled || hs.URL == "" {
		nlog.Core().Info("machine: ws disabled by panel, REST only")
		return
	}

	ws := o.client.NewMachineSocket(
		hs.URL, o.cfg.Machine.Token, o.cfg.Machine.MachineID,
		o.cfg.WS, o.cfg.Kernel, o.onMachineEvent, o.onMachineStatus,
	)

	o.wsMu.Lock()
	o.ws = ws
	o.wsMu.Unlock()
	wsCtx, wsCancel := context.WithCancel(ctx)
	o.wsCancel = wsCancel
	go ws.Run(wsCtx)

	nlog.Core().Info("machine: ws mux started")
}

func (o *Orchestrator) onMachineEvent(event machineEvent) {
	if event.Kind == machineEventRuntimeUpdate {
		if event.RuntimeUpdate == nil {
			nlog.Core().Warn("machine runtime update missing typed payload")
			return
		}
		if o.runtimeUpdater == nil {
			nlog.Core().Warn("machine runtime updater unavailable")
			return
		}
		if err := o.runtimeUpdater.Request(
			event.RuntimeUpdate.RequestID,
			event.RuntimeUpdate.Target,
		); err != nil {
			nlog.Core().Warn("machine runtime update request rejected",
				"request_id", event.RuntimeUpdate.RequestID,
				"error", err,
			)
			return
		}
		nlog.Core().Info("machine runtime update accepted",
			"request_id", event.RuntimeUpdate.RequestID,
			"target", event.RuntimeUpdate.Target,
		)
		return
	}

	// sync.nodes is a machine-level event, not per-node
	if event.Kind == machineEventSyncNodes {
		nlog.Core().Info("machine received sync.nodes, triggering immediate rediscovery")
		go o.rediscover(o.runCtx)
		return
	}

	nodeID := event.NodeID
	if nodeID == 0 {
		nlog.Core().Debug("machine ws event missing node_id, dropping", "type", event.Kind)
		return
	}

	translated, err := event.NodeEvent, event.Err
	if err != nil {
		nlog.Core().Warn("machine ws event translation failed",
			"type", event.Kind, "node_id", nodeID, "error", err)
		return
	}

	o.eventsMu.RLock()
	mailbox, ok := o.mailboxes[nodeID]
	o.eventsMu.RUnlock()
	if !ok {
		nlog.Core().Debug("machine ws event for unknown node", "node_id", nodeID, "type", event.Kind)
		return
	}

	mailbox.Apply(translated)
}

func (o *Orchestrator) onMachineStatus(connected bool) {
	change := controlplane.StatusChange{Connected: connected}
	o.eventsMu.RLock()
	defer o.eventsMu.RUnlock()
	for _, ch := range o.statuses {
		select {
		case ch <- change:
		default:
		}
	}
}

func (o *Orchestrator) registerNode(nodeID int, st chan<- controlplane.StatusChange) {
	o.eventsMu.Lock()
	o.statuses[nodeID] = st
	o.eventsMu.Unlock()
}

func (o *Orchestrator) unregisterNode(nodeID int) {
	// o.nodes MUST be cleaned up here, not only in stopNode. This runs from the
	// node goroutine's defer, including when the service exits with an error.
	// Leaving the handle behind would make startNode's "already running" guard
	// skip the node forever — a node that failed once (bad port, panel hiccup)
	// would never come back, even after the cause was fixed.
	//
	// The two maps are guarded by different mutexes; they are taken as separate
	// critical sections (never nested) to keep lock ordering deadlock-free.
	o.mu.Lock()
	delete(o.nodes, nodeID)
	o.mu.Unlock()

	o.eventsMu.Lock()
	delete(o.mailboxes, nodeID)
	delete(o.statuses, nodeID)
	o.eventsMu.Unlock()
}

func (o *Orchestrator) applyIntervals(bc machineIntervals) {
	o.pullInterval = time.Duration(bc.PullInterval) * time.Second
	if o.pullInterval < 30*time.Second {
		o.pullInterval = 60 * time.Second
	}
	o.pushInterval = time.Duration(bc.PushInterval) * time.Second
	if o.pushInterval < 10*time.Second {
		o.pushInterval = 60 * time.Second
	}
}

// ─── Virtual PushClient ─────────────────────────────────────────────────

// machineNodePush implements controlplane.PushClient for a single node
// backed by the shared machine WS connection. Events are routed by the
// WS mux directly to the Service's channels; this adapter only provides
// connectivity status and send capabilities.
type machineNodePush struct {
	nodeID   int
	wsLookup func() machineSocket
}

func (p *machineNodePush) currentWS() machineSocket {
	if p.wsLookup == nil {
		return nil
	}
	return p.wsLookup()
}

func (p *machineNodePush) Run(ctx context.Context) {
	// The shared WS mux pushes events into our channels; we just wait.
	<-ctx.Done()
}

func (p *machineNodePush) IsConnected() bool {
	ws := p.currentWS()
	return ws != nil && ws.IsConnected()
}

func (p *machineNodePush) SendDeviceReport(devices map[int][]string) {
	ws := p.currentWS()
	if ws == nil {
		return
	}
	payload := map[string]interface{}{
		"node_id": p.nodeID,
	}
	// Flatten into the standard format with node_id wrapper.
	strDevices := make(map[string][]string, len(devices))
	for uid, ips := range devices {
		strDevices[fmt.Sprintf("%d", uid)] = ips
	}
	payload["devices"] = strDevices
	data, _ := json.Marshal(payload)
	ws.SendDeviceReport(data)
}
