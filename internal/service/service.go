package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/auditcoord"
	"github.com/ANRCM0/TX-Node/internal/certcoord"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/kernel/singbox"
	"github.com/ANRCM0/TX-Node/internal/kernel/xray"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/limiter"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/monitor"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/nodesync"
	"github.com/ANRCM0/TX-Node/internal/pushsync"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	"github.com/ANRCM0/TX-Node/internal/tracker"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usageobserver"
	"github.com/ANRCM0/TX-Node/internal/userstate"
)

type Service struct {
	cfg          *config.Config
	source       controlplane.Source
	sink         controlplane.Sink
	kernel       kernel.Kernel
	kernelLife   *kernellifecycle.Controller
	tracker      *tracker.Tracker
	limiter      *limiter.Limiter
	speedTracker *limiter.SpeedTracker
	certs        *certcoord.Coordinator

	lastConfig *model.NodeSpec
	users      *userstate.Controller

	// nodeLog is the logger with node context for this service instance.
	nodeLog *nlog.NodeLog

	pushInterval int // seconds
	pullInterval int // seconds

	lastConfigHash     string // desired full configuration hash
	desiredGeneration  uint64 // main Service goroutine only
	appliedConfigHash  string
	appliedUserHash    string
	desiredDirty       bool
	pendingCertRenewal bool
	applicationFailure string
	configRejected     bool
	syncer             *nodesync.Controller
	reporter           *reporting.Controller
	reporterInitErr    error
	legacyPendingPath  string
	usageV2            *isolatedUsageRuntime
	usageOwner         *usagebucket.ProcessOwner

	push             *pushsync.Controller
	machineMailbox   *controlplane.NodeMailbox
	machineMailboxCh <-chan struct{}

	// metricsMu guards mutable runtime snapshots consumed by reporting.
	// Push transport state is owned independently by pushsync.Controller.
	metricsMu sync.RWMutex

	observerMu    sync.Mutex
	observer      *usageobserver.Observer
	observerState string

	eventConsumerMu    sync.Mutex
	eventConsumer      *usagebucket.Coordinator
	eventConsumerState string
	eventOwner         *usagebucket.ProcessOwner
	eventFactory       func(string, usagebucket.StoreOptions, usagebucket.CoordinatorOptions) (*usagebucket.Coordinator, error)
}

func NewChecked(cfg *config.Config) (*Service, error) {
	cp, err := controlplane.NewForConfigChecked(cfg)
	if err != nil {
		return nil, err
	}
	return newService(cfg, cp), nil
}

func New(cfg *config.Config) *Service {
	svc, _ := NewChecked(cfg)
	return svc
}

// NewWithControlPlane creates a Service with an externally-provided
// ControlPlane. Used by the machine orchestrator to inject a
// MachineXboardControlPlane with WS mux routing.
func NewWithControlPlane(cfg *config.Config, cp controlplane.ControlPlane) *Service {
	return newService(cfg, cp)
}

func newService(cfg *config.Config, cp controlplane.ControlPlane) *Service {
	var k kernel.Kernel
	switch cfg.Kernel.Type {
	case "singbox":
		k = singbox.New(cfg.Kernel)
	case "xray":
		k = xray.New(cfg.Kernel)
	default:
		nlog.Core().Warn("unsupported kernel type, defaulting to sing-box", "type", cfg.Kernel.Type)
		k = singbox.New(cfg.Kernel)
	}

	l := limiter.New()
	st := limiter.NewSpeedTracker(l)

	// Optional Access Audit remains an adapter over the existing audit.Reporter.
	// Service does not own panel audit credentials, reporter construction, or
	// kernel-specific attachment logic.
	auditcoord.Attach(cfg.Audit, cp, k)

	reporter := reporting.New(cp)
	var reporterInitErr error
	var legacyPendingPath string
	if cfg.Kernel.ConfigDir != "" && !cfg.IsStandalone() {
		// The directory must be a persistent writable volume; no traffic
		// is acknowledged unless the pending batch is durably spooled first.
		key := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%s",
			cfg.Panel.URL, cfg.Panel.NodeID, cfg.Panel.MachineID, cfg.InstanceID)))
		path := filepath.Join(cfg.Kernel.ConfigDir,
			".txnode-traffic-"+hex.EncodeToString(key[:12])+".pending.json")
		legacyPendingPath = path
		reporter, reporterInitErr = reporting.NewDurable(cp, path)
	}
	s := &Service{
		reporterInitErr:   reporterInitErr,
		legacyPendingPath: legacyPendingPath,
		cfg:               cfg,
		source:            cp,
		sink:              cp,
		kernel:            k,
		kernelLife:        kernellifecycle.New(k),
		tracker:           tracker.New(),
		limiter:           l,
		speedTracker:      st,
		certs:             certcoord.New(cfg.Cert),
		users:             userstate.New(l, st),
		syncer:            nodesync.New(cp),
		push:              pushsync.New(cp),
		reporter:          reporter,
	}
	return s
}

func (s *Service) Run(ctx context.Context) error {
	if s.reporterInitErr != nil {
		return fmt.Errorf("durable traffic report spool initialization failed: %w", s.reporterInitErr)
	}
	if err := s.preflightUsageV2(); err != nil {
		return err
	}
	defer s.closeUsageV2()
	s.initUsageObserver()
	defer s.closeUsageObserver()
	s.initLocalEventConsumer()
	defer s.closeLocalEventConsumer()
	// Start cert manager (handles auto-TLS or manual cert verification)
	if err := s.certs.Start(ctx); err != nil {
		return fmt.Errorf("cert manager: %w", err)
	}
	defer s.certs.Stop()

	// Handshake: get WS config + initial data in one call
	if err := s.initialSetup(ctx); err != nil {
		return fmt.Errorf("initial setup: %w", err)
	}
	defer s.stopKernelObserved(false)
	s.startUsageV2Worker()
	usageLease, stopUsageLease := s.usageLeaseChannel()
	defer stopUsageLease()

	// Set up tickers
	trackTicker := time.NewTicker(time.Duration(s.cfg.Node.TrackInterval) * time.Second)
	pushInterval := time.Duration(math.Max(float64(s.pushInterval), 5)) * time.Second
	pullInterval := time.Duration(s.pullInterval) * time.Second
	reportTicker := time.NewTicker(pushInterval)
	pullTicker := time.NewTicker(pullInterval)
	deviceReportTicker := time.NewTicker(time.Duration(s.cfg.Node.DeviceReportInterval) * time.Second)

	// WS discovery: when in REST-only mode, periodically re-handshake to check
	// if WS has been enabled. When WS is disconnected for too long, re-check
	// if it's still available.
	wsDiscoveryTicker := time.NewTicker(time.Duration(s.cfg.WS.DiscoveryInterval) * time.Second)

	defer trackTicker.Stop()
	defer reportTicker.Stop()
	defer pullTicker.Stop()
	defer deviceReportTicker.Stop()
	defer wsDiscoveryTicker.Stop()

	s.push.Start(ctx)
	defer s.push.Stop()

	for {
		if err := s.syncer.Terminal(); err != nil {
			return s.stopForAuthorityDenial(err)
		}
		if cause := context.Cause(ctx); cause != nil {
			if controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
		}
		select {
		case <-ctx.Done():
			if cause := context.Cause(ctx); cause != nil {
				if controlerror.IsAuthoritativeStopCause(cause) {
					return s.stopForAuthorityDenial(cause)
				}
			}
			if s.usageMode() {
				s.usageV2.tracker.StopBoundedUsageTraffic()
			}
			s.pushReportSync()
			return nil

		case <-s.usageFailureChannel():
			s.failUsageV2()
			return errUsageV2
		case <-usageLease:
			s.failUsageV2()
			return errUsageV2
		case <-trackTicker.C:
			if cause := context.Cause(ctx); controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
			s.trackAndEnforce(ctx)

		case <-reportTicker.C:
			if cause := context.Cause(ctx); controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
			s.pushReportAsync()

		case <-deviceReportTicker.C:
			if cause := context.Cause(ctx); controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
			s.reportDevices()

		case <-pullTicker.C:
			if cause := context.Cause(ctx); controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
			// WebSocket provides low-latency updates, while periodic REST polling
			// provides eventual consistency if a push event is missed. Panel API
			// ETags keep this reconciliation cheap when nothing changed.
			if s.push != nil && s.push.Connected() {
				nlog.Core().Debug("reconciling from API (ws connected)")
			} else {
				nlog.Core().Debug("polling from API (ws not connected)")
			}
			s.schedulePoll(ctx)

		case result := <-s.syncer.Results():
			if cause := context.Cause(ctx); controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
			if result.Terminal != nil {
				return s.stopForAuthorityDenial(result.Terminal)
			}
			s.applySyncResult(ctx, result)

		case <-wsDiscoveryTicker.C:
			if cause := context.Cause(ctx); controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
			if !s.usageMode() {
				s.discoverPush(ctx)
			}

		case status := <-s.push.Statuses():
			if cause := context.Cause(ctx); controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
			s.handlePushStatus(ctx, status)

		case <-s.machineMailboxCh:
			if cause := context.Cause(ctx); controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
			s.drainMachineMailbox(ctx)

		case event := <-s.push.Events():
			if cause := context.Cause(ctx); controlerror.IsAuthoritativeStopCause(cause) {
				return s.stopForAuthorityDenial(cause)
			}
			s.handleWSEvent(ctx, event)
		}
	}
}

func (s *Service) initialSetup(ctx context.Context) error {
	// Register speed limit lookup with kernel unconditionally (before push/poll branch).
	s.kernel.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	s.kernel.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)

	bootstrap, err := s.source.Initial(ctx, s.wsMetrics, s.push.EventSink(), s.push.StatusSink())
	if err != nil {
		return err
	}

	if s.cfg.Node.PushInterval == 0 && bootstrap.PushInterval > 0 {
		s.pushInterval = bootstrap.PushInterval
	} else {
		s.pushInterval = s.cfg.Node.PushInterval
	}
	if s.pushInterval == 0 {
		s.pushInterval = 60
	}

	if s.cfg.Node.PullInterval == 0 && bootstrap.PullInterval > 0 {
		s.pullInterval = bootstrap.PullInterval
	} else {
		s.pullInterval = s.cfg.Node.PullInterval
	}
	if s.pullInterval == 0 {
		s.pullInterval = 60
	}

	if bootstrap.Push != nil {
		s.push.SetBootstrapClient(bootstrap.Push)
	}
	s.machineMailbox = bootstrap.Mailbox
	if s.machineMailbox != nil {
		s.machineMailboxCh = s.machineMailbox.NotifyCh()
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if bootstrap.Config == nil {
		if s.reporter.HasTerminalTail() {
			return fmt.Errorf("NATIVE_AUTHORITY_RECOVERY_CONFIG_REQUIRED")
		}
		if bootstrap.Push != nil {
			// In machine mode a shared WS client may be available before the first
			// per-node snapshot arrives. In that case we wait for subsequent WS/REST
			// updates instead of failing startup.
			return nil
		}
		return fmt.Errorf("initial config is nil")
	}
	if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), bootstrap.Config, s.certs.TLSCert()); err != nil {
		return err
	}

	if !s.cfg.UsageV2.Enabled && s.reporter.HasTerminalTail() {
		if err := s.reporter.ReplayRecovery(); err != nil {
			return fmt.Errorf("NATIVE_AUTHORITY_RECOVERY_FAILED: %w", err)
		}
	}

	if err := s.initUsageV2(ctx, bootstrap); err != nil {
		return err
	}
	s.metricsMu.Lock()
	s.lastConfig = bootstrap.Config
	s.lastConfigHash = computeConfigHash(bootstrap.Config)
	s.metricsMu.Unlock()
	s.updateUserState(bootstrap.Users, srcBootstrap)

	nlog.Core().Info("initial snapshot ready",
		"protocol", bootstrap.Config.Protocol,
		"port", bootstrap.Config.ServerPort,
		"users", len(bootstrap.Users),
	)

	if len(bootstrap.Users) == 0 {
		s.applyDesiredState(ctx)
		nlog.Core().Warn("no users, kernel will not start until users are available")
		s.markMailboxReadyAndDrain(ctx)
		return nil
	}

	s.applyRemoteOverrides(ctx, bootstrap.Config)
	if !s.startKernel(bootstrap.Config, bootstrap.Users) {
		s.markApplicationPending("KERNEL_START_FAILED")
		// Native complete snapshots will retry this desired state on the next poll.
		if s.cfg.Panel.Provider != "txboard" {
			return fmt.Errorf("start kernel")
		}
	}
	s.markMailboxReadyAndDrain(ctx)
	return nil
}

func (s *Service) markMailboxReadyAndDrain(ctx context.Context) {
	if s.machineMailbox == nil {
		return
	}
	// Seed mailbox with bootstrap state so delta events can be applied
	// incrementally instead of always triggering REST reconciliation.
	s.metricsMu.RLock()
	config := s.lastConfig
	s.metricsMu.RUnlock()
	users := s.users.Users()
	s.machineMailbox.SeedBaseline(users, config)
	s.machineMailbox.MarkReady()
	s.drainMachineMailbox(ctx)
}

func (s *Service) drainMachineMailbox(ctx context.Context) {
	if s.machineMailbox == nil {
		return
	}
	state := s.machineMailbox.DrainIfReady()
	if state.HasConfig {
		s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: state.Config})
	}
	if state.HasUsers {
		s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUsers, Users: state.Users})
	}
	if state.HasDevices {
		s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncDevices, DeviceUsers: state.DeviceUsers})
	}
	if state.NeedsReconcile {
		s.requestWSResync(ctx, "machine_mailbox_reconcile")
	}
}

func (s *Service) wsMetrics() map[string]interface{} {
	status := monitor.Collect()
	m := s.buildMetrics(status)
	m["kernel_status"] = s.kernel.IsRunning()
	return m
}

// handleWSEvent processes data events received via WebSocket
func (s *Service) handleWSEvent(ctx context.Context, event controlplane.Event) {
	if s.usageMode() {
		switch event.Type {
		case controlplane.EventSyncConfig:
			if event.Config != nil && computeConfigHash(event.Config) != s.lastConfigHash {
				s.failUsageV2()
				return
			}
		case controlplane.EventSyncUsers:
			if event.Users != nil && computeUserHash(event.Users) != s.users.Hash() {
				s.failUsageV2()
				return
			}
		case controlplane.EventSyncUserDelta:
			if len(event.DeltaUsers) > 0 {
				s.failUsageV2()
				return
			}
		}
	}
	if s.usageMode() {
		return
	}
	if s.authorityTerminal(ctx) {
		return
	}
	switch event.Type {
	case controlplane.EventSyncConfig:
		if event.Config == nil {
			return
		}
		if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), event.Config, s.certs.TLSCert()); err != nil {
			s.metricsMu.Lock()
			s.configRejected = true
			s.metricsMu.Unlock()
			s.markApplicationPending("CONFIG_VALIDATION_FAILED")
			return
		}
		s.desiredGeneration++
		s.acceptDesiredConfig(ctx, event.Config)
		s.applyDesiredState(ctx)
	case controlplane.EventSyncUsers:
		if event.Users == nil {
			return
		}
		s.desiredGeneration++
		s.applyUserUpdate(ctx, event.Users, computeUserHash(event.Users), srcWSFull)
	case controlplane.EventSyncUserDelta:
		if len(event.DeltaUsers) == 0 || (event.DeltaAction != "add" && event.DeltaAction != "remove") {
			return
		}
		s.desiredGeneration++
		s.applyUserDelta(ctx, event.DeltaAction, event.DeltaUsers)
	case controlplane.EventSyncDevices:
		if event.DeviceUsers != nil {
			s.kernel.UpdateGlobalDevices(event.DeviceUsers)
		}
	default:
		nlog.Core().Debug("unknown ws event", "type", event.Type)
	}
}

func (s *Service) trackAndEnforce(ctx context.Context) {
	if !s.kernel.IsRunning() {
		return
	}

	traffic, aliveIPs, connCount, err := s.kernel.GetUserTraffic(ctx)
	if err != nil {
		if s.usageMode() {
			s.failUsageV2()
			return
		}
		nlog.Core().Debug("get user traffic failed", "error", err)
		s.observeBoundary("TRACK_ERROR", false)
		return
	}

	if s.usageMode() {
		if !s.tracker.ProcessUsageV2Metrics(traffic, aliveIPs, connCount) {
			s.failUsageV2()
			return
		}
	} else {
		s.tracker.Process(traffic, aliveIPs, connCount)
	}
	// Pass the exact original cumulative snapshot after v1 has consumed it.
	// The observer neither polls meters again nor flushes/restores v1 state.
	s.observeTraffic(traffic)

	// Only log stats if there's actual traffic or connections
	if connCount > 0 || len(traffic) > 0 {
		if s.nodeLog != nil {
			s.nodeLog.Debug(fmt.Sprintf("tracker: %d conns, %d users online", connCount, len(traffic)))
		} else {
			nlog.TrackerStats(connCount, len(traffic))
		}
	}
}

// buildMetrics aggregates node-level metrics to be reported to the panel.
// This includes active connections, per-core CPU, GC stats, API call stats,
// WebSocket status, and limiter hit counts.
func (s *Service) buildMetrics(status monitor.Status) map[string]interface{} {
	totalUsers := 0
	if s.users != nil {
		totalUsers = s.users.Count()
	}

	m := make(map[string]interface{})
	if s.cfg != nil && s.cfg.UsageObserver.Enabled {
		m["usage_observer"] = s.usageObserverMetrics()
	}
	if s.cfg != nil && s.cfg.UsageEventStore.Enabled {
		m["usage_event_store"] = s.localEventMetrics()
	}
	online := s.tracker.CurrentOnline()

	m["uptime"] = status.Uptime
	m["goroutines"] = status.Goroutines

	// Active connections (last measured during tracker.Process()).
	m["active_connections"] = s.tracker.ActiveConnections()
	m["total_connections"] = s.tracker.TotalConnections()
	m["active_users"] = len(online)
	m["total_users"] = totalUsers
	s.metricsMu.RLock()
	desiredUsersHash := ""
	if s.users != nil {
		desiredUsersHash = s.users.Hash()
	}
	m["control_application"] = map[string]interface{}{
		"desired_config_hash": s.lastConfigHash, "applied_config_hash": s.appliedConfigHash,
		"desired_users_hash": desiredUsersHash, "applied_users_hash": s.appliedUserHash,
		"pending_retry": s.desiredDirty || s.pendingCertRenewal, "certificate_pending": s.pendingCertRenewal,
		"failure_code": s.applicationFailure, "configuration_applied": !s.configRejected && s.lastConfigHash != "" && s.lastConfigHash == s.appliedConfigHash,
		"users_applied": desiredUsersHash != "" && desiredUsersHash == s.appliedUserHash,
	}
	s.metricsMu.RUnlock()

	// Speed
	m["inbound_speed"] = s.tracker.InboundSpeed()
	m["outbound_speed"] = s.tracker.OutboundSpeed()

	// Per-core CPU usage (if available).
	if len(status.CPUPerCore) > 0 {
		m["cpu_per_core"] = status.CPUPerCore
	}

	m["load"] = map[string]interface{}{
		"load1":  status.Load1,
		"load5":  status.Load5,
		"load15": status.Load15,
	}

	// Speed Limiter metrics
	m["speed_limiter"] = map[string]interface{}{
		"has_limits":    s.speedTracker.HasLimits(),
		"limited_users": s.speedTracker.LimitedUserCount(),
	}

	// GC metrics.
	m["gc"] = map[string]interface{}{
		"num_gc":        status.NumGC,
		"last_pause_ms": status.LastPauseMS,
	}

	// API metrics.
	api := s.source.Metrics()
	m["api"] = map[string]interface{}{
		"success": api.Success,
		"failure": api.Failure,
	}

	// WebSocket/push status is owned by pushsync.Controller.
	wsEnabled, wsConnected := false, false
	if s.push != nil {
		wsEnabled, wsConnected = s.push.State()
	}
	m["ws"] = map[string]interface{}{
		"enabled":   wsEnabled,
		"connected": wsConnected,
	}

	// Limiter metrics.
	lm := s.limiter.SnapshotMetrics()
	m["limits"] = map[string]interface{}{
		"device_limit_events": lm.DeviceLimitEvents,
		"speed_limited_users": s.speedTracker.LimitedUserCount(),
	}

	return m
}

// ─── Device management ──────────────────────────────────────────────────

// sendDeviceBatch reports local device snapshot to panel via WS.
func (s *Service) sendDeviceBatch() {
	if s.push == nil {
		return
	}
	client := s.push.Client()
	if client == nil || !client.IsConnected() {
		return
	}

	devices := s.tracker.FlushAliveIPs()
	// FlushAliveIPs returns nil if no changes since last flush
	if devices == nil {
		nlog.Core().Debug("device snapshot unchanged, skipping")
		return
	}
	s.sink.ReportDevices(client, devices)
	nlog.Core().Debug("device snapshot sent", "users", len(devices))
}

// reportDevices periodically reports device snapshot to panel.
func (s *Service) reportDevices() {
	s.sendDeviceBatch()
}

// ─── Runtime validation ─────────────────────────────────────────────────

func validateNodeRuntime(cfg *config.Config, kcfgSupported []string, spec *model.NodeSpec, tls kernel.TLSCert) error {
	if spec == nil {
		return fmt.Errorf("node spec is nil")
	}
	if !containsString(kcfgSupported, spec.Protocol) {
		return fmt.Errorf("protocol %q is not supported by kernel %q", spec.Protocol, cfg.Kernel.Type)
	}
	if err := validateTLSRequirements(spec, tls, cfgKernelType(cfg)); err != nil {
		return err
	}
	if err := certcoord.ValidateNodeConfig(spec); err != nil {
		return err
	}
	return nil
}

func validateTLSRequirements(spec *model.NodeSpec, tls kernel.TLSCert, kernelType string) error {
	needsCert := false
	switch spec.Protocol {
	case "hysteria", "hysteria2", "tuic", "anytls":
		needsCert = true
	case "trojan":
		if spec.TLS != 2 {
			needsCert = true
		}
	}
	if needsCert && !hasUsableTLSConfig(spec, tls) {
		return fmt.Errorf("protocol %q requires TLS certificate files", spec.Protocol)
	}
	if spec.TLS == 2 {
		if err := validateRealityRequirements(spec, kernelType); err != nil {
			return err
		}
	}
	return nil
}

func hasUsableTLSConfig(spec *model.NodeSpec, tls kernel.TLSCert) bool {
	if tls.HasCert() {
		return true
	}
	if spec == nil || spec.CertConfig == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(spec.CertConfig.CertMode))
	switch mode {
	case "self":
		return true
	case "content":
		return strings.TrimSpace(spec.CertConfig.CertContent) != "" && strings.TrimSpace(spec.CertConfig.KeyContent) != ""
	case "file":
		return strings.TrimSpace(spec.CertConfig.CertFile) != "" && strings.TrimSpace(spec.CertConfig.KeyFile) != ""
	case "http":
		return strings.TrimSpace(spec.CertConfig.Domain) != ""
	case "dns":
		return strings.TrimSpace(spec.CertConfig.Domain) != "" && strings.TrimSpace(spec.CertConfig.DNSProvider) != ""
	default:
		return false
	}
}

func validateRealityRequirements(spec *model.NodeSpec, _ string) error {
	if spec.TLSSettings == nil {
		return fmt.Errorf("reality tls requires tls_settings")
	}
	privateKey := strings.TrimSpace(stringValue(spec.TLSSettings["private_key"]))
	serverName := strings.TrimSpace(stringValue(spec.TLSSettings["server_name"]))
	dest := strings.TrimSpace(stringValue(spec.TLSSettings["dest"]))
	if privateKey == "" {
		return fmt.Errorf("reality tls requires tls_settings.private_key")
	}
	if serverName == "" && dest == "" {
		return fmt.Errorf("reality tls requires tls_settings.server_name or tls_settings.dest")
	}
	return nil
}

func cfgKernelType(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(cfg.Kernel.Type))
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func stringValue(v any) string {
	switch value := v.(type) {
	case string:
		return value
	default:
		return ""
	}
}
