package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel/singbox"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

var errNativeUsage = errors.New("NATIVE_USAGE_SESSION_STOPPED")

type nativeUsageKernel interface {
	SetNativeUsageTracker(*singbox.ConnTracker) bool
}

type nativeUsageRuntime struct {
	store           *usageinterval.NativeStore
	spool           *usagev2.Spool
	reporter        *usagev2.Reporter
	active          atomic.Pointer[singbox.ConnTracker]
	collector       atomic.Pointer[usageinterval.NativeCollector]
	failure         chan error
	stop            sync.Once
	failed          atomic.Bool
	cancel          context.CancelFunc
	done            chan struct{}
	workerStarted   bool
	admissionMu     sync.Mutex
	session         usagev2.Session
	revision        string
	blockedRevision string
	refresh         chan struct{}
	refreshNeeded   atomic.Bool
}

func (s *Service) nativeUsageConfigured() bool {
	return s != nil && s.cfg != nil && s.cfg.UsageV2.Enabled && s.cfg.Authorization.Enabled &&
		s.cfg.Authorization.PolicyVersion == config.NativeProviderUsagePolicyVersion
}
func (s *Service) nativeUsageMode() bool { return s != nil && s.nativeUsage != nil }

func nativeUsageConfig(node *model.NodeSpec) error {
	if node == nil || (node.Protocol != "vless" && node.Protocol != "vmess") ||
		node.Network != "" && node.Network != "tcp" || node.Multiplex != nil && node.Multiplex.Enabled {
		return errors.New("NATIVE_USAGE_DIRECT_TCP_REQUIRED")
	}
	return nil
}

func (s *Service) initNativeUsage(ctx context.Context, bootstrap controlplane.Bootstrap) error {
	snapshot := s.authorization.Current()
	if snapshot == nil || snapshot.Payload.PolicyVersion != config.NativeProviderUsagePolicyVersion || snapshot.Payload.UsageV2 == nil ||
		bootstrap.UsageV2Transport == nil || !bootstrap.UsageV2NativeHTTP || nativeUsageConfig(bootstrap.Config) != nil ||
		s.kernel.IsRunning() || s.tracker == nil || !s.tracker.EmptyForUsageHandoff() || !s.reporter.EmptyForUsageHandoff() ||
		usagev2.CheckHandoff(s.legacyPendingPath, true) != nil {
		return errNativeUsage
	}
	if _, ok := s.kernel.(nativeUsageKernel); !ok {
		return errNativeUsage
	}
	traffic, alive, count, err := s.kernel.GetUserTraffic(ctx)
	if err != nil || len(alive) != 0 || count != 0 {
		return errNativeUsage
	}
	for _, counters := range traffic {
		if counters[0] != 0 || counters[1] != 0 {
			return errNativeUsage
		}
	}
	directory := filepath.Join(s.cfg.UsageV2.Directory, fmt.Sprintf("node-%d", s.cfg.Panel.NodeID))
	spool, err := usagev2.OpenSpool(filepath.Join(directory, "spool"), s.cfg.UsageV2.MaxBytes)
	if err != nil {
		return errNativeUsage
	}
	store, err := usageinterval.OpenNativeStore(filepath.Join(directory, "native"), *snapshot.Payload.UsageV2, spool)
	if err != nil {
		spool.Close()
		return errNativeUsage
	}
	reporter, err := usagev2.NewReporter(*snapshot.Payload.UsageV2, spool, bootstrap.UsageV2Transport)
	if err != nil {
		store.Close()
		spool.Close()
		return errNativeUsage
	}
	runtime := &nativeUsageRuntime{store: store, spool: spool, reporter: reporter,
		failure: make(chan error, 1), refresh: make(chan struct{}, 1), done: make(chan struct{})}
	s.nativeUsage = runtime
	if err := s.installNativeCollector(ctx, snapshot); err != nil {
		store.Close()
		reporter.Close()
		s.nativeUsage = nil
		return err
	}
	return nil
}

func (s *Service) installNativeCollector(ctx context.Context, snapshot *authorization.Snapshot) error {
	if snapshot == nil || snapshot.Payload.UsageV2 == nil || s.nativeUsage.failed.Load() {
		return errNativeUsage
	}
	users := make(map[string]int, len(snapshot.Users))
	for _, user := range snapshot.Users {
		users[user.UUID] = user.ID
	}
	collector, err := s.nativeUsage.store.NewCollector(*snapshot.Payload.UsageV2,
		usageinterval.NativeWindow{Revision: snapshot.Payload.Revision, Digest: snapshot.Digest,
			IssuedAt: snapshot.Payload.IssuedAt, ExpiresAt: snapshot.Payload.ExpiresAt}, users)
	if err != nil {
		return errNativeUsage
	}
	if wait := time.Until(collector.ReadyAt()); wait > 0 {
		if wait > 30*time.Second {
			collector.Fail()
			return errNativeUsage
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			collector.Fail()
			return ctx.Err()
		case <-timer.C:
		}
	}
	tracker := singbox.NewNativeUsageTracker(collector, users)
	s.nativeUsage.admissionMu.Lock()
	defer s.nativeUsage.admissionMu.Unlock()
	if blocked := s.nativeUsage.blockedRevision; blocked != "" &&
		(len(snapshot.Payload.Revision) < len(blocked) ||
			len(snapshot.Payload.Revision) == len(blocked) && strings.Compare(snapshot.Payload.Revision, blocked) <= 0) {
		collector.Fail()
		return errNativeUsage
	}
	if !tracker.EnableEnforcingBounded() || !s.kernel.(nativeUsageKernel).SetNativeUsageTracker(tracker) {
		collector.Fail()
		return errNativeUsage
	}
	s.nativeUsage.collector.Store(collector)
	s.nativeUsage.active.Store(tracker)
	s.nativeUsage.session = *snapshot.Payload.UsageV2
	s.nativeUsage.session.Grants = append([]usagev2.Grant{}, snapshot.Payload.UsageV2.Grants...)
	s.nativeUsage.revision = snapshot.Payload.Revision
	s.nativeUsage.refreshNeeded.Store(false)
	if s.nativeUsage.failed.Load() {
		tracker.StopBoundedUsageTraffic()
		return errNativeUsage
	}
	return nil
}

func (s *Service) nativeUsageRefreshChannel() <-chan struct{} {
	if !s.nativeUsageMode() {
		return nil
	}
	return s.nativeUsage.refresh
}

func (s *Service) quarantineNativeUsage(record usagev2.Record) {
	runtime := s.nativeUsage
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	current := runtime.session
	if current.CoreInstanceID != record.Session.CoreInstanceID || current.NodeID != record.Session.NodeID ||
		current.SourceEpoch != record.Session.SourceEpoch {
		return
	}
	affected := false
	for _, entry := range record.Submission.Payload.Entries {
		for _, grant := range current.Grants {
			if entry.AuthSnapshotID == grant.AuthSnapshotID {
				affected = true
			}
		}
	}
	if !affected {
		return
	}
	// This authenticated rejection concerns current admission. Stop it before
	// requesting replacement authority; unrelated history cannot stop a new grant.
	runtime.blockedRevision = runtime.revision
	runtime.refreshNeeded.Store(true)
	if tracker := runtime.active.Load(); tracker != nil {
		tracker.StopBoundedUsageTraffic()
	}
	select {
	case runtime.refresh <- struct{}{}:
	default:
	}
}

func (s *Service) stopNativeUsageIO() {
	if !s.nativeUsageMode() {
		return
	}
	if tracker := s.nativeUsage.active.Load(); tracker != nil {
		tracker.StopBoundedUsageTraffic()
	}
}

func (s *Service) drainNativeUsage(ctx context.Context) error {
	s.stopNativeUsageIO()
	s.stopKernelObserved(false)
	if collector := s.nativeUsage.collector.Load(); collector != nil {
		drain, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if collector.Drain(drain) != nil {
			return errNativeUsage
		}
	}
	return nil
}

func (s *Service) applyNativeAuthorization(ctx context.Context, result controlplane.Snapshot, certChanged bool) error {
	verified, err := s.authorization.VerifyCandidate(result.Authorization, time.Now())
	if err != nil {
		return err
	}
	if verified.Payload.PolicyVersion != config.NativeProviderUsagePolicyVersion || verified.Payload.UsageV2 == nil ||
		result.Users == nil || computeUserHash(result.Users) != computeUserHash(model.UserSpecsFromPanel(verified.Users)) {
		return errNativeUsage
	}
	node := result.Config
	if node == nil {
		node = s.lastConfig
	}
	if err := nativeUsageConfig(node); err != nil {
		return err
	}
	if err := authorization.ValidateProtocol(verified, node.Protocol); err != nil {
		return err
	}
	if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), node, s.certs.TLSCert()); err != nil {
		return errNativeUsage
	}
	current := s.authorization.Current()
	if current != nil && current.Digest == verified.Digest {
		if certChanged || computeConfigHash(node) != s.lastConfigHash {
			return errNativeUsage
		}
		return nil
	}
	if err := s.drainNativeUsage(ctx); err != nil {
		return err
	}
	if err := s.acceptAuthorization(verified, result.Users, node); err != nil {
		return err
	}
	// The private envelope has been reverified again after draining old I/O.
	accepted := s.authorization.Current()
	if err := s.installNativeCollector(ctx, accepted); err != nil {
		return err
	}
	s.acceptDesiredConfig(ctx, node)
	s.updateUserState(result.Users, srcPollFull)
	if certChanged {
		s.pendingCertRenewal = true
	}
	if len(result.Users) == 0 {
		s.confirmAppliedUsers(result.Users)
		return nil
	}
	if !s.startKernel(node, result.Users) {
		s.stopNativeUsageIO()
		return errNativeUsage
	}
	return nil
}

func (s *Service) failNativeUsage() {
	if !s.nativeUsageMode() {
		return
	}
	s.nativeUsage.failed.Store(true)
	s.stopNativeUsageIO()
	s.nativeUsage.stop.Do(func() {
		select {
		case s.nativeUsage.failure <- errNativeUsage:
		default:
		}
	})
}

func retryableUsageError(err error) bool {
	var httpError *usagev2.HTTPError
	return errors.Is(err, usagev2.ErrTransportUnavailable) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) || errors.As(err, &httpError) && httpError.Status >= 500
}

func (s *Service) startNativeUsageWorker() {
	runtime := s.nativeUsage
	ctx, cancel := context.WithCancel(context.Background())
	runtime.cancel, runtime.workerStarted = cancel, true
	go func() {
		defer close(runtime.done)
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		lastPrune := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			if collector := runtime.collector.Load(); collector != nil {
				if _, err := collector.Flush(); err != nil && err != usageinterval.ErrPending {
					s.failNativeUsage()
					return
				}
			}
			delivery, stop := context.WithTimeout(ctx, 2*time.Second)
			err := runtime.reporter.DeliverNativePage(delivery, 16, s.quarantineNativeUsage)
			stop()
			if err != nil && !retryableUsageError(err) {
				s.failNativeUsage()
				return
			}
			if time.Since(lastPrune) >= time.Minute {
				if runtime.spool.PruneSettled(time.Now().Unix()) != nil {
					s.failNativeUsage()
					return
				}
				lastPrune = time.Now()
			}
		}
	}()
}

func (s *Service) closeNativeUsage() {
	runtime := s.nativeUsage
	s.stopNativeUsageIO()
	if runtime.workerStarted {
		runtime.cancel()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-runtime.done:
		case <-timer.C:
			return
		}
	}
	if collector := runtime.collector.Load(); collector != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = collector.Drain(ctx)
		cancel()
	}
	final, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = runtime.reporter.DeliverNativePage(final, 16, s.quarantineNativeUsage)
	cancel()
	_ = runtime.store.Close()
	_ = runtime.reporter.Close()
}
