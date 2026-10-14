package service

import (
	"context"
	"errors"
	"github.com/ANRCM0/TX-Node/internal/certcoord"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/monitor"
	"github.com/ANRCM0/TX-Node/internal/nodesync"
	"github.com/ANRCM0/TX-Node/internal/pushsync"
	"github.com/ANRCM0/TX-Node/internal/tracker"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func snapshotTestService(k *fakeKernel) *Service {
	s := newTestService(k)
	s.cfg = &config.Config{Panel: config.PanelConfig{Provider: "txboard"}, Kernel: config.KernelConfig{Type: "singbox"}}
	return s
}
func TestIdenticalDesiredConfigRetriesAfterReloadAndStartFailure(t *testing.T) {
	k := &fakeKernel{}
	s := snapshotTestService(k)
	old := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	users := []model.UserSpec{{ID: 1, UUID: "first"}}
	s.lastConfig = old
	s.lastConfigHash = computeConfigHash(old)
	s.updateUserState(users, srcBootstrap)
	if !s.startKernel(old, users) {
		t.Fatal("initial")
	}
	applied := s.appliedConfigHash
	next := &model.NodeSpec{Protocol: "vless", ServerPort: 12346}
	k.reloadErr = errors.New("reload")
	k.startErr = errors.New("start")
	event := controlplane.Event{Type: controlplane.EventSyncConfig, Config: next}
	s.handleWSEvent(context.Background(), event)
	if k.running || s.appliedConfigHash != applied || s.lastConfigHash != computeConfigHash(next) || !s.desiredDirty {
		t.Fatal("failed config falsely applied or forgotten")
	}
	k.reloadErr = nil
	k.startErr = nil
	s.handleWSEvent(context.Background(), event)
	if !k.running || s.appliedConfigHash != computeConfigHash(next) || s.desiredDirty {
		t.Fatal("identical desired config not retried")
	}
	calls := k.startCalls + k.reloadCalls
	s.handleWSEvent(context.Background(), event)
	if k.startCalls+k.reloadCalls != calls {
		t.Fatal("duplicate applied config restarted")
	}
}
func TestInvalidConfigFailureSurvivesSuccessfulUserApplyAndClearsOnlyValidConfig(t *testing.T) {
	k := &fakeKernel{}
	s := snapshotTestService(k)
	cfg := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	users := []model.UserSpec{{ID: 1, UUID: "first"}}
	s.lastConfig = cfg
	s.lastConfigHash = computeConfigHash(cfg)
	s.updateUserState(users, srcBootstrap)
	s.startKernel(cfg, users)
	next := []model.UserSpec{{ID: 2, UUID: "second"}}
	s.applySyncResult(context.Background(), nodesync.Result{Config: &model.NodeSpec{Protocol: "unsupported"}, Users: next, UserHash: computeUserHash(next)})
	if s.applicationFailure != "CONFIG_VALIDATION_FAILED" || !s.desiredDirty || !s.configRejected || s.appliedUserHash != computeUserHash(next) {
		t.Fatal("successful users hid invalid config refusal")
	}
	s.tracker = tracker.New()
	s.source = noPollControlPlane{}
	metrics := s.buildMetrics(monitor.Status{})["control_application"].(map[string]interface{})
	if metrics["failure_code"] != "CONFIG_VALIDATION_FAILED" || metrics["pending_retry"] != true || metrics["configuration_applied"] != false || metrics["users_applied"] != true {
		t.Fatal("runtime metrics hid rejected configuration", metrics)
	}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: cfg})
	if s.applicationFailure != "" || s.desiredDirty || s.configRejected {
		t.Fatal("valid config did not reconcile rejected intent")
	}
}
func TestUserConfirmationCannotClearPendingConfigOrCertificate(t *testing.T) {
	s := snapshotTestService(&fakeKernel{})
	s.lastConfig = &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	s.appliedConfigHash = "old"
	s.pendingCertRenewal = true
	s.markApplicationPending("KERNEL_RELOAD_FAILED")
	s.confirmAppliedUsers([]model.UserSpec{{ID: 1, UUID: "first"}})
	if !s.desiredDirty || !s.pendingCertRenewal || s.applicationFailure != "KERNEL_RELOAD_FAILED" {
		t.Fatal("user mutation falsely confirmed pending config/certificate")
	}
}
func TestRealOccupiedListenerDesiredRetryAfterPortFreed(t *testing.T) {
	occupied, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := occupied.Addr().(*net.TCPAddr).Port
	p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
	s := authorityService(t, p)
	s.lastConfig = p.bootstrap.Config
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	s.updateUserState(p.bootstrap.Users, srcBootstrap)
	s.applyDesiredState(context.Background())
	if s.kernel.IsRunning() || s.appliedConfigHash != "" || !s.desiredDirty {
		occupied.Close()
		t.Fatal("occupied listener was marked applied")
	}
	occupied.Close()
	s.applySyncResult(context.Background(), nodesync.Result{Config: p.bootstrap.Config, ConfigHash: computeConfigHash(p.bootstrap.Config), Users: p.bootstrap.Users, UserHash: computeUserHash(p.bootstrap.Users)})
	defer s.kernel.Stop()
	if !s.kernel.IsRunning() || s.desiredDirty || s.appliedConfigHash != computeConfigHash(p.bootstrap.Config) {
		t.Fatal("same complete snapshot not retried after occupied port freed")
	}
	authorityWaitListener(t, port)
}

// This source blocks only the first read, reproducing an already-in-flight REST
// response captured before a later authoritative push.
type applicationPollSource struct {
	noPollControlPlane
	polls        atomic.Int32
	resets       atomic.Int32
	started      chan struct{}
	release      chan struct{}
	old, current controlplane.Snapshot
}

func (p *applicationPollSource) SupportsPolling() bool { return true }
func (p *applicationPollSource) ResetSnapshotCache()   { p.resets.Add(1) }
func (p *applicationPollSource) Poll(ctx context.Context) (controlplane.Snapshot, error) {
	if p.polls.Add(1) == 1 && p.release != nil {
		close(p.started)
		select {
		case <-p.release:
			return p.old, nil
		case <-ctx.Done():
			return controlplane.Snapshot{}, ctx.Err()
		}
	}
	return p.current, nil
}
func TestDelayedGenerationPollCannotRestoreNewerRemovedUser(t *testing.T) {
	k := &fakeKernel{}
	s := snapshotTestService(k)
	cfg := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	users := []model.UserSpec{{ID: 1, UUID: "revoked"}, {ID: 2, UUID: "kept"}}
	s.lastConfig = cfg
	s.lastConfigHash = computeConfigHash(cfg)
	s.updateUserState(users, srcBootstrap)
	s.startKernel(cfg, users)
	p := &applicationPollSource{started: make(chan struct{}), release: make(chan struct{}), old: controlplane.Snapshot{Config: cfg, Users: users}, current: controlplane.Snapshot{Config: cfg, Users: []model.UserSpec{{ID: 2, UUID: "kept"}}}}
	s.source = p
	s.syncer = nodesync.New(p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.schedulePoll(ctx)
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("poll did not capture old response")
	}
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	generation := s.desiredGeneration
	close(p.release)
	var old nodesync.Result
	select {
	case old = <-s.syncer.Results():
	case <-time.After(time.Second):
		t.Fatal("old result")
	}
	if !old.HasGeneration || old.Generation == generation {
		t.Fatal("inflight generation not captured")
	}
	s.applySyncResult(ctx, old)
	if got := s.users.Users(); len(got) != 1 || got[0].ID != 2 {
		t.Fatal("old response revived revoked user")
	}
	var current nodesync.Result
	select {
	case current = <-s.syncer.Results():
	case <-time.After(time.Second):
		t.Fatal("stale response did not trigger current reconciliation")
	}
	if current.Generation != generation || p.resets.Load() != 1 {
		t.Fatal("fresh reconciliation did not reset cache/capture current generation")
	}
	s.applySyncResult(ctx, current)
	if s.appliedUserHash != computeUserHash(p.current.Users) {
		t.Fatal("current response not confirmed")
	}
}
func TestReconnectForcesSnapshotCacheAndCapturesNewGeneration(t *testing.T) {
	s := snapshotTestService(&fakeKernel{})
	p := &applicationPollSource{current: controlplane.Snapshot{Users: []model.UserSpec{}}}
	s.source = p
	s.syncer = nodesync.New(p)
	s.push = pushsync.New(p)
	s.handlePushStatus(context.Background(), controlplane.StatusChange{Connected: true})
	select {
	case r := <-s.syncer.Results():
		if !r.HasGeneration || r.Generation != 1 || p.resets.Load() != 1 {
			t.Fatal("reconnect poll not fresh")
		}
	case <-time.After(time.Second):
		t.Fatal("reconnect poll missing")
	}
}
func TestTerminalGenerationDominatesEvenNewerQueuedUserAddition(t *testing.T) {
	k := &fakeKernel{}
	s := snapshotTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	s.updateUserState([]model.UserSpec{}, srcBootstrap)
	d := &controlerror.AuthorityDenial{Scope: controlerror.NodeScope, NodeID: 42, Code: "NODE_NOT_FOUND", HTTPStatus: 404}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(d)
	s.desiredGeneration = 3
	s.applySyncResult(ctx, nodesync.Result{Terminal: d, HasGeneration: true, Generation: 1})
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{{ID: 1, UUID: "stale"}}})
	if k.startCalls != 0 || s.users.Count() != 0 {
		t.Fatal("terminal denial superseded by late data")
	}
}

type applicationRenewalBackend struct {
	serviceCertBackend
	renew bool
}

func (b *applicationRenewalBackend) CertRenewed() bool {
	value := b.renew
	b.renew = false
	return value
}
func TestCertificateRenewalPersistsAcrossFailedPollAndKernelApply(t *testing.T) {
	k := &fakeKernel{}
	s := snapshotTestService(k)
	cfg := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	users := []model.UserSpec{{ID: 1, UUID: "first"}}
	s.lastConfig = cfg
	s.lastConfigHash = computeConfigHash(cfg)
	s.updateUserState(users, srcBootstrap)
	s.startKernel(cfg, users)
	backend := &applicationRenewalBackend{renew: true}
	s.certs = certcoord.NewWithBackend(backend)
	s.latchCertificateRenewal()
	s.latchCertificateRenewal()
	if !s.pendingCertRenewal {
		t.Fatal("one-shot renewal lost before application")
	}
	k.reloadErr = errors.New("reload")
	k.startErr = errors.New("start")
	s.applyDesiredState(context.Background())
	if !s.pendingCertRenewal || !s.desiredDirty || k.running {
		t.Fatal("failed renewal falsely applied")
	}
	k.reloadErr = nil
	k.startErr = nil
	s.applySyncResult(context.Background(), nodesync.Result{Config: cfg, Users: users, UserHash: computeUserHash(users)})
	if !k.running || s.pendingCertRenewal || s.desiredDirty {
		t.Fatal("renewal not retried/confirmed")
	}
}

type partialRemovalKernel struct {
	*fakeKernel
	removeError error
}

func (k *partialRemovalKernel) RemoveUsers(users []model.UserSpec) (int, error) {
	k.removeCalls++
	return 0, k.removeError
}
func TestUUIDReplacementRemovalErrorCannotSilentlyConfirmNewIdentity(t *testing.T) {
	base := &fakeKernel{}
	s := snapshotTestService(base)
	k := &partialRemovalKernel{fakeKernel: base}
	s.kernel = k
	s.kernelLife = kernellifecycle.New(k)
	cfg := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	old := []model.UserSpec{{ID: 1, UUID: "revoked-uuid"}, {ID: 2, UUID: "kept"}}
	s.lastConfig = cfg
	s.lastConfigHash = computeConfigHash(cfg)
	s.updateUserState(old, srcBootstrap)
	s.startKernel(cfg, old)
	originalApplied := s.appliedUserHash
	k.removeError = errors.New("partial removal")
	k.updateErr = errors.New("fallback update")
	k.startErr = errors.New("rebuild unavailable")
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 1, UUID: "current-uuid"}}})
	if k.removeCalls != 1 || k.addCalls != 0 || k.running || !s.desiredDirty || s.appliedUserHash != originalApplied {
		t.Fatal("failed UUID removal silently confirmed or left old listener running")
	}
	desired := []model.UserSpec{{ID: 1, UUID: "current-uuid"}, {ID: 2, UUID: "kept"}}
	if s.users.Hash() != computeUserHash(desired) {
		t.Fatal("current desired UUID lost after failure")
	}
	k.removeError = nil
	k.updateErr = nil
	k.startErr = nil
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: desired})
	if !k.running || s.desiredDirty || s.appliedUserHash != computeUserHash(desired) {
		t.Fatal("same authoritative UUID snapshot not retried")
	}
}
