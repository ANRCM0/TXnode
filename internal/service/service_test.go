package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/certcoord"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/limiter"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/userstate"
	"golang.org/x/time/rate"
)

type fakeKernel struct {
	running bool

	startErr  error
	reloadErr error
	updateErr error
	addErr    error

	startCalls        int
	reloadCalls       int
	updateCalls       int
	addCalls          int
	removeCalls       int
	clearDevicesCalls int

	onUpdateUsers func([]model.UserSpec)
	onAddUsers    func([]model.UserSpec)
	onRemoveUsers func([]model.UserSpec)

	speedLimitFunc  func(string) *rate.Limiter
	deviceLimitFunc func(string) (int, bool)
}

func (f *fakeKernel) Name() string                      { return "fake" }
func (f *fakeKernel) Protocols() []string               { return []string{"vless"} }
func (f *fakeKernel) Capabilities() kernel.Capabilities { return kernel.Capabilities{} }
func (f *fakeKernel) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	_, _, _ = nodeConfig, users, tls
	f.startCalls++
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	return nil
}
func (f *fakeKernel) Stop()           { f.running = false }
func (f *fakeKernel) IsRunning() bool { return f.running }
func (f *fakeKernel) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	_, _, _ = nodeConfig, users, tls
	f.reloadCalls++
	if f.reloadErr != nil {
		return f.reloadErr
	}
	f.running = true
	return nil
}
func (f *fakeKernel) AddUsers(users []model.UserSpec) (int, error) {
	f.addCalls++
	if f.onAddUsers != nil {
		f.onAddUsers(users)
	}
	if f.addErr != nil {
		return 0, f.addErr
	}
	return len(users), nil
}
func (f *fakeKernel) RemoveUsers(users []model.UserSpec) (int, error) {
	f.removeCalls++
	if f.onRemoveUsers != nil {
		f.onRemoveUsers(users)
	}
	return len(users), nil
}
func (f *fakeKernel) UpdateUsers(users []model.UserSpec) (int, int, error) {
	f.updateCalls++
	if f.onUpdateUsers != nil {
		f.onUpdateUsers(users)
	}
	if f.updateErr != nil {
		return 0, 0, f.updateErr
	}
	return len(users), 0, nil
}
func (f *fakeKernel) GetUserTraffic(ctx context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	_ = ctx
	return nil, nil, 0, nil
}
func (f *fakeKernel) CloseConnection(ctx context.Context, connID string) error {
	_, _ = ctx, connID
	return nil
}
func (f *fakeKernel) CloseUserConnections(ctx context.Context, uuid string) error {
	_, _ = ctx, uuid
	return nil
}
func (f *fakeKernel) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) { f.speedLimitFunc = fn }
func (f *fakeKernel) SetDeviceLimitFunc(fn func(uuid string) (int, bool))  { f.deviceLimitFunc = fn }
func (f *fakeKernel) UpdateGlobalDevices(users map[int][]string)           { _ = users }
func (f *fakeKernel) ClearGlobalDevices()                                  { f.clearDevicesCalls++ }

func newTestService(k *fakeKernel) *Service {
	sharedLimiter := limiter.New()
	speedTracker := limiter.NewSpeedTracker(sharedLimiter)
	s := &Service{
		kernel:       k,
		kernelLife:   kernellifecycle.New(k),
		limiter:      sharedLimiter,
		speedTracker: speedTracker,
		certs:        certcoord.New(config.CertConfig{}),
		users:        userstate.New(sharedLimiter, speedTracker),
	}
	k.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	k.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)
	return s
}

func TestApplyUserUpdatePreparesLimiterBeforeKernelUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.updateUserState(oldUsers, srcBootstrap)

	newUsers := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	k.onUpdateUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0].UUID != "uuid-new" {
			t.Fatalf("unexpected users passed to UpdateUsers: %#v", users)
		}
		if got := k.speedLimitFunc("uuid-new"); got == nil {
			t.Fatal("expected new user's limiter to be visible before kernel UpdateUsers")
		}
	}

	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers), srcWSFull)

	if got := k.updateCalls; got != 1 {
		t.Fatalf("UpdateUsers call count = %d, want 1", got)
	}
	if len(s.users.Users()) != 1 || s.users.Users()[0].UUID != "uuid-new" {
		t.Fatalf("lastUsers = %#v, want new users", s.users.Users())
	}
	if s.speedTracker.GetLimiter("uuid-new") == nil {
		t.Fatal("expected limiter for new user after successful update")
	}
}

func TestApplyUserUpdateRetainsRevocationAndStopsUncertainKernelWhenRestartFails(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.cfg = &config.Config{Panel: config.PanelConfig{Provider: "txboard"}, Kernel: config.KernelConfig{Type: "singbox"}}
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.updateUserState(oldUsers, srcBootstrap)
	if !s.startKernel(s.lastConfig, oldUsers) {
		t.Fatal("initial confirmed start failed")
	}
	oldApplied := s.appliedUserHash
	k.updateErr = errors.New("partial update failed")
	k.startErr = errors.New("restart failed")
	newUsers := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers), srcWSFull)
	if k.startCalls != 2 || k.running {
		t.Fatal("failed revocation kept uncertain kernel serving")
	}
	if len(s.users.Users()) != 1 || s.users.Users()[0].UUID != "uuid-new" || s.users.Hash() != computeUserHash(newUsers) {
		t.Fatal("pending desired revocation was forgotten")
	}
	if s.appliedUserHash != oldApplied || !s.desiredDirty {
		t.Fatal("failed mutation falsely recorded as applied")
	}
	if s.speedTracker.GetLimiter("uuid-old") != nil || s.speedTracker.GetLimiter("uuid-new") == nil {
		t.Fatal("pending desired limiter state rolled back")
	}
	k.updateErr = nil
	k.startErr = nil
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: newUsers})
	if !k.running || s.desiredDirty || s.appliedUserHash != computeUserHash(newUsers) {
		t.Fatal("identical pending revocation did not retry and apply")
	}
	if applied := s.kernelLife.Applied(); len(applied.Users) != 1 || applied.Users[0].ID != 2 {
		t.Fatal("successful retry did not update confirmed users")
	}
}

func TestApplyUserDeltaAddPreparesLimiterBeforeKernelUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.updateUserState(oldUsers, srcBootstrap)

	delta := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	k.onAddUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0].UUID != "uuid-new" {
			t.Fatalf("unexpected users passed to AddUsers: %#v", users)
		}
		if got := k.speedLimitFunc("uuid-new"); got == nil {
			t.Fatal("expected delta user's limiter to be visible before kernel AddUsers")
		}
	}

	s.applyUserDelta(context.Background(), "add", delta)

	if got := k.addCalls; got != 1 {
		t.Fatalf("AddUsers call count = %d, want 1", got)
	}
	if s.speedTracker.GetLimiter("uuid-new") == nil {
		t.Fatal("expected limiter for delta-added user after successful update")
	}
}

func TestApplyUserUpdateStartsKernelWhenFirstUserArrives(t *testing.T) {
	k := &fakeKernel{running: false}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.updateUserState([]model.UserSpec{}, srcBootstrap)

	users := []model.UserSpec{{ID: 1, UUID: "uuid-first", SpeedLimit: 8}}
	s.applyUserUpdate(context.Background(), users, computeUserHash(users), srcWSFull)

	if got := k.startCalls; got != 1 {
		t.Fatalf("Start call count = %d, want 1", got)
	}
	if got := k.updateCalls; got != 0 {
		t.Fatalf("UpdateUsers call count = %d, want 0 for initial kernel start", got)
	}
	if !k.running {
		t.Fatal("expected kernel to be running after first user arrives")
	}
	if len(s.users.Users()) != 1 || s.users.Users()[0].UUID != "uuid-first" {
		t.Fatalf("lastUsers = %#v, want first user", s.users.Users())
	}
	if s.speedTracker.GetLimiter("uuid-first") == nil {
		t.Fatal("expected limiter for first user before kernel start")
	}
}

func TestApplyUserDeltaStartsKernelWhenFirstUserArrives(t *testing.T) {
	k := &fakeKernel{running: false}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.updateUserState([]model.UserSpec{}, srcBootstrap)

	delta := []model.UserSpec{{ID: 1, UUID: "uuid-first", SpeedLimit: 8}}
	s.applyUserDelta(context.Background(), "add", delta)

	if got := k.startCalls; got != 1 {
		t.Fatalf("Start call count = %d, want 1", got)
	}
	if got := k.addCalls; got != 0 {
		t.Fatalf("AddUsers call count = %d, want 0 for initial kernel start", got)
	}
	if !k.running {
		t.Fatal("expected kernel to be running after first user delta")
	}
	if len(s.users.Users()) != 1 || s.users.Users()[0].UUID != "uuid-first" {
		t.Fatalf("lastUsers = %#v, want first user", s.users.Users())
	}
}

func TestApplyUserDeltaRemoveUpdatesStoppedServiceState(t *testing.T) {
	k := &fakeKernel{running: false}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	users := []model.UserSpec{{ID: 1, UUID: "uuid-old"}, {ID: 2, UUID: "uuid-keep"}}
	s.updateUserState(users, srcBootstrap)

	s.applyUserDelta(context.Background(), "remove", []model.UserSpec{{ID: 1}})

	if got := k.removeCalls; got != 0 {
		t.Fatalf("RemoveUsers call count = %d, want 0 while kernel is stopped", got)
	}
	if len(s.users.Users()) != 1 || s.users.Users()[0].ID != 2 {
		t.Fatalf("lastUsers = %#v, want only user 2", s.users.Users())
	}
}

func TestValidateNodeRuntimeRejectsUnsupportedDNSProvider(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"http"}, &model.NodeSpec{
		Protocol: "http",
		CertConfig: &config.CertConfig{
			CertMode:    "dns",
			DNSProvider: "3123123",
			Domain:      "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() == "" {
		t.Fatal("expected non-empty error")
	}
	if got := err.Error(); !strings.HasPrefix(got, `unsupported cert_config.dns_provider "3123123" (supported: `) {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeAllowsSelfManagedTLSBeforeFilesExist(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"anytls", "hysteria"}, &model.NodeSpec{
		Protocol: "anytls",
		CertConfig: &config.CertConfig{
			CertMode: "self",
			Domain:   "example.com",
		},
	}, kernel.TLSCert{})
	if err != nil {
		t.Fatalf("expected self-managed TLS config to pass validation, got %v", err)
	}
}

func TestValidateNodeRuntimeAllowsSingboxRealityWithRequiredFields(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": "test-key",
			"server_name": "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err != nil {
		t.Fatalf("expected sing-box reality validation to pass, got %v", err)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutTLSSettings(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutPrivateKey(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"server_name": "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings.private_key" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutServerNameOrDest(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": "test-key",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings.server_name or tls_settings.dest" {
		t.Fatalf("unexpected error: %v", got)
	}
}
