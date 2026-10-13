//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/kernel/singbox"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usageobserver"
	"github.com/sagernet/sing-box/adapter"
	singM "github.com/sagernet/sing/common/metadata"
)

type observedMeterKernel struct {
	fakeKernel
	meter      *singbox.ConnTracker
	reads      int
	trafficErr error
	started    chan struct{}
	startOnce  sync.Once
}

func (k *observedMeterKernel) Start(spec *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	err := k.fakeKernel.Start(spec, users, tls)
	if err == nil && k.started != nil {
		k.startOnce.Do(func() { close(k.started) })
	}
	return err
}

func (k *observedMeterKernel) GetUserTraffic(context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	k.reads++
	if k.trafficErr != nil {
		return nil, nil, 0, k.trafficErr
	}
	traffic, alive, count := k.meter.GetUserTraffic()
	return traffic, alive, count, nil
}
func (k *observedMeterKernel) UpdateUsers(users []model.UserSpec) (int, int, error) {
	added, removed, err := k.fakeKernel.UpdateUsers(users)
	if err == nil {
		mapping := map[string]int{}
		for _, user := range users {
			mapping[user.UUID] = user.ID
		}
		k.meter.SetUserMap(mapping)
	}
	return added, removed, err
}
func (k *observedMeterKernel) CloseUserConnections(_ context.Context, uuid string) error {
	k.meter.CloseByUUID(uuid)
	return nil
}

func observationRecords(t *testing.T, dir string) []usageobserver.Record {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var records []usageobserver.Record
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var e struct {
			Record usageobserver.Record `json:"record"`
		}
		if err := json.Unmarshal(data, &e); err != nil {
			t.Fatal(err)
		}
		records = append(records, e.Record)
	}
	return records
}
func observedService(t *testing.T, maxBytes int64) (*Service, *observedMeterKernel, *reportTestControlPlane) {
	t.Helper()
	cp := &reportTestControlPlane{}
	k := &observedMeterKernel{meter: singbox.NewConnTracker(0)}
	s := newReportingTestService(&k.fakeKernel, cp)
	s.kernel = k
	s.kernelLife = kernellifecycle.New(k)
	s.cfg = &config.Config{Kernel: config.KernelConfig{ConfigDir: t.TempDir()}, UsageObserver: config.UsageObserverConfig{Enabled: true, MaxBytes: maxBytes}, Panel: config.PanelConfig{Provider: "txboard", NodeID: 7, Token: "never-copy-this-token"}}
	s.lastConfig = &model.NodeSpec{Protocol: "vless", ServerPort: 23456}
	s.initUsageObserver()
	t.Cleanup(s.closeUsageObserver)
	return s, k, cp
}
func pipeTraffic(t *testing.T, k *observedMeterKernel, uuid string, up, down string) net.Conn {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
	_ = local.SetDeadline(time.Now().Add(3 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	tracked := k.meter.RoutedConnection(context.Background(), local, adapter.InboundContext{User: uuid, Source: singM.Socksaddr{Addr: netip.MustParseAddr("127.0.0.1")}}, nil, nil)
	t.Cleanup(func() { _ = tracked.Close() })
	result := make(chan error, 1)
	go func() { _, err := peer.Write([]byte(up)); result <- err }()
	buffer := make([]byte, len(up))
	if _, err := io.ReadFull(tracked, buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := tracked.Write([]byte(down)); result <- err }()
	buffer = make([]byte, len(down))
	if _, err := io.ReadFull(peer, buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	return tracked
}

func TestObserverConsumesRealMeterWithoutChangingLegacyTraffic(t *testing.T) {
	s, k, cp := observedService(t, 0)
	user := model.UserSpec{ID: 7, UUID: "private-runtime-uuid"}
	s.updateUserState([]model.UserSpec{user}, srcBootstrap)
	k.meter.SetUserMap(map[string]int{user.UUID: user.ID})
	if !s.startKernel(s.lastConfig, []model.UserSpec{user}) {
		t.Fatal("start failed")
	}
	conn := pipeTraffic(t, k, user.UUID, "upload", "download")
	s.trackAndEnforce(context.Background())
	s.trackAndEnforce(context.Background())
	if k.reads != 2 {
		t.Fatalf("observer drained meter separately: %d reads", k.reads)
	}
	if err := s.reloadKernelObserved(s.lastConfig, s.users.Users()); err != nil {
		t.Fatal(err)
	}
	s.applyUserUpdate(context.Background(), nil, "", srcWSFull)
	if _, err := conn.Write([]byte("closed")); err == nil {
		t.Fatal("removed runtime connection remained open")
	}
	s.trackAndEnforce(context.Background())
	s.pushReportSync()
	calls, payload := cp.snapshot()
	if calls != 1 || payload.Traffic[7] != [2]int64{6, 8} {
		t.Fatalf("v1 traffic changed: %d, %+v", calls, payload.Traffic)
	}
	s.stopKernelObserved(false)
	s.closeUsageObserver()
	records := observationRecords(t, s.usageObserverDirectory())
	events := map[string]bool{}
	for _, record := range records {
		events[record.Event] = true
		if record.Attribution != "unattributable" {
			t.Fatal("observer claimed billing attribution")
		}
		data, _ := json.Marshal(record)
		if strings.Contains(string(data), user.UUID) || strings.Contains(string(data), s.cfg.Panel.Token) || strings.Contains(string(data), "terms_id") {
			t.Fatal("runtime secret/ownership leaked into observation")
		}
		if record.Event == "TRACK" && (len(record.Counters) != 1 || record.Counters[0].Up != "6" || record.Counters[0].Down != "8") {
			t.Fatalf("raw meter changed: %+v", record)
		}
	}
	for _, event := range []string{"PROCESS_BEGIN", "KERNEL_START_BEGIN", "KERNEL_START_OK", "TRACK", "KERNEL_RELOAD_BEGIN", "KERNEL_RELOAD_OK", "USER_UPDATE_BEGIN", "USER_UPDATE_END", "KERNEL_STOP_BEGIN", "KERNEL_STOP_END", "PROCESS_END"} {
		if !events[event] {
			t.Fatalf("missing real Service consumer %s", event)
		}
	}
}

func TestObserverStorageFailurePreservesV1ReportAndDoesNotRetry(t *testing.T) {
	s, k, cp := observedService(t, 2048)
	user := model.UserSpec{ID: 7, UUID: "private-user"}
	k.meter.SetUserMap(map[string]int{user.UUID: 7})
	k.running = true
	pipeTraffic(t, k, user.UUID, "raw-upload", "raw-download")
	for i := 0; i < 8; i++ {
		s.trackAndEnforce(context.Background())
	}
	if s.usageObserverMetrics()["state"] != "capacity_reached" {
		t.Fatalf("failure not visible: %+v", s.usageObserverMetrics())
	}
	before := len(observationRecords(t, s.usageObserverDirectory()))
	s.trackAndEnforce(context.Background())
	if len(observationRecords(t, s.usageObserverDirectory())) != before {
		t.Fatal("failed observer resumed writing")
	}
	s.pushReportSync()
	calls, payload := cp.snapshot()
	if calls != 1 || payload.Traffic[7] != [2]int64{10, 12} {
		t.Fatalf("failed observation lost v1 bytes: %+v", payload.Traffic)
	}
	if k.reads != 9 {
		t.Fatal("v1 meter reads stopped")
	}
}

func TestObserverDisabledAndUnwritableStartupPreserveRuntime(t *testing.T) {
	s, k, _ := observedService(t, 0)
	s.closeUsageObserver()
	s.observer = nil
	s.observerState = ""
	s.cfg.UsageObserver.Enabled = false
	dir := filepath.Join(t.TempDir(), "must-not-exist")
	s.cfg.UsageObserver.Directory = dir
	s.initUsageObserver()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("disabled observer performed I/O")
	}
	s.cfg.UsageObserver.Enabled = true
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	s.cfg.UsageObserver.Directory = blocked
	s.initUsageObserver()
	if s.usageObserverMetrics()["state"] != "storage_unavailable" {
		t.Fatal("unwritable storage not reported")
	}
	if !s.startKernel(s.lastConfig, []model.UserSpec{{ID: 7, UUID: "user"}}) || !k.running {
		t.Fatal("observer I/O broke runtime")
	}
}

func TestObserverKernelFailureAndUserDeltaKeepBoundaryEvidence(t *testing.T) {
	s, k, _ := observedService(t, 0)
	k.running = true
	k.reloadErr = errors.New("kernel reload failure")
	if err := s.reloadKernelObserved(s.lastConfig, s.users.Users()); err == nil {
		t.Fatal("expected reload failure")
	}
	s.applyUserDelta(context.Background(), "add", []model.UserSpec{{ID: 7, UUID: "u"}})
	k.trafficErr = errors.New("meter unavailable")
	s.trackAndEnforce(context.Background())
	counts := map[string]int{}
	for _, r := range observationRecords(t, s.usageObserverDirectory()) {
		counts[r.Event]++
	}
	if counts["KERNEL_RELOAD_FAILED"] != 1 || counts["USER_DELTA_BEGIN"] != 1 || counts["USER_DELTA_END"] != 1 || counts["TRACK_ERROR"] != 1 {
		t.Fatalf("boundary evidence absent: %v", counts)
	}
	if k.reads != 1 {
		t.Fatal("lifecycle observation polled meter")
	}
}

func TestServiceObservationDirectorySeparatesRuntimeInstances(t *testing.T) {
	s, _, _ := observedService(t, 0)
	first := s.usageObserverDirectory()
	copyCfg := *s.cfg
	copyCfg.Panel.NodeID++
	other := &Service{cfg: &copyCfg}
	if first == other.usageObserverDirectory() {
		t.Fatal("node streams collide")
	}
	copyCfg = *s.cfg
	copyCfg.InstanceID = "other-instance"
	if first == other.usageObserverDirectory() {
		t.Fatal("instance streams collide")
	}
}

// This runs the production Service.Run loop and original kernel interface over
// the actual sing-box connection meter. The lifecycle harness avoids opening a
// proxy listener; local net.Pipe I/O is counted by the production collector.
func TestServiceRunObserverCapturesActualConnTrackerAndShutdown(t *testing.T) {
	cfg := &config.Config{InstanceID: "local-runtime", Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, DeviceReportInterval: 60, PushInterval: 60, PullInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}, UsageObserver: config.UsageObserverConfig{Enabled: true}, Standalone: &config.StandaloneConfig{Enabled: true, Node: config.StandaloneNodeConfig{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: 23456}, Users: []config.StandaloneUser{{ID: 7, UUID: "00112233-4455-6677-8899-aabbccddeeff"}}}}
	s := NewWithControlPlane(cfg, controlplane.NewLocalControlPlane(cfg))
	k := &observedMeterKernel{meter: singbox.NewConnTracker(0), started: make(chan struct{})}
	k.meter.SetUserMap(map[string]int{cfg.Standalone.Users[0].UUID: 7})
	s.kernel = k
	s.kernelLife = kernellifecycle.New(k)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	completed := false
	t.Cleanup(func() {
		cancel()
		if !completed {
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Error("Service.Run did not terminate")
			}
		}
	})
	select {
	case <-k.started:
	case err := <-done:
		completed = true
		t.Fatalf("Service failed to start: %v", err)
	case <-time.After(4 * time.Second):
		t.Fatal("Service did not start")
	}
	conn := pipeTraffic(t, k, cfg.Standalone.Users[0].UUID, "original-upload", "original-download")
	deadline := time.Now().Add(4 * time.Second)
	sampled := false
	for time.Now().Before(deadline) {
		for _, r := range observationRecords(t, s.usageObserverDirectory()) {
			if r.Event == "TRACK" && len(r.Counters) > 0 {
				sampled = true
			}
		}
		if sampled {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sampled {
		t.Fatal("production track ticker did not feed observer")
	}
	_ = conn.Close()
	cancel()
	select {
	case err := <-done:
		completed = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Service shutdown timed out")
	}
	records := observationRecords(t, s.usageObserverDirectory())
	if records[len(records)-1].Event != "PROCESS_END" {
		t.Fatal("Run shutdown did not close observer")
	}
	var raw []usageobserver.Counter
	for _, r := range records {
		if r.Event == "TRACK" {
			raw = r.Counters
		}
	}
	if len(raw) != 1 || raw[0].UserID != "7" || raw[0].Up != "15" || raw[0].Down != "17" {
		t.Fatalf("real collector counters: %+v", raw)
	}
	if k.IsRunning() {
		t.Fatal("Run did not stop kernel")
	}
	if pending := s.tracker.FlushTraffic(); pending[7] != [2]int64{15, 17} {
		t.Fatalf("standalone observer lost legacy tracker bytes: %+v", pending)
	}
}
