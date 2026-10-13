package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/kernel/singbox"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Actual Service.Run owns reporting/lifecycle. This injected kernel harness
// uses the production enforcing ConnTracker and memory TCP, no proxy listener.
type usageModeKernel struct {
	fakeKernel
	mu             sync.Mutex
	meter          *singbox.ConnTracker
	started        chan struct{}
	running        bool
	starts         int
	initialBytes   bool
	initialRunning bool
}

func (k *usageModeKernel) Protocols() []string { return []string{"vless", "vmess"} }
func (k *usageModeKernel) SetBoundedUsageTracker(m *singbox.ConnTracker) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.meter != nil {
		return false
	}
	k.meter = m
	return true
}
func (k *usageModeKernel) Start(*model.NodeSpec, []model.UserSpec, kernel.TLSCert) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.meter == nil {
		return errors.New("missing actual bounded tracker")
	}
	k.running = true
	k.starts++
	close(k.started)
	return nil
}
func (k *usageModeKernel) Stop() {
	k.mu.Lock()
	k.running = false
	meter := k.meter
	k.mu.Unlock()
	if meter != nil {
		meter.StopBoundedUsageTraffic()
	}
}
func (k *usageModeKernel) IsRunning() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.running || k.initialRunning
}
func (k *usageModeKernel) GetUserTraffic(context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	k.mu.Lock()
	meter := k.meter
	initial := k.initialBytes
	k.mu.Unlock()
	if meter == nil {
		if initial {
			return map[int][2]int64{7: {1, 0}}, nil, 0, nil
		}
		return nil, nil, 0, nil
	}
	traffic, alive, count := meter.GetUserTraffic()
	return traffic, alive, count, nil
}
func (k *usageModeKernel) FlushBoundedUsage() (*usagev2.Submission, error) {
	k.mu.Lock()
	meter := k.meter
	k.mu.Unlock()
	return meter.FlushBoundedUsage()
}
func (k *usageModeKernel) CheckBoundedUsage() error {
	k.mu.Lock()
	meter := k.meter
	k.mu.Unlock()
	return meter.CheckBoundedUsage()
}
func (k *usageModeKernel) StopBoundedUsageTraffic() {
	k.mu.Lock()
	meter := k.meter
	k.mu.Unlock()
	if meter != nil {
		meter.StopBoundedUsageTraffic()
	}
}
func (k *usageModeKernel) tracker() *singbox.ConnTracker {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.meter
}

type modeTransport struct {
	mu           sync.Mutex
	session      usagev2.Session
	receipts     map[string]usagev2.Receipt
	submissions  []usagev2.Submission
	err          bool
	blockEntered chan struct{}
	blockRelease chan struct{}
	blockOnce    sync.Once
}

func (f *modeTransport) Get(ctx context.Context, q usagev2.Query) (usagev2.Receipt, bool, error) {
	f.mu.Lock()
	fault, entered, release := f.err, f.blockEntered, f.blockRelease
	r, ok := f.receipts[q.BatchID]
	f.mu.Unlock()
	if entered != nil {
		f.blockOnce.Do(func() { close(entered) })
		<-release
	}
	if ctx.Err() != nil {
		return usagev2.Receipt{}, false, ctx.Err()
	}
	if fault {
		return usagev2.Receipt{}, false, errors.New("synthetic transport failure")
	}
	return r, ok, nil
}
func (f *modeTransport) Submit(_ context.Context, s usagev2.Submission) (usagev2.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := usagev2.Receipt{ProtocolVersion: 2, CoreInstanceID: f.session.CoreInstanceID, ReceiptGeneration: f.session.ReceiptGeneration, NodeID: s.Payload.NodeID, SourceEpoch: s.Payload.SourceEpoch, BatchID: s.Payload.BatchID, PayloadDigest: s.PayloadDigest, ReceiptStatus: "persisted", SettlementStatus: "pending", AcceptedAt: s.Payload.EndedAt, ReceiptID: "service-synthetic-receipt"}
	f.receipts[s.Payload.BatchID] = r
	f.submissions = append(f.submissions, s)
	return r, nil
}
func (f *modeTransport) snapshot() []usagev2.Submission {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]usagev2.Submission{}, f.submissions...)
}

type usageModeSource struct {
	reportTestControlPlane
	bootstrap    controlplane.Bootstrap
	prepareCalls int
	badSetup     bool
}

func (p *usageModeSource) PrepareIsolatedUsageV2(string) error {
	p.prepareCalls++
	if p.badSetup {
		return errors.New("synthetic trust failure")
	}
	return nil
}
func (p *usageModeSource) Initial(context.Context, func() map[string]interface{}, chan<- controlplane.Event, chan<- controlplane.StatusChange) (controlplane.Bootstrap, error) {
	return p.bootstrap, nil
}

func modeFixture(t *testing.T, lease time.Duration) (*Service, *usageModeKernel, *usageModeSource, *modeTransport) {
	t.Helper()
	now := time.Now().Unix()
	session := usagev2.Session{ProtocolVersion: 2, CoreInstanceID: "service-core-fixture", NodeID: "1", SourceEpoch: "1", ReceiptGeneration: "1", RetentionSeconds: 86400, MaxLateReportSeconds: 3600, ReceiptRetentionSeconds: 86400, IssuedAt: now, Grants: []usagev2.Grant{{UserID: "7", AccessSubjectID: "8", AuthSnapshotID: "9", TariffRevisionID: "10", TermsID: "11", UsagePeriodID: "12", IssuedAt: now - 2, LeaseExpiresAt: now + int64(lease/time.Second), RevocationVersion: "0"}}}
	transport := &modeTransport{session: session, receipts: map[string]usagev2.Receipt{}}
	source := &usageModeSource{bootstrap: controlplane.Bootstrap{Config: &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: 23456}, Users: []model.UserSpec{{ID: 7, UUID: "00112233-4455-6677-8899-aabbccddeeff"}}, UsageV2Session: &session, UsageV2Transport: transport, UsageV2NativeHTTP: true}}
	cfg := &config.Config{InstanceID: "usage-service-fixture", Panel: config.PanelConfig{Provider: "txboard", URL: "https://127.0.0.1:18499", NodeID: 1, Token: "synthetic-test-only"}, Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, PushInterval: 5, PullInterval: 60, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}, UsageV2: config.UsageV2Config{Enabled: true, IsolatedCopy: true, Directory: t.TempDir()}}
	service := NewWithControlPlane(cfg, source)
	service.usageOwner = &usagebucket.ProcessOwner{}
	k := &usageModeKernel{started: make(chan struct{})}
	service.kernel = k
	service.kernelLife = kernellifecycle.New(k)
	return service, k, source, transport
}
func startMode(t *testing.T, s *Service, k *usageModeKernel) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case <-k.started:
	case err := <-done:
		cancel()
		t.Fatalf("mode did not start: %v", err)
	case <-time.After(4 * time.Second):
		cancel()
		t.Fatal("mode startup timed out")
	}
	t.Cleanup(cancel)
	return cancel, done
}
func modeTCP(t *testing.T, k *usageModeKernel) (net.Conn, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	local.SetDeadline(time.Now().Add(5 * time.Second))
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	conn := k.tracker().RoutedConnection(context.Background(), local, adapter.InboundContext{User: "00112233-4455-6677-8899-aabbccddeeff", Source: M.Socksaddr{Addr: netip.MustParseAddr("127.0.0.1")}}, nil, nil)
	t.Cleanup(func() { conn.Close(); peer.Close() })
	return conn, peer
}
func ioMode(t *testing.T, k *usageModeKernel) (net.Conn, net.Conn) {
	t.Helper()
	conn, peer := modeTCP(t, k)
	done := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("upload-11!!")); done <- err }()
	if _, err := io.ReadFull(conn, make([]byte, 11)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := io.ReadFull(peer, make([]byte, 7)); done <- err }()
	if err := bufio.NewExtendedWriter(conn).WriteBuffer(buf.As([]byte("down-07"))); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return conn, peer
}
func waitMode(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("mode condition timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func finishMode(t *testing.T, done <-chan error, expected bool) {
	t.Helper()
	select {
	case err := <-done:
		if expected && err == nil || !expected && err != nil {
			t.Fatalf("unexpected exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mode shutdown timed out")
	}
}

func TestServiceRunUsageV2ActualTrackerWorkerSpoolAndNoV1DoubleReport(t *testing.T) {
	s, k, source, transport := modeFixture(t, 30*time.Second)
	cancel, done := startMode(t, s, k)
	connection, _ := ioMode(t, k)
	waitMode(t, func() bool { return len(transport.snapshot()) == 1 })
	submitted := transport.snapshot()[0]
	if submitted.Payload.Entries[0].RawUpBytes != "11" || submitted.Payload.Entries[0].RawDownBytes != "7" {
		t.Fatal("actual Service producer physical bytes changed")
	}
	connection.Close()
	cancel()
	finishMode(t, done, false)
	calls, payload := source.snapshot()
	if calls == 0 || len(payload.Traffic) != 0 {
		t.Fatal("v2 Service sent same bytes to v1 Traffic")
	}
	if s.tracker.HasTraffic() || k.IsRunning() {
		t.Fatal("second billing queue or running kernel survived shutdown")
	}
	spool, err := usagev2.OpenSpool(filepath.Join(s.cfg.UsageV2.Directory, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	records, err := spool.Records()
	if err != nil || len(records) != 1 || records[0].Receipt == nil || records[0].Submission.PayloadDigest != submitted.PayloadDigest {
		t.Fatal("Service shutdown discarded original payload/receipt")
	}
}
func TestServiceUsageV2HandoffRefusesRealLegacyStateWithoutDraining(t *testing.T) {
	for _, kind := range []string{"pending_file", "pending_ram", "tracker_pending", "kernel_bytes", "kernel_running", "missing_capability", "wrong_mode", "invalid_setup", "unsupported_kernel"} {
		t.Run(kind, func(t *testing.T) {
			s, k, source, _ := modeFixture(t, 30*time.Second)
			var before []byte
			switch kind {
			case "pending_file":
				before = []byte("unknown v1 durable payload must be retained")
				if err := os.WriteFile(s.legacyPendingPath, before, 0600); err != nil {
					t.Fatal(err)
				}
			case "pending_ram":
				s.reporter.PushAsync(func() reporting.Batch {
					return reporting.Batch{Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{7: {1, 2}}}}
				}, nil, nil)
				waitMode(t, func() bool { calls, _ := source.snapshot(); return calls > 0 })
			case "tracker_pending":
				s.tracker.RestoreTraffic(map[int][2]int64{7: {3, 4}})
			case "kernel_bytes":
				k.initialBytes = true
			case "kernel_running":
				k.initialRunning = true
			case "missing_capability":
				source.bootstrap.UsageV2Session = nil
			case "wrong_mode":
				source.bootstrap.UsageV2NativeHTTP = false
			case "invalid_setup":
				source.badSetup = true
			case "unsupported_kernel":
				s.kernel = &fakeKernel{}
				s.kernelLife = kernellifecycle.New(s.kernel)
			}
			if kind == "pending_ram" {
				source.mu.Lock()
				source.err = errors.New("retain pending batch")
				source.mu.Unlock()
				s.reporter.PushSync(func() reporting.Batch {
					return reporting.Batch{Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{7: {1, 2}}}}
				})
			}
			if err := s.Run(context.Background()); err == nil {
				t.Fatal("handoff accepted uncertain legacy state")
			}
			if before != nil {
				after, err := os.ReadFile(s.legacyPendingPath)
				if err != nil || string(after) != string(before) {
					t.Fatal("pending handoff file was drained/deleted")
				}
			}
			if kind == "tracker_pending" && s.tracker.FlushTraffic()[7] != ([2]int64{3, 4}) {
				t.Fatal("v1 RAM counters lost")
			}
			if k.starts != 0 {
				t.Fatal("listener started before handoff")
			}
		})
	}
}
func TestServiceUsageV2ExpiryUnknownUDPAndUpdatesStopModeWithoutBillingFallback(t *testing.T) {
	for _, kind := range []string{"expiry", "udp", "user_change", "config_change", "transport_failure"} {
		t.Run(kind, func(t *testing.T) {
			lease := 30 * time.Second
			if kind == "expiry" {
				lease = 2 * time.Second
			}
			s, k, source, transport := modeFixture(t, lease)
			cancel, done := startMode(t, s, k)
			defer cancel()
			conn, peer := modeTCP(t, k)
			switch kind {
			case "udp":
				k.tracker().RoutedPacketConnection(context.Background(), &modeRejectPacket{}, adapter.InboundContext{User: "00112233-4455-6677-8899-aabbccddeeff", Source: M.Socksaddr{Addr: netip.MustParseAddr("127.0.0.1")}}, nil, nil)
			case "user_change":
				s.push.EventSink() <- controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{{ID: 7, UUID: "rebound-identity"}}}
			case "config_change":
				s.push.EventSink() <- controlplane.Event{Type: controlplane.EventSyncConfig, Config: &model.NodeSpec{Protocol: "vless", ServerPort: 23457}}
			case "transport_failure":
				transport.mu.Lock()
				transport.err = true
				transport.mu.Unlock()
				ioMode(t, k)
			}
			finishMode(t, done, true)
			if k.IsRunning() {
				t.Fatal("mode traffic still running")
			}
			peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if n, err := peer.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatal("active connection not closed")
			}
			if n, err := conn.Write([]byte("refuse")); n != 0 || err == nil {
				t.Fatal("unknown/expired mode allowed new bytes")
			}
			_, payload := source.snapshot()
			if len(payload.Traffic) != 0 {
				t.Fatal("mode fell back to v1 Traffic")
			}
		})
	}
}

// This rejected packet fixture is never used for actual UDP I/O; the enforcing
// RoutedPacketConnection must close it before returning without consuming bytes.
type modeRejectPacket struct {
	N.PacketConn
	closed bool
}

func (p *modeRejectPacket) Close() error { p.closed = true; return nil }

func TestServiceUsageV2SameSourceRestartRefusedAndPermanentOwnerNotReused(t *testing.T) {
	s, k, source, _ := modeFixture(t, 30*time.Second)
	cancel, done := startMode(t, s, k)
	cancel()
	finishMode(t, done, false)
	copy := *s.cfg
	next := NewWithControlPlane(&copy, source)
	next.usageOwner = &usagebucket.ProcessOwner{}
	nextK := &usageModeKernel{started: make(chan struct{})}
	next.kernel = nextK
	next.kernelLife = kernellifecycle.New(nextK)
	if err := next.Run(context.Background()); err == nil || nextK.starts != 0 {
		t.Fatal("old source epoch resumed live timeline")
	}
	other := NewWithControlPlane(&copy, source)
	other.usageOwner = s.usageOwner
	if err := other.preflightUsageV2(); err == nil {
		t.Fatal("permanent process owner reused after close")
	}
}
func TestServiceUsageV2DisabledHasNoConsumerWorkerOrExtraPath(t *testing.T) {
	s, _, source, _ := modeFixture(t, 30*time.Second)
	s.cfg.UsageV2.Enabled = false
	s.cfg.UsageV2.IsolatedCopy = false
	if err := s.preflightUsageV2(); err != nil || source.prepareCalls != 0 || s.usageMode() {
		t.Fatal("default mode allocated v2")
	}
	s.startUsageV2Worker()
	s.closeUsageV2()
	paths, err := filepath.Glob(filepath.Join(s.cfg.UsageV2.Directory, "*"))
	if err != nil || len(paths) != 0 {
		t.Fatal("disabled mode performed filesystem work")
	}
	encoded, _ := json.Marshal(s.prepareReportBatch())
	if !bytes.Contains(encoded, []byte("Traffic")) {
		t.Fatal("default report shape changed")
	}
}

func TestServiceUsageV2BlockedWorkerExpiryStopsIOAndRetainsOwnerUntilCompletion(t *testing.T) {
	s, k, source, transport := modeFixture(t, 3*time.Second)
	transport.blockEntered = make(chan struct{})
	transport.blockRelease = make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(transport.blockRelease)
		}
	})
	cancel, done := startMode(t, s, k)
	defer cancel()
	conn, _ := ioMode(t, k)
	select {
	case <-transport.blockEntered:
	case <-time.After(4 * time.Second):
		t.Fatal("worker did not block after sealed journal")
	}
	finishMode(t, done, true)
	if k.IsRunning() {
		t.Fatal("main lease timer waited for blocked worker")
	}
	if n, err := conn.Write([]byte("expired")); n != 0 || err == nil {
		t.Fatal("expired blocked mode continued IO")
	}
	spool, err := usagev2.OpenSpool(filepath.Join(s.cfg.UsageV2.Directory, "spool"), 0)
	if err == nil {
		spool.Close()
		t.Fatal("shutdown timeout released stalled worker owner")
	}
	other := NewWithControlPlane(s.cfg, source)
	other.usageOwner = s.usageOwner
	if other.preflightUsageV2() == nil {
		t.Fatal("timed-out process owner reassigned")
	}
	close(transport.blockRelease)
	released = true
	select {
	case <-s.usageV2.done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not close after stall released")
	}
	reopened, err := usagev2.OpenSpool(filepath.Join(s.cfg.UsageV2.Directory, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	records, err := reopened.Records()
	if err != nil || len(records) != 1 || records[0].Submission.Payload.Entries[0].RawUpBytes != "11" {
		t.Fatal("timeout discarded original sealed payload")
	}
}

// Opt-in real Core path. The kernel lifecycle is injected only to route memory
// TCP through the actual production enforcing tracker without a proxy listener.
// Source, config/users/handshake, Reporter HTTPS and SQL receipts are actual.
func TestServiceUsageV2ActualCoreHTTPInterop(t *testing.T) {
	dir := os.Getenv("TXBOARD_SERVICE_USAGE_DIR")
	if dir == "" {
		t.Skip("Requires opt-in dedicated actual Core HTTPS fixture")
	}
	var fixture struct {
		NodeID string `json:"node_id"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil || json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("actual Core fixture metadata unavailable")
	}
	id, err := strconv.Atoi(fixture.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{InstanceID: "service-real-core-fixture", Panel: config.PanelConfig{Provider: "txboard", URL: os.Getenv("TXBOARD_SERVICE_USAGE_ENDPOINT"), NodeID: id, Token: "service-usage-local-test-only"}, Kernel: config.KernelConfig{Type: "singbox", ConfigDir: filepath.Join(dir, "kernel"), LogLevel: "error"}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, PushInterval: 5, PullInterval: 60, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}, UsageV2: config.UsageV2Config{Enabled: true, IsolatedCopy: true, Directory: filepath.Join(dir, "mode"), CAFile: filepath.Join(dir, "cert.pem")}}
	if err := os.MkdirAll(cfg.Kernel.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	cp := controlplane.NewTXBoardControlPlane(cfg.Panel, cfg.WS, cfg.Kernel)
	if os.Getenv("TXBOARD_SERVICE_USAGE_PHASE") == "settled" {
		var capture struct {
			Session    usagev2.Session    `json:"session"`
			Submission usagev2.Submission `json:"submission"`
			Pending    usagev2.Receipt    `json:"pending_receipt"`
		}
		raw, err := os.ReadFile(filepath.Join(dir, "service-capture.json"))
		if err != nil || json.Unmarshal(raw, &capture) != nil {
			t.Fatal("original Service capture missing")
		}
		if err := cp.PrepareIsolatedUsageV2(cfg.UsageV2.CAFile); err != nil {
			t.Fatal(err)
		}
		bootstrap, err := cp.Initial(context.Background(), nil, nil, nil)
		if err != nil || bootstrap.UsageV2Transport == nil {
			t.Fatal("settled native transport missing")
		}
		spool, err := usagev2.OpenSpool(filepath.Join(cfg.UsageV2.Directory, "spool"), 0)
		if err != nil {
			t.Fatal(err)
		}
		reporter, err := usagev2.NewReporter(capture.Session, spool, bootstrap.UsageV2Transport)
		if err != nil {
			t.Fatal(err)
		}
		if err := reporter.Deliver(context.Background()); err != nil {
			t.Fatal(err)
		}
		records, err := spool.Records()
		if err != nil || len(records) != 1 || records[0].Receipt == nil || records[0].Receipt.SettlementStatus != "settled" || records[0].Receipt.ReceiptID != capture.Pending.ReceiptID {
			t.Fatal("actual settled Service receipt mismatch")
		}
		duplicate, err := bootstrap.UsageV2Transport.Submit(context.Background(), capture.Submission)
		if err != nil || duplicate.ReceiptID != capture.Pending.ReceiptID || duplicate.SettlementStatus != "settled" {
			t.Fatal("actual settled replay not stable")
		}
		settled := *records[0].Receipt
		if err := reporter.Close(); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(map[string]any{"session": capture.Session, "submission": capture.Submission, "pending_receipt": capture.Pending, "settled_receipt": settled, "actual_service_run": true, "receipt_retained_after_close": true, "production_authorization": false})
		if err := os.WriteFile(filepath.Join(dir, "service-settled.json"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	s := NewWithControlPlane(cfg, cp)
	s.usageOwner = &usagebucket.ProcessOwner{}
	k := &usageModeKernel{started: make(chan struct{})}
	s.kernel = k
	s.kernelLife = kernellifecycle.New(k)
	cancel, done := startMode(t, s, k)
	connection, _ := ioMode(t, k)
	var captured usagev2.Record
	waitMode(t, func() bool {
		files, _ := filepath.Glob(filepath.Join(cfg.UsageV2.Directory, "spool", "*.json"))
		if len(files) != 1 {
			return false
		}
		body, err := os.ReadFile(files[0])
		if err != nil {
			return false
		}
		if usagev2.StrictDecode(body, &captured, usagev2.MaxPayloadBytes) != nil {
			return false
		}
		return captured.Validate() == nil && captured.Receipt != nil && captured.Receipt.ReceiptStatus == "persisted"
	})
	connection.Close()
	cancel()
	finishMode(t, done, false)
	if captured.Submission.Payload.Entries[0].RawUpBytes != "11" || captured.Submission.Payload.Entries[0].RawDownBytes != "7" || s.tracker.HasTraffic() {
		t.Fatal("actual Core Service interval or v1 double queue wrong")
	}
	encoded, _ := json.Marshal(map[string]any{"session": captured.Session, "submission": captured.Submission, "pending_receipt": captured.Receipt, "actual_service_run": true, "native_config_users_handshake": true, "v1_traffic_sent": false, "kernel_lifecycle": "injected actual enforcing tracker; memory TCP; no live proxy listener"})
	if err := os.WriteFile(filepath.Join(dir, "service-capture.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
}
