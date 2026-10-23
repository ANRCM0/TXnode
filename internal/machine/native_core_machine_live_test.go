//go:build linux

package machine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/outbound"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
	"github.com/ANRCM0/TX-Node/internal/txboard"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
	"github.com/gorilla/websocket"
)

type machineCoreLiveNode struct {
	ID       int    `json:"id"`
	UserID   int    `json:"user_id"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	UUID     string `json:"uuid"`
}
type machineCoreLiveFixture struct {
	MachineID        int                   `json:"machine_id"`
	Token            string                `json:"token"`
	Nodes            []machineCoreLiveNode `json:"nodes"`
	OriginPort       int                   `json:"origin_port"`
	NewPort          int                   `json:"new_port"`
	ForeignMachineID int                   `json:"foreign_machine_id"`
	ForeignNodeID    int                   `json:"foreign_node_id"`
	ForeignToken     string                `json:"foreign_token"`
}
type machineCoreLiveSpool struct {
	Path          string          `json:"-"`
	NodeID        int             `json:"node_id"`
	BatchID       string          `json:"batch_id"`
	SHA256        string          `json:"sha256"`
	SourceEpoch   string          `json:"source_epoch"`
	PayloadDigest string          `json:"payload_digest"`
	PeriodIDs     []string        `json:"period_ids"`
	Payload       usagev2.Payload `json:"payload"`
}

// Observe the real callback without changing frames or draining the child mailbox.
type machineCoreConfigObservation struct {
	mu                                sync.Mutex
	targetID, newPort                 int
	received, dispatched, desiredPort bool
}
type machineCoreObservedControlPlane struct {
	machineControlPlane
	observation *machineCoreConfigObservation
}

// Preserve the native context extension while decorating only socket callbacks.
func (o *machineCoreObservedControlPlane) GetMachineNodesContext(ctx context.Context) (*machineDiscovery, error) {
	return machineNodesContext(ctx, o.machineControlPlane)
}
func (o *machineCoreObservedControlPlane) HandshakeContext(ctx context.Context) (*machineHandshake, error) {
	return machineHandshakeContext(ctx, o.machineControlPlane)
}
func (o *machineCoreObservedControlPlane) ReportMachineStatusContext(ctx context.Context, cpu float64, mem, swap, disk [2]uint64, netIn, netOut float64, status *machineRuntimeStatus) error {
	if native, ok := o.machineControlPlane.(machineContextControlPlane); ok {
		return native.ReportMachineStatusContext(ctx, cpu, mem, swap, disk, netIn, netOut, status)
	}
	return o.machineControlPlane.ReportMachineStatus(cpu, mem, swap, disk, netIn, netOut, status)
}

// Raw stacks remain private; only these reviewed owner labels reach evidence.
func machineCoreWaitChains() []string {
	labels := []struct{ needle, label string }{
		{"internal/machine.(*Orchestrator).stopAll(", "machine_children_join"},
		{"internal/machine.(*Orchestrator).rediscover(", "machine_discovery"},
		{"internal/machine.(*Orchestrator).startNode(", "machine_child_start"},
		{"internal/machine.(*Orchestrator).reportMachineStatusContext(", "machine_status"},
		{"internal/service.(*Service).Run(", "service_run"},
		{"internal/service.(*Service).recoverNativeStartup(", "startup_recovery"},
		{"internal/service.(*Service).initialSetup(", "startup_setup"},
		{"internal/service.(*Service).initNativeUsage(", "startup_usage"},
		{"internal/service.(*Service).newNativeCollector(", "startup_collector"},
		{"internal/usagev2.(*Reporter).DeliverNativeUnacknowledgedPage(", "startup_replay_page"},
		{"internal/service.(*Service).closeAuthorization(", "authorization_join"},
		{"internal/service.(*Service).requestAuthorizationSnapshot.func1(", "authorization_worker"},
		{"internal/service.(*Service).closeNativeUsage(", "native_usage_close"},
		{"internal/txboard.(*Client).AuthorizedUsersSnapshotContext(", "core_users_read"},
		{"internal/txboard.(*Client).requestContext(", "core_http"},
		{"internal/credentialdeliveryclient.(*Client).Resolve(", "provider_resolve"},
		{"internal/txboard.(*Socket).connect(", "shared_ws_connect"},
		{"internal/kernel/txnode.(*Kernel).Stop(", "kernel_stop"},
		{"sync.(*WaitGroup).Wait(", "worker_wait"},
	}
	buffer := make([]byte, 1<<20)
	stack := buffer[:runtime.Stack(buffer, true)]
	chains := map[string]bool{}
	for _, goroutine := range strings.Split(string(stack), "\n\n") {
		var chain []string
		for _, line := range strings.Split(goroutine, "\n") {
			for _, label := range labels {
				if strings.Contains(line, label.needle) && len(chain) < 12 {
					chain = append(chain, label.label)
				}
			}
		}
		if len(chain) > 0 {
			chains[strings.Join(chain, ">")] = true
		}
	}
	result := make([]string, 0, len(chains))
	for chain := range chains {
		result = append(result, chain)
	}
	sort.Strings(result)
	if len(result) > 16 {
		result = result[:16]
	}
	return result
}

func machineCoreChildren(o *Orchestrator) []<-chan struct{} {
	o.mu.Lock()
	defer o.mu.Unlock()
	children := make([]<-chan struct{}, 0, len(o.nodes))
	for _, child := range o.nodes {
		children = append(children, child.done)
	}
	return children
}

func machineCoreShutdownDiagnostic(t *testing.T, o *Orchestrator, children []<-chan struct{}, targetPort, siblingPort int) {
	t.Helper()
	o.mu.Lock()
	classes := []string{}
	for _, failure := range o.failures {
		classes = append(classes, machineCoreFailureClass(failure.lastErr))
	}
	sort.Strings(classes)
	terminal := o.terminalErr
	cancelled := o.runCtx != nil && o.runCtx.Err() != nil
	o.mu.Unlock()
	denial, typed := controlerror.AsAuthorityDenial(terminal)
	done := 0
	for _, child := range children {
		select {
		case <-child:
			done++
		default:
		}
	}
	socket := o.currentWS()
	data := map[string]any{"schema": "txnode-machine-shutdown-diagnostic/v1", "stage": "old-rejected", "code": "machine_join_timeout",
		"failed_children": len(classes), "failure_classes": classes,
		"terminal_cause_observed": terminal != nil, "terminal_machine_denial": typed && denial.Scope == controlerror.MachineScope,
		"context_cancelled": cancelled, "tracked_children": len(children), "completed_children": done,
		"shared_ws_connected": socket != nil && socket.IsConnected(), "target_listener_open": machineCoreListening(targetPort),
		"sibling_listener_open": machineCoreListening(siblingPort), "wait_chains": machineCoreWaitChains()}
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal("fixed shutdown diagnostic encoding failed")
	}
	t.Logf("NATIVE_MACHINE_SHUTDOWN_DIAGNOSTIC %s", body)
}

func machineCoreFailureClass(err error) string {
	class := "other"
	if denial, ok := controlerror.AsAuthorityDenial(err); ok {
		class = "authority_node"
		if denial.Scope == controlerror.MachineScope {
			class = "authority_machine"
		}
	}

	if class == "other" {
		switch {
		case errors.Is(err, context.Canceled):
			class = "context_canceled"
		case errors.Is(err, context.DeadlineExceeded):
			class = "context_deadline"
		default:
			cause := err
			for depth := 0; cause != nil && depth < 8; depth++ {
				for _, prefix := range []struct{ prefix, label string }{{"NODE_CREDENTIAL_DELIVERY_", "provider"}, {"NODE_AUTHORIZATION_", "authorization"}, {"NATIVE_USAGE_", "native_usage"}} {
					if strings.HasPrefix(cause.Error(), prefix.prefix) {
						class = prefix.label
						break
					}
				}
				if class != "other" {
					break
				}
				cause = errors.Unwrap(cause)
			}
		}
	}
	return class
}

// Publish only reviewed state labels; errors and runtime stacks remain private.
func machineCoreRecoveryDiagnostic(t *testing.T, o *Orchestrator, targetPort, siblingPort int) {
	t.Helper()
	o.mu.Lock()
	tracked, completed, cancelled, failures := len(o.nodes), 0, 0, len(o.failures)
	classes := []string{}
	for _, child := range o.nodes {
		select {
		case <-child.done:
			completed++
		default:
		}
	}
	for _, failure := range o.failures {
		class := machineCoreFailureClass(failure.lastErr)
		classes = append(classes, class)
	}
	if o.runCtx != nil && o.runCtx.Err() != nil {
		cancelled = 1
	}
	o.mu.Unlock()
	sort.Strings(classes)
	socket := o.currentWS()
	data := map[string]any{"schema": "txnode-machine-recovery-diagnostic/v1", "stage": "recovered", "code": "fresh_readiness_failed",
		"tracked_children": tracked, "completed_children": completed, "failed_children": failures, "failure_classes": classes,
		"context_cancelled": cancelled == 1, "shared_ws_connected": socket != nil && socket.IsConnected(),
		"target_listener_open": machineCoreListening(targetPort), "sibling_listener_open": machineCoreListening(siblingPort), "wait_chains": machineCoreWaitChains()}
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal("fixed recovery diagnostic encoding failed")
	}
	t.Logf("NATIVE_MACHINE_RECOVERY_DIAGNOSTIC %s", body)
}

func (o *machineCoreObservedControlPlane) NewMachineSocket(url, token string, machineID int, ws config.WSConfig, kernel config.KernelConfig, onEvent func(machineEvent), onStatus func(bool)) machineSocket {
	return o.machineControlPlane.NewMachineSocket(url, token, machineID, ws, kernel, func(event machineEvent) {
		onEvent(event)
		if event.NodeID != o.observation.targetID || event.NodeEvent.Type != controlplane.EventSyncConfig {
			return
		}
		o.observation.mu.Lock()
		o.observation.received = true
		o.observation.dispatched = event.Err == nil && event.NodeEvent.Config != nil
		o.observation.desiredPort = event.NodeEvent.Config != nil && event.NodeEvent.Config.ServerPort == o.observation.newPort
		o.observation.mu.Unlock()
	}, onStatus)
}
func (o *machineCoreConfigObservation) report(t *testing.T, orchestrator *Orchestrator, oldPort int, code string) {
	t.Helper()
	o.mu.Lock()
	data := map[string]any{"schema": "txnode-machine-config-diagnostic/v1", "stage": "configured", "code": code,
		"config_event_received": o.received, "config_event_dispatched": o.dispatched, "config_event_desired_port": o.desiredPort,
		"child_applied_port": "unavailable"}
	o.mu.Unlock()
	data["old_listener_open"] = machineCoreListening(oldPort)
	data["new_listener_open"] = machineCoreListening(o.newPort)
	socket := orchestrator.currentWS()
	data["shared_ws_connected"] = socket != nil && socket.IsConnected()
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal("fixed config diagnostic encoding failed")
	}
	t.Logf("NATIVE_MACHINE_CONFIG_DIAGNOSTIC %s", body)
}

// Real production Orchestrator, native installation activation, signed
// authorization, Provider mTLS delivery and period-bound native usage. The
// external runner supplies private fixture state, never substituted admission.
func TestNativeCoreMachineLive(t *testing.T) {
	directory := os.Getenv("TXBOARD_NATIVE_MACHINE_DIR")
	endpoint := os.Getenv("TXBOARD_NATIVE_MACHINE_URL")
	if directory == "" {
		t.Skip("requires exclusive true Core/Workerman/MySQL/Redis/TLS machine fixture")
	}
	if endpoint == "" || os.Getenv("SSL_CERT_FILE") == "" {
		t.Fatal("trusted native machine endpoint required")
	}
	var fixture machineCoreLiveFixture
	machineCoreDecode(t, filepath.Join(directory, "fixture.json"), &fixture)
	if fixture.MachineID <= 0 || len(fixture.Nodes) != 2 || fixture.Token == "" || fixture.Nodes[0].Protocol != "vless" || fixture.Nodes[1].Protocol != "vmess" || fixture.NewPort < 1024 || fixture.OriginPort < 1024 {
		t.Fatal("invalid dedicated machine fixture")
	}
	root := filepath.Join(directory, "kernel")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, node := range fixture.Nodes {
		if node.ID <= 0 || node.Port < 1024 || node.UserID <= 0 {
			t.Fatal("invalid fixture node")
		}
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("node-%d", node.ID)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	origin, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.OriginPort)))
	if err != nil {
		t.Fatal(err)
	}
	var originMu sync.Mutex
	originConnections := map[net.Conn]struct{}{}
	var originWG sync.WaitGroup
	t.Cleanup(func() {
		_ = origin.Close()
		originMu.Lock()
		for c := range originConnections {
			_ = c.Close()
		}
		originMu.Unlock()
		originWG.Wait()
	})
	originWG.Add(1)
	go func() {
		defer originWG.Done()
		for {
			connection, err := origin.Accept()
			if err != nil {
				return
			}
			originMu.Lock()
			originConnections[connection] = struct{}{}
			originMu.Unlock()
			originWG.Add(1)
			go func() {
				defer originWG.Done()
				defer connection.Close()
				defer func() { originMu.Lock(); delete(originConnections, connection); originMu.Unlock() }()
				_ = connection.SetDeadline(time.Now().Add(100 * time.Second))
				buffer := make([]byte, 65536)
				for {
					n, e := connection.Read(buffer)
					if n > 0 {
						if _, e := connection.Write(buffer[:n]); e != nil {
							return
						}
					}
					if e != nil {
						return
					}
				}
			}()
		}
	}()
	cfg := &config.Config{InstanceID: "actual-native-machine", Panel: config.PanelConfig{Provider: "txboard", URL: endpoint}, Machine: &config.MachineConfig{MachineID: fixture.MachineID, Token: fixture.Token}, Kernel: config.KernelConfig{Type: "txnode", ConfigDir: root, LogLevel: "error"}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, PushInterval: 60, PullInterval: 1, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60, HandshakeTimeout: 5, BackoffInitial: 1, BackoffMax: 3}}
	var trust struct {
		CoreInstanceID string `json:"core_instance_id"`
		KeyID          string `json:"key_id"`
		KeyEpoch       string `json:"key_epoch"`
		PublicKey      string `json:"public_key"`
	}
	machineCoreDecode(t, filepath.Join(directory, "trust.json"), &trust)
	provider := os.Getenv("NATIVE_MACHINE_PROVIDER")
	if provider == "" {
		t.Fatal("real private Provider endpoint required")
	}
	cfg.Authorization = config.AuthorizationConfig{Enabled: true, StateDir: filepath.Join(directory, "authorization"),
		CoreInstanceID: trust.CoreInstanceID, KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch, PublicKey: trust.PublicKey,
		PolicyVersion: config.NativeProviderUsagePolicyVersion, RefreshInterval: 1, MaxClockSkew: 1,
		Provider: config.AuthorizationProviderConfig{Endpoint: provider, ProviderID: "primary-provider", ProviderInstanceEpoch: "1",
			CAFile: filepath.Join(directory, "ca.pem"), ClientCert: filepath.Join(directory, "node.pem"), ClientKey: filepath.Join(directory, "node.key")}}
	cfg.UsageV2 = config.UsageV2Config{Enabled: true, Directory: filepath.Join(directory, "usage"), CAFile: filepath.Join(directory, "ca.pem")}
	usageRoot := cfg.UsageV2.Directory
	configObservation := &machineCoreConfigObservation{targetID: fixture.Nodes[0].ID, newPort: fixture.NewPort}
	start := func(cfg *config.Config) (*Orchestrator, context.CancelFunc, chan error) {
		o, e := NewChecked(cfg)
		if e != nil {
			t.Fatal(e)
		}
		o.client = &machineCoreObservedControlPlane{machineControlPlane: o.client, observation: configObservation}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- o.Run(ctx) }()
		return o, cancel, done
	}
	orchestrator, cancel, done := start(cfg)
	stopped := false
	t.Cleanup(func() {
		cancel()
		if !stopped {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("machine cleanup exceeded deadline")
			}
		}
	})
	machineCoreWait(t, done, 8*time.Second, func() bool {
		return machineCoreListening(fixture.Nodes[0].Port) && machineCoreListening(fixture.Nodes[1].Port) && orchestrator.currentWS() != nil && orchestrator.currentWS().IsConnected()
	})
	destination := socks.Addr{Host: "127.0.0.1", Port: uint16(fixture.OriginPort)}
	stream1 := machineCoreDial(t, fixture.Nodes[0], destination)
	defer stream1.Close()
	stream2 := machineCoreDial(t, fixture.Nodes[1], destination)
	defer stream2.Close()
	machineCoreEcho(t, stream1, bytes.Repeat([]byte("vless-initial"), 31))
	machineCoreEcho(t, stream2, bytes.Repeat([]byte("vmess-initial"), 37))
	machineCoreAlive(t, endpoint, fixture, fixture.Nodes[0], stream1)
	machineCoreAlive(t, endpoint, fixture, fixture.Nodes[1], stream2)
	machineCoreBarrier(t, directory, "initial", map[string]any{"machine_id": fixture.MachineID, "real_two_streams": true, "shared_ws_connected": true})
	machineCoreClosed(t, stream1, 8*time.Second, func(code string) { configObservation.report(t, orchestrator, fixture.Nodes[0].Port, code) })
	oldPort := fixture.Nodes[0].Port
	fixture.Nodes[0].Port = fixture.NewPort
	machineCoreWait(t, done, 8*time.Second, func() bool { return !machineCoreListening(oldPort) && machineCoreListening(fixture.NewPort) })
	stream1 = machineCoreDial(t, fixture.Nodes[0], destination)
	defer stream1.Close()
	machineCoreEcho(t, stream1, bytes.Repeat([]byte("changed-vless"), 43))
	machineCoreEcho(t, stream2, []byte("sibling-unchanged-after-config"))
	machineCoreBarrier(t, directory, "configured", map[string]any{"new_listener": fixture.NewPort, "old_listener_closed": true, "sibling_stream_continued": true})
	machineCoreBarrier(t, directory, "transient-start", map[string]any{"actual_existing_streams": true})
	// Runner causes a real shared TCP disconnect and four completed gateway503
	// responses. Keep real streams active while awaiting its recovery evidence.
	machineCoreEchoBarrier(t, directory, "transient-recovered", stream1, stream2)
	machineCoreWait(t, done, 8*time.Second, func() bool { return orchestrator.currentWS() != nil && orchestrator.currentWS().IsConnected() })
	machineCoreEcho(t, stream1, []byte("target-after-503-reconnect"))
	machineCoreEcho(t, stream2, []byte("sibling-after-503-reconnect"))
	// A second real authenticated client becomes the Workerman successor. It
	// sends only documented heartbeat messages and consumes real native frames.
	diagnostic := machineCoreSocket(t, endpoint, fixture.Token, fixture.MachineID, "session.ready")
	machineCoreWait(t, done, 2*time.Second, func() bool { return !orchestrator.currentWS().IsConnected() })
	machineCoreHeartbeat(t, diagnostic)
	machineCoreAlive(t, endpoint, fixture, fixture.Nodes[0], stream1)
	machineCoreAlive(t, endpoint, fixture, fixture.Nodes[1], stream2)
	machineCoreBarrier(t, directory, "replacement-ready", map[string]any{"actual_successor_session_ready": true, "actual_heartbeat_ack": true, "device_report_source": "actual_protocol_socket_peer", "traffic_injected": false})
	_ = diagnostic.Close()
	machineCoreWait(t, done, 8*time.Second, func() bool { return orchestrator.currentWS() != nil && orchestrator.currentWS().IsConnected() })
	machineCoreEcho(t, stream1, []byte("target-after-successor-reconnect"))
	machineCoreEcho(t, stream2, []byte("sibling-after-successor-reconnect"))
	machineCoreForeignScope(t, endpoint, fixture)
	machineCoreAlive(t, endpoint, fixture, fixture.Nodes[0], stream1)
	machineCoreAlive(t, endpoint, fixture, fixture.Nodes[1], stream2)
	machineCoreBarrier(t, directory, "scope-checked", map[string]any{"actual_foreign_http_ws_matrix": true, "sibling_authority_unchanged": true})
	machineCoreClosed(t, stream1, 8*time.Second)
	machineCoreWait(t, done, 8*time.Second, func() bool { return !machineCoreListening(fixture.NewPort) })
	machineCoreEcho(t, stream2, []byte("sibling-unchanged-after-disable"))
	machineCoreWait(t, done, 3*time.Second, func() bool {
		return len(machineCoreSpools(t, usageRoot, fixture.Nodes[0].ID)) > 0
	})
	removed := machineCoreSpools(t, usageRoot, fixture.Nodes[0].ID)
	if len(removed) == 0 {
		t.Fatal("withdrawn member traffic did not reach durable terminal storage")
	}
	machineCoreBarrier(t, directory, "disabled", map[string]any{"spools": removed, "target_stopped": true, "sibling_stream_continued": true})
	machineCoreWait(t, done, 12*time.Second, func() bool { return machineCoreListening(fixture.NewPort) })
	for _, spool := range removed {
		machineCoreReplayed(t, spool, "restored member opened before original native submission was acknowledged")
	}
	stream1 = machineCoreDial(t, fixture.Nodes[0], destination)
	defer stream1.Close()
	machineCoreEcho(t, stream1, bytes.Repeat([]byte("vless-rotation-tail"), 127))
	machineCoreEcho(t, stream2, bytes.Repeat([]byte("vmess-rotation-tail"), 131))
	var replacement struct {
		Token string `json:"token"`
	}
	shutdownChildren := machineCoreChildren(orchestrator)
	machineCoreBarrierResult(t, directory, "reenabled", map[string]any{"removed_replayed": removed, "fresh_listener": true, "actual_streams": true}, &replacement)
	select {
	case e := <-done:
		denial, ok := controlerror.AsAuthorityDenial(e)
		if !ok || denial.Scope != controlerror.MachineScope || denial.MachineID != fixture.MachineID {
			t.Fatalf("machine denial cause not preserved: %v", e)
		}
		stopped = true
	case <-time.After(10 * time.Second):
		machineCoreShutdownDiagnostic(t, orchestrator, shutdownChildren, fixture.NewPort, fixture.Nodes[1].Port)
		t.Fatal("authenticated machine rejection failed to join children")
	}
	machineCoreClosed(t, stream1, 2*time.Second)
	machineCoreClosed(t, stream2, 2*time.Second)
	if machineCoreListening(fixture.NewPort) || machineCoreListening(fixture.Nodes[1].Port) {
		t.Fatal("listener remained after machine credential rejection")
	}
	tails := append(machineCoreSpools(t, usageRoot, fixture.Nodes[0].ID), machineCoreSpools(t, usageRoot, fixture.Nodes[1].ID)...)
	for _, node := range fixture.Nodes {
		found := false
		for _, tail := range tails {
			if tail.NodeID == node.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("node %d had no terminal traffic", node.ID)
		}
	}
	for _, tail := range tails {
		if got := machineCoreHash(t, tail.Path); got != tail.SHA256 {
			t.Fatal("terminal storage changed before restart")
		}
	}
	old, err := NewChecked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	oldctx, oldcancel := context.WithTimeout(context.Background(), 5*time.Second)
	e := old.Run(oldctx)
	oldcancel()
	if denial, ok := controlerror.AsAuthorityDenial(e); !ok || denial.Scope != controlerror.MachineScope {
		t.Fatalf("old credentials restart not refused: %v", e)
	}
	if machineCoreListening(fixture.NewPort) || machineCoreListening(fixture.Nodes[1].Port) {
		t.Fatal("old token admitted a listener")
	}
	for _, tail := range tails {
		if got := machineCoreHash(t, tail.Path); got != tail.SHA256 {
			t.Fatal("old token restart mutated stored traffic")
		}
	}
	machineCoreBarrier(t, directory, "old-rejected", map[string]any{"tails": tails, "old_restart_denied": true, "listeners_closed": true})
	if replacement.Token == "" || replacement.Token == cfg.Machine.Token {
		t.Fatal("fresh machine token required")
	}
	newcfg := *cfg
	newMachine := *cfg.Machine
	newMachine.Token = replacement.Token
	newcfg.Machine = &newMachine
	current, newcancel, newdone := start(&newcfg)
	t.Cleanup(func() {
		newcancel()
		select {
		case e := <-newdone:
			if e != nil {
				t.Errorf("fresh machine cleanup: %v", e)
			}
		case <-time.After(10 * time.Second):
			t.Error("fresh machine failed cleanup")
		}
	})
	recoveryReady := false
	defer func() {
		if !recoveryReady {
			machineCoreRecoveryDiagnostic(t, current, fixture.NewPort, fixture.Nodes[1].Port)
		}
	}()
	machineCoreWait(t, newdone, 12*time.Second, func() bool {
		return machineCoreListening(fixture.NewPort) && machineCoreListening(fixture.Nodes[1].Port)
	})
	recoveryReady = true
	for _, tail := range tails {
		machineCoreReplayed(t, tail, "current token listeners opened before original native submission was acknowledged")
	}
	new1 := machineCoreDial(t, fixture.Nodes[0], destination)
	defer new1.Close()
	new2 := machineCoreDial(t, fixture.Nodes[1], destination)
	defer new2.Close()
	machineCoreEcho(t, new1, []byte("current-vless"))
	machineCoreEcho(t, new2, []byte("current-vmess"))
	machineCoreWrite(t, filepath.Join(directory, "machine-live-result.json"), map[string]any{"core_installation_mode": "native", "node_kernel": "txnode", "native_core_installation_admission": true, "actual_orchestrator": true, "actual_shared_workerman": true, "actual_ws_only_config_delivery": true, "transient_transport_retry": true, "successor_session_ready": true, "foreign_machine_scope": true, "device_facts_from_socket_peer": true, "actual_vless_vmess": true, "scope_safe_config_disable": true, "membership_tail_recovered": removed, "machine_denial_tails_recovered": tails, "old_restart_denied": true, "fresh_restart_authenticated": true, "real_database_billing_verified": false})
	machineCoreBarrier(t, directory, "recovered", map[string]any{"tails": tails, "actual_protocol_recovery": true})
}

func machineCoreListening(port int) bool {
	c, e := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 20*time.Millisecond)
	if e != nil {
		return false
	}
	_ = c.Close()
	return true
}
func machineCoreWait(t *testing.T, done chan error, limit time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-ticker.C:
		case e := <-done:
			done <- e
			t.Fatalf("machine exited before readiness: %v", e)
		case <-deadline.C:
			t.Fatal("actual machine readiness deadline")
		}
	}
}
func machineCoreDial(t *testing.T, node machineCoreLiveNode, destination socks.Addr) net.Conn {
	t.Helper()
	client, err := outbound.New(node.Protocol, opt.Opt{
		"server": "127.0.0.1", "port": node.Port, "uuid": node.UUID,
		"method": "aes-128-gcm", "network": "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	stream, err := client.DialTCP(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(90 * time.Second))
	return stream
}
func machineCoreEcho(t *testing.T, stream net.Conn, request []byte) {
	t.Helper()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e := stream.Write(request); e != nil {
		t.Fatal("actual machine stream write", e)
	}
	reply := make([]byte, len(request))
	if _, e := io.ReadFull(stream, reply); e != nil || !bytes.Equal(request, reply) {
		t.Fatal("actual machine echo failed", e)
	}
	_ = stream.SetDeadline(time.Now().Add(90 * time.Second))
}
func machineCoreClosed(t *testing.T, stream net.Conn, limit time.Duration, diagnostic ...func(string)) {
	t.Helper()
	_ = stream.SetReadDeadline(time.Now().Add(limit))
	var b [1]byte
	n, e := stream.Read(b[:])
	if n != 0 || e == nil {
		for _, report := range diagnostic {
			report("old_stream_remained_open")
		}
		t.Fatal("revoked actual stream remained open")
	}
	if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		for _, report := range diagnostic {
			report("old_stream_close_timeout")
		}
		t.Fatal("stream timed out instead of authority close")
	}
}
func machineCoreDecode(t *testing.T, path string, value any) {
	t.Helper()
	body, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(body, value); e != nil {
		t.Fatal(e)
	}
}
func machineCoreWrite(t *testing.T, path string, value any) {
	t.Helper()
	body, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	temporary := path + ".write"
	f, e := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(body); e == nil {
		e = f.Sync()
	}
	closeerr := f.Close()
	if e != nil || closeerr != nil {
		t.Fatal("fixture barrier persistence failed", e, closeerr)
	}
	if e := os.Rename(temporary, path); e != nil {
		t.Fatal(e)
	}
	directory, e := os.Open(filepath.Dir(path))
	if e != nil {
		t.Fatal(e)
	}
	e = directory.Sync()
	closeerr = directory.Close()
	if e != nil || closeerr != nil {
		t.Fatal("fixture barrier directory persistence failed", e, closeerr)
	}
}
func machineCoreBarrier(t *testing.T, directory, stage string, value any) {
	machineCoreBarrierResult(t, directory, stage, value, nil)
}
func machineCoreBarrierResult(t *testing.T, directory, stage string, value, target any) {
	t.Helper()
	machineCoreWrite(t, filepath.Join(directory, stage+".ready.json"), value)
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	path := filepath.Join(directory, stage+".ack.json")
	for {
		if _, e := os.Stat(path); e == nil {
			if target != nil {
				machineCoreDecode(t, path, target)
			}
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("runner stage %s did not complete", stage)
		}
	}
}
func machineCoreHash(t *testing.T, path string) string {
	t.Helper()
	body, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

// The legacy terminal-slot invariant maps to native durable unacknowledged
// submissions. Receipts are retained beside original payloads after replay.
func machineCoreSpools(t *testing.T, root string, nodeID int) []machineCoreLiveSpool {
	t.Helper()
	paths, e := filepath.Glob(filepath.Join(root, fmt.Sprintf("node-%d", nodeID), "spool", "*.usage.json"))
	if e != nil {
		t.Fatal(e)
	}
	result := []machineCoreLiveSpool{}
	for _, path := range paths {
		var record usagev2.Record
		machineCoreDecode(t, path, &record)
		if err := record.Validate(); err != nil {
			t.Fatal("invalid native usage record", err)
		}
		// Only unacknowledged tail work participates in restart ordering. Existing
		// acknowledged traffic remains durably retained under the receipt policy.
		if record.Receipt != nil {
			continue
		}
		payload := record.Submission.Payload
		if payload.NodeID != strconv.Itoa(nodeID) || len(payload.Entries) == 0 {
			t.Fatal("empty or foreign native tail")
		}
		periods := make([]string, 0, len(payload.Entries))
		for _, entry := range payload.Entries {
			periods = append(periods, entry.UsagePeriodID)
		}
		result = append(result, machineCoreLiveSpool{Path: path, NodeID: nodeID, BatchID: payload.BatchID, SHA256: machineCoreHash(t, path),
			SourceEpoch: payload.SourceEpoch, PayloadDigest: record.Submission.PayloadDigest, PeriodIDs: periods, Payload: payload})
	}
	return result
}

func machineCoreReplayed(t *testing.T, original machineCoreLiveSpool, failure string) {
	t.Helper()
	var record usagev2.Record
	machineCoreDecode(t, original.Path, &record)
	if err := record.Validate(); err != nil {
		t.Fatal(failure, err)
	}
	before, err := json.Marshal(original.Payload)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(record.Submission.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || record.Submission.PayloadDigest != original.PayloadDigest ||
		record.Receipt == nil || record.Receipt.ReceiptStatus != "persisted" {
		t.Fatal(failure)
	}
}

// Device facts are a separate alive-only native report. No traffic/counters are
// supplied: source IP is the real authenticated protocol socket's local peer.
func machineCoreAlive(t *testing.T, endpoint string, fixture machineCoreLiveFixture, node machineCoreLiveNode, stream net.Conn) {
	t.Helper()
	address, ok := stream.LocalAddr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		t.Fatal("actual local protocol peer required")
	}
	client := txboard.NewClient(config.PanelConfig{URL: endpoint, Token: fixture.Token, MachineID: fixture.MachineID, NodeID: node.ID})
	if err := client.PostReport(map[string]any{"alive": map[int][]string{node.UserID: {address.IP.String()}}}); err != nil {
		t.Fatal("actual alive-only device report", err)
	}
}

func machineCoreEchoBarrier(t *testing.T, directory, stage string, first, second net.Conn) {
	t.Helper()
	machineCoreWrite(t, filepath.Join(directory, stage+".ready.json"), map[string]any{"actual_streams_continue_during_fault": true})
	deadline := time.NewTimer(18 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(filepath.Join(directory, stage+".ack.json")); err == nil {
			return
		}
		select {
		case <-ticker.C:
			machineCoreEcho(t, first, []byte("vless-during-gateway-fault"))
			machineCoreEcho(t, second, []byte("vmess-during-gateway-fault"))
		case <-deadline.C:
			t.Fatal("actual outage barrier exceeded deadline")
		}
	}
}

func machineCoreSocket(t *testing.T, endpoint, token string, machineID int, expected string) *websocket.Conn {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer " + token}, "X-TX-Machine-ID": {strconv.Itoa(machineID)}, "User-Agent": {"TXNode-live-successor"}}
	connection, _, err := (&websocket.Dialer{HandshakeTimeout: 3 * time.Second}).Dial("wss"+strings.TrimPrefix(endpoint, "https")+"/txapi/node/v1/ws", headers)
	if err != nil {
		if expected == "error" && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			// NativeNodeWebSocket performs the same current credential check
			// before locked Workerman sends101. Accept its actual transport close
			// only with independent middleware401 and direct upstream-close proof;
			// EOF alone never establishes a credential refusal.
			machineCoreRejectedUpgradeEvidence(t, machineID)
			return nil
		}
		t.Fatal("actual native WSS client", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	var frame struct {
		Version int            `json:"protocol_version"`
		Event   string         `json:"event"`
		Data    map[string]any `json:"data"`
	}
	if err := connection.ReadJSON(&frame); err != nil || frame.Version != 1 || frame.Event != expected {
		t.Fatalf("real native upgrade response: event=%s error=%v", frame.Event, err)
	}
	if expected == "session.ready" && (frame.Data["mode"] != "machine" || frame.Data["machine_id"] != float64(machineID)) {
		t.Fatal("actual successor identity mismatch")
	}
	if expected == "error" && frame.Data["code"] != "UNAUTHORIZED" {
		t.Fatal("foreign upgrade was not refused")
	}
	return connection
}

func machineCoreHeartbeat(t *testing.T, connection *websocket.Conn) {
	t.Helper()
	_ = connection.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := connection.WriteJSON(map[string]any{"protocol_version": 1, "event": "heartbeat.ping", "request_id": "actual-machine-successor-heartbeat", "data": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var frame struct {
			Event     string `json:"event"`
			RequestID string `json:"request_id"`
		}
		if err := connection.ReadJSON(&frame); err != nil {
			t.Fatal("actual successor heartbeat", err)
		}
		if frame.Event == "heartbeat.ack" && frame.RequestID == "actual-machine-successor-heartbeat" {
			return
		}
	}
}

func machineCoreForeignScope(t *testing.T, endpoint string, fixture machineCoreLiveFixture) {
	t.Helper()
	if fixture.ForeignMachineID <= 0 || fixture.ForeignNodeID <= 0 || fixture.ForeignToken == "" {
		t.Fatal("foreign Machine fixture required")
	}
	request := func(path, token string, machineID, nodeID int, expectedStatus int, expectedCode string) {
		req, err := http.NewRequest(http.MethodGet, endpoint+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-TX-Machine-ID", strconv.Itoa(machineID))
		if nodeID > 0 {
			req.Header.Set("X-TX-Node-ID", strconv.Itoa(nodeID))
		}
		response, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&body) != nil || response.StatusCode != expectedStatus || body.Error.Code != expectedCode {
			t.Fatalf("actual foreign HTTP scope: status=%d code=%s", response.StatusCode, body.Error.Code)
		}
	}
	request("/txapi/node/v1/config", fixture.Token, fixture.MachineID, fixture.ForeignNodeID, 404, "NODE_NOT_FOUND")
	request("/txapi/node/v1/machine/nodes", fixture.Token, fixture.ForeignMachineID, 0, 401, "NODE_UNAUTHORIZED")
	rejected := machineCoreSocket(t, endpoint, fixture.Token, fixture.ForeignMachineID, "error")
	if rejected != nil {
		_ = rejected.Close()
	}
	foreign := machineCoreSocket(t, endpoint, fixture.ForeignToken, fixture.ForeignMachineID, "session.ready")
	defer foreign.Close()
	_ = foreign.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := foreign.WriteJSON(map[string]any{"protocol_version": 1, "event": "sync.request", "request_id": "actual-foreign-node-request", "data": map[string]any{"node_id": fixture.Nodes[0].ID}}); err != nil {
		t.Fatal(err)
	}
	_ = foreign.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var frame struct {
			Event     string         `json:"event"`
			RequestID string         `json:"request_id"`
			Data      map[string]any `json:"data"`
		}
		if err := foreign.ReadJSON(&frame); err != nil {
			t.Fatal(err)
		}
		if frame.RequestID == "actual-foreign-node-request" {
			if frame.Event != "error" || frame.Data["code"] != "NODE_NOT_FOUND" {
				t.Fatal("actual foreign WS node accepted")
			}
			break
		}
	}
}

func machineCoreRejectedUpgradeEvidence(t *testing.T, machineID int) {
	t.Helper()
	path := filepath.Join(os.Getenv("TXBOARD_NATIVE_MACHINE_DIR"), "native-observations.jsonl")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var middlewareRefused, upstreamRefused bool
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct {
			Kind          string `json:"kind"`
			MachineID     string `json:"machine_id"`
			Path          string `json:"path"`
			Status        int    `json:"status"`
			Code          string `json:"error_code"`
			ResponseBytes int    `json:"response_bytes"`
		}
		if json.Unmarshal(line, &event) != nil {
			continue
		}
		if event.MachineID != strconv.Itoa(machineID) {
			continue
		}
		if event.Kind == "http" && event.Path == "/txapi/node/v1/machine/nodes" && event.Status == 401 && event.Code == "NODE_UNAUTHORIZED" {
			middlewareRefused = true
		}
		if event.Kind == "ws-preupgrade-close" && event.ResponseBytes == 0 {
			upstreamRefused = true
		}
	}
	if !middlewareRefused || !upstreamRefused {
		t.Fatal("pre-upgrade EOF lacked actual Core401 and direct Workerman-close evidence")
	}
}
