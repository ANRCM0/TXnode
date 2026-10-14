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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	"github.com/ANRCM0/TX-Node/internal/txboard"
	"github.com/gorilla/websocket"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
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
	Path    string           `json:"-"`
	NodeID  int              `json:"node_id"`
	BatchID string           `json:"batch_id"`
	SHA256  string           `json:"sha256"`
	Traffic map[int][2]int64 `json:"traffic"`
}

// Real production Orchestrator, native HTTP/WSS, Workerman, Redis and decoded
// TCP protocol bytes. Only the exclusive external runner supplies Core state.
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
	cfg := &config.Config{InstanceID: "actual-native-machine", Panel: config.PanelConfig{Provider: "txboard", URL: endpoint}, Machine: &config.MachineConfig{MachineID: fixture.MachineID, Token: fixture.Token}, Kernel: config.KernelConfig{Type: "singbox", ConfigDir: root, LogLevel: "error"}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, PushInterval: 60, PullInterval: 1, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60, HandshakeTimeout: 5, BackoffInitial: 1, BackoffMax: 3}}
	start := func(cfg *config.Config) (*Orchestrator, context.CancelFunc, chan error) {
		o, e := NewChecked(cfg)
		if e != nil {
			t.Fatal(e)
		}
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
	destination := M.ParseSocksaddr(origin.Addr().String())
	stream1 := machineCoreDial(t, fixture.Nodes[0], destination)
	defer stream1.Close()
	stream2 := machineCoreDial(t, fixture.Nodes[1], destination)
	defer stream2.Close()
	machineCoreEcho(t, stream1, bytes.Repeat([]byte("vless-initial"), 31))
	machineCoreEcho(t, stream2, bytes.Repeat([]byte("vmess-initial"), 37))
	machineCoreAlive(t, endpoint, fixture, fixture.Nodes[0], stream1)
	machineCoreAlive(t, endpoint, fixture, fixture.Nodes[1], stream2)
	machineCoreBarrier(t, directory, "initial", map[string]any{"machine_id": fixture.MachineID, "real_two_streams": true, "shared_ws_connected": true})
	machineCoreClosed(t, stream1, 8*time.Second)
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
		paths, _ := filepath.Glob(filepath.Join(root, fmt.Sprintf("node-%d", fixture.Nodes[0].ID), "*.pending.json.terminal.json"))
		return len(paths) == 1
	})
	removed := machineCoreSpools(t, root, fixture.Nodes[0].ID)
	if len(removed) == 0 {
		t.Fatal("withdrawn member traffic did not reach durable terminal storage")
	}
	machineCoreBarrier(t, directory, "disabled", map[string]any{"spools": removed, "target_stopped": true, "sibling_stream_continued": true})
	machineCoreWait(t, done, 12*time.Second, func() bool { return machineCoreListening(fixture.NewPort) })
	for _, spool := range removed {
		if _, e := os.Stat(spool.Path); !os.IsNotExist(e) {
			t.Fatal("restored member opened before old terminal slot was replayed")
		}
	}
	stream1 = machineCoreDial(t, fixture.Nodes[0], destination)
	defer stream1.Close()
	machineCoreEcho(t, stream1, bytes.Repeat([]byte("vless-rotation-tail"), 127))
	machineCoreEcho(t, stream2, bytes.Repeat([]byte("vmess-rotation-tail"), 131))
	var replacement struct {
		Token string `json:"token"`
	}
	machineCoreBarrierResult(t, directory, "reenabled", map[string]any{"removed_replayed": removed, "fresh_listener": true, "actual_streams": true}, &replacement)
	select {
	case e := <-done:
		denial, ok := controlerror.AsAuthorityDenial(e)
		if !ok || denial.Scope != controlerror.MachineScope || denial.MachineID != fixture.MachineID {
			t.Fatalf("machine denial cause not preserved: %v", e)
		}
		stopped = true
	case <-time.After(10 * time.Second):
		t.Fatal("authenticated machine rejection failed to join children")
	}
	machineCoreClosed(t, stream1, 2*time.Second)
	machineCoreClosed(t, stream2, 2*time.Second)
	if machineCoreListening(fixture.NewPort) || machineCoreListening(fixture.Nodes[1].Port) {
		t.Fatal("listener remained after machine credential rejection")
	}
	tails := append(machineCoreSpools(t, root, fixture.Nodes[0].ID), machineCoreSpools(t, root, fixture.Nodes[1].ID)...)
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
	_ = current
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
	machineCoreWait(t, newdone, 12*time.Second, func() bool {
		return machineCoreListening(fixture.NewPort) && machineCoreListening(fixture.Nodes[1].Port)
	})
	for _, tail := range tails {
		if _, e := os.Stat(tail.Path); !os.IsNotExist(e) {
			t.Fatal("current token listeners opened with an unreplayed terminal slot")
		}
	}
	new1 := machineCoreDial(t, fixture.Nodes[0], destination)
	defer new1.Close()
	new2 := machineCoreDial(t, fixture.Nodes[1], destination)
	defer new2.Close()
	machineCoreEcho(t, new1, []byte("current-vless"))
	machineCoreEcho(t, new2, []byte("current-vmess"))
	machineCoreWrite(t, filepath.Join(directory, "machine-live-result.json"), map[string]any{"actual_orchestrator": true, "actual_shared_workerman": true, "actual_ws_only_config_delivery": true, "transient_transport_retry": true, "successor_session_ready": true, "foreign_machine_scope": true, "device_facts_from_socket_peer": true, "actual_vless_vmess": true, "scope_safe_config_disable": true, "membership_tail_recovered": removed, "machine_denial_tails_recovered": tails, "old_restart_denied": true, "fresh_restart_authenticated": true, "real_database_billing_verified": false})
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
func machineCoreDial(t *testing.T, node machineCoreLiveNode, destination M.Socksaddr) net.Conn {
	t.Helper()
	raw, e := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(node.Port)), 2*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	_ = raw.SetDeadline(time.Now().Add(90 * time.Second))
	var stream net.Conn
	if node.Protocol == "vless" {
		client, e := vless.NewClient(node.UUID, "", logger.NOP())
		if e != nil {
			raw.Close()
			t.Fatal(e)
		}
		stream, e = client.DialConn(raw, destination)
	} else {
		client, err := vmess.NewClient(node.UUID, "aes-128-gcm", 0)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		stream, e = client.DialConn(raw, destination)
	}
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
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
func machineCoreClosed(t *testing.T, stream net.Conn, limit time.Duration) {
	t.Helper()
	_ = stream.SetReadDeadline(time.Now().Add(limit))
	var b [1]byte
	n, e := stream.Read(b[:])
	if n != 0 || e == nil {
		t.Fatal("revoked actual stream remained open")
	}
	if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
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
func machineCoreSpools(t *testing.T, root string, nodeID int) []machineCoreLiveSpool {
	t.Helper()
	paths, e := filepath.Glob(filepath.Join(root, fmt.Sprintf("node-%d", nodeID), "*.pending.json.terminal.json"))
	if e != nil {
		t.Fatal(e)
	}
	result := []machineCoreLiveSpool{}
	for _, path := range paths {
		var batch reporting.Batch
		machineCoreDecode(t, path, &batch)
		if batch.Payload.BatchID == "" || len(batch.Payload.Traffic) == 0 {
			t.Fatal("empty terminal spool")
		}
		result = append(result, machineCoreLiveSpool{Path: path, NodeID: nodeID, BatchID: batch.Payload.BatchID, SHA256: machineCoreHash(t, path), Traffic: batch.Payload.Traffic})
	}
	return result
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
