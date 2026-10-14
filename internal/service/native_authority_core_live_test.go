package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	M "github.com/sagernet/sing/common/metadata"
)

type nativeAuthorityLiveFixture struct {
	NodeID     int    `json:"node_id"`
	UserID     int    `json:"user_id"`
	Protocol   string `json:"protocol"`
	NodePort   int    `json:"node_port"`
	OriginPort int    `json:"origin_port"`
	UUID       string `json:"uuid"`
}

// Ordinary native-v1 Service: genuine Core HTTP, TLS verification and protocol IO.
// The runner performs the administrator mutation after the ready barrier. This
// test never supplies a source/sink mock, cumulative counter or Usage-v2 grant.
func TestServiceNativeAuthorityCoreLive(t *testing.T) {
	directory := os.Getenv("TXBOARD_NATIVE_AUTHORITY_CORE_DIR")
	if directory == "" {
		t.Skip("requires exclusive native-control database and real Core fixture")
	}
	endpoint := os.Getenv("TXBOARD_NATIVE_AUTHORITY_CORE_URL")
	if endpoint == "" || os.Getenv("SSL_CERT_FILE") == "" {
		t.Fatal("trusted native Core TLS fixture required")
	}
	var fixture nativeAuthorityLiveFixture
	body, e := os.ReadFile(filepath.Join(directory, "fixture.json"))
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(body, &fixture) != nil || fixture.NodeID <= 0 || fixture.UserID <= 0 || fixture.UUID != liveProtocolUUID || fixture.NodePort < 1024 || fixture.OriginPort < 1024 || fixture.OriginPort == fixture.NodePort || (fixture.Protocol != "vless" && fixture.Protocol != "vmess") {
		t.Fatal("invalid exclusive native fixture")
	}
	kernelDir := filepath.Join(directory, "kernel")
	if e := os.Mkdir(kernelDir, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := &config.Config{InstanceID: "native-authority-core-" + fixture.Protocol,
		Panel:  config.PanelConfig{Provider: "txboard", URL: endpoint, NodeID: fixture.NodeID, Token: "native-control-local-test-only"},
		Kernel: config.KernelConfig{Type: "singbox", ConfigDir: kernelDir, LogLevel: "error", CustomRoute: []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{fixture.OriginPort}, "outbound": "direct"}}},
		Cert:   config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 60, PushInterval: 60, PullInterval: 1, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}}
	svc, e := NewChecked(cfg)
	if e != nil {
		t.Fatal("normal native Service construction failed", e)
	}
	if cfg.UsageV2.Enabled || svc.usageMode() {
		t.Fatal("isolated-v2 entered native fixture")
	}
	origin, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: fixture.OriginPort})
	if e != nil {
		t.Fatal(e)
	}
	defer origin.Close()
	request := bytes.Repeat([]byte{'u'}, 43)
	response := bytes.Repeat([]byte{'D'}, 79)
	originResult := make(chan error, 1)
	go func() {
		conn, e := origin.AcceptTCP()
		if e != nil {
			originResult <- e
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		got := make([]byte, len(request))
		_, e = io.ReadFull(conn, got)
		if e != nil || !bytes.Equal(got, request) {
			originResult <- io.ErrUnexpectedEOF
			return
		}
		if _, e = conn.Write(response); e != nil {
			originResult <- e
			return
		}
		var last [1]byte
		n, e := conn.Read(last[:])
		if n != 0 || e == nil {
			originResult <- io.ErrNoProgress
			return
		}
		originResult <- nil
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.NodePort))
	liveProtocolWait(t, done, 6*time.Second, func() bool {
		c, e := net.DialTimeout("tcp4", address, 20*time.Millisecond)
		if e != nil {
			return false
		}
		c.Close()
		return true
	})
	raw, client := liveProtocolDial(t, fixture.Protocol, address, fixture.UUID, M.ParseSocksaddr(net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.OriginPort))))
	defer raw.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(20 * time.Second))
	if n, e := client.Write(request); e != nil || n != len(request) {
		t.Fatal("real native protocol request incomplete", e)
	}
	got := make([]byte, len(response))
	if _, e := io.ReadFull(client, got); e != nil || !bytes.Equal(got, response) {
		t.Fatal("real native protocol response incomplete", e)
	}
	liveProtocolWrite(t, filepath.Join(directory, "ready.json"), map[string]any{"node_id": fixture.NodeID, "user_id": fixture.UserID, "protocol": fixture.Protocol, "request_bytes": len(request), "response_bytes": len(response), "actual_service": true, "actual_native_v1": true, "actual_protocol_stream": true})
	var terminal error
	select {
	case terminal = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("real Core denial did not stop native Service")
	}
	denial, ok := controlerror.AsAuthorityDenial(terminal)
	if !ok || denial.Scope != controlerror.NodeScope || denial.NodeID != fixture.NodeID || denial.Code != "NODE_NOT_FOUND" || denial.HTTPStatus != 404 {
		t.Fatal("expected scoped Core node disable denial", terminal)
	}
	if svc.kernel.IsRunning() {
		t.Fatal("denied native kernel still running")
	}
	if conn, e := net.DialTimeout("tcp4", address, 100*time.Millisecond); e == nil {
		conn.Close()
		t.Fatal("denied native listener reopened")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var extra [1]byte
	if n, e := client.Read(extra[:]); n != 0 || e == nil {
		t.Fatal("denied established native stream still open")
	}
	select {
	case e := <-originResult:
		if e != nil {
			t.Fatal("origin closure evidence invalid", e)
		}
	case <-time.After(time.Second):
		t.Fatal("origin stream not closed by denial")
	}
	tailPath := svc.legacyPendingPath + ".terminal.json"
	tail, e := os.ReadFile(tailPath)
	if e != nil {
		t.Fatal("final native durable tail absent", e)
	}
	var batch reporting.Batch
	if json.Unmarshal(tail, &batch) != nil || batch.Payload.BatchID == "" || batch.Payload.Traffic[fixture.UserID][0] < int64(len(request)) || batch.Payload.Traffic[fixture.UserID][1] < int64(len(response)) {
		t.Fatal("actual unreported native bytes missing from distinct tail")
	}
	tailHash := sha256.Sum256(tail)
	restart, e := NewChecked(cfg)
	if e != nil {
		t.Fatal(e)
	}
	restartErr := restart.Run(context.Background())
	again, ok := controlerror.AsAuthorityDenial(restartErr)
	if !ok || again.Code != "NODE_NOT_FOUND" || again.NodeID != fixture.NodeID || restart.kernel.IsRunning() {
		t.Fatal("disabled node restart accepted stale identity", restartErr)
	}
	retained, e := os.ReadFile(tailPath)
	if e != nil || !bytes.Equal(retained, tail) {
		t.Fatal("denied restart mutated old tail")
	}
	if conn, e := net.DialTimeout("tcp4", address, 100*time.Millisecond); e == nil {
		conn.Close()
		t.Fatal("rejected restart opened listener")
	}
	if _, e := os.Stat(filepath.Join(directory, "mutation.json")); e != nil {
		t.Fatal("actual administrator mutation barrier missing")
	}
	liveProtocolWrite(t, filepath.Join(directory, "core-live-result.json"), map[string]any{
		"protocol": fixture.Protocol, "node_id": fixture.NodeID, "user_id": fixture.UserID, "actual_service": true, "actual_singbox": true, "native_v1": true, "usage_v2_enabled": false,
		"denial_code": denial.Code, "denial_http_status": denial.HTTPStatus, "listener_closed": true, "established_stream_closed": true, "rejected_restart_before_listener": true,
		"decoded_up_bytes": len(request), "decoded_down_bytes": len(response), "terminal_up_bytes": batch.Payload.Traffic[fixture.UserID][0], "terminal_down_bytes": batch.Payload.Traffic[fixture.UserID][1],
		"terminal_batch_id": batch.Payload.BatchID, "tail_sha256": hex.EncodeToString(tailHash[:]), "tail_unchanged_after_rejected_restart": true})
}
