package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const liveProtocolUUID = "00112233-4455-6677-8899-aabbccddeeff"

type liveProtocolFixture struct {
	NodeID     string `json:"node_id"`
	Protocol   string `json:"protocol"`
	NodePort   int    `json:"node_port"`
	OriginPort int    `json:"origin_port"`
}
type liveProtocolCapture struct {
	Session             usagev2.Session    `json:"session"`
	Submission          usagev2.Submission `json:"submission"`
	Pending             usagev2.Receipt    `json:"pending_receipt"`
	Protocol            string             `json:"protocol"`
	RequestBytes        int                `json:"request_bytes"`
	ResponseBytes       int                `json:"response_bytes"`
	RequestSHA256       string             `json:"request_sha256"`
	ResponseSHA256      string             `json:"response_sha256"`
	Heartbeat           json.RawMessage    `json:"scheduled_heartbeat"`
	Listener            string             `json:"actual_listener"`
	ActualService       bool               `json:"actual_service_run"`
	ActualKernel        bool               `json:"actual_singbox_kernel"`
	WrongUUIDRejected   bool               `json:"wrong_uuid_rejected"`
	NativeTrafficAbsent bool               `json:"native_traffic_absent"`
}

// This opt-in fixture constructs the production Service/kernel normally. It never
// replaces the kernel or supplies a counter map; only real decoded protocol IO
// can reach the enforcing interval collector and produce the submission.
func TestServiceUsageV2LiveProtocolCoreInterop(t *testing.T) {
	dir := os.Getenv("TXBOARD_LIVE_PROTOCOL_DIR")
	if dir == "" {
		t.Skip("requires exclusive real Core HTTPS/live protocol fixture")
	}
	var fixture liveProtocolFixture
	liveProtocolDecode(t, filepath.Join(dir, "fixture.json"), &fixture)
	if (fixture.Protocol != "vless" && fixture.Protocol != "vmess") || fixture.NodePort < 1024 || fixture.OriginPort < 1024 || fixture.NodePort == fixture.OriginPort {
		t.Fatal("invalid loopback protocol fixture")
	}
	id, err := strconv.Atoi(fixture.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		InstanceID: "live-protocol-" + fixture.Protocol,
		Panel:      config.PanelConfig{Provider: "txboard", URL: os.Getenv("TXBOARD_LIVE_PROTOCOL_ENDPOINT"), NodeID: id, Token: "live-protocol-local-test-only"},
		Kernel:     config.KernelConfig{Type: "singbox", ConfigDir: filepath.Join(dir, "kernel"), LogLevel: "error", CustomRoute: []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{fixture.OriginPort}, "outbound": "direct"}}},
		Cert:       config.CertConfig{CertMode: "none"},
		Node:       config.NodeConfig{TrackInterval: 1, PushInterval: 5, PullInterval: 60, DeviceReportInterval: 60},
		WS:         config.WSConfig{DiscoveryInterval: 60},
		UsageV2:    config.UsageV2Config{Enabled: true, IsolatedCopy: true, Directory: filepath.Join(dir, "mode"), CAFile: filepath.Join(dir, "cert.pem")},
	}
	if err := os.MkdirAll(cfg.Kernel.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("TXBOARD_LIVE_PROTOCOL_PHASE") == "settled" {
		liveProtocolVerifySettled(t, dir, cfg)
		return
	}
	if os.Getenv("TXBOARD_LIVE_PROTOCOL_PHASE") != "capture" {
		t.Fatal("invalid fixture phase")
	}
	origin, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: fixture.OriginPort})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	svc, err := NewChecked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if svc.kernel.Name() != "sing-box" {
		t.Fatal("real sing-box kernel not constructed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	startedAt := time.Now()
	go func() { done <- svc.Run(ctx) }()
	liveProtocolWait(t, done, 12*time.Second, func() bool { return svc.kernel.IsRunning() })
	liveProtocolCheckListener(t, fixture.NodePort)
	nodeAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.NodePort))
	destination := M.ParseSocksaddr(net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.OriginPort)))

	// Authentication refusal must happen before Router/ConnTracker and cannot
	// result in an origin connection or substitute a billing grant.
	wrongRaw, wrong := liveProtocolDial(t, fixture.Protocol, nodeAddress, "10112233-4455-6677-8899-aabbccddeeff", destination)
	_ = wrong.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = wrong.Write([]byte("untrusted"))
	var rejected [1]byte
	if n, e := wrong.Read(rejected[:]); n != 0 || e == nil {
		t.Fatal("wrong UUID was not rejected")
	}
	wrong.Close()
	wrongRaw.Close()
	_ = origin.SetDeadline(time.Now().Add(150 * time.Millisecond))
	unexpected, e := origin.AcceptTCP()
	if e == nil {
		unexpected.Close()
		t.Fatal("wrong UUID reached origin")
	}
	if timeout, ok := e.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("origin refusal observation failed", e)
	}
	_ = origin.SetDeadline(time.Time{})
	if !svc.kernel.IsRunning() {
		t.Fatal("unauthenticated refusal stopped healthy Service")
	}

	request := bytes.Repeat([]byte("u"), 43)
	response := bytes.Repeat([]byte("D"), 79)
	originResult := make(chan error, 1)
	originRequest := make(chan []byte, 1)
	responseReady := make(chan struct{})
	go func() {
		conn, e := origin.AcceptTCP()
		if e != nil {
			originResult <- e
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		got := make([]byte, len(request))
		if _, e = io.ReadFull(conn, got); e != nil {
			originResult <- e
			return
		}
		originRequest <- got
		if !bytes.Equal(got, request) {
			originResult <- errors.New("origin decoded request mismatch")
			return
		}
		if n, e := conn.Write(response); n != len(response) || e != nil {
			originResult <- errors.New("origin response write incomplete")
			return
		}
		close(responseReady)
		var extra [1]byte
		if n, e := conn.Read(extra[:]); n != 0 || e != io.EOF {
			originResult <- fmt.Errorf("upload EOF incomplete: n=%d err=%v", n, e)
			return
		}
		if e := conn.CloseWrite(); e != nil {
			originResult <- e
			return
		}
		originResult <- nil
	}()
	raw, client := liveProtocolDial(t, fixture.Protocol, nodeAddress, liveProtocolUUID, destination)
	defer raw.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(20 * time.Second))
	if n, e := client.Write(request); n != len(request) || e != nil {
		t.Fatal("actual client request incomplete", n, e)
	}
	gotResponse := make([]byte, len(response))
	if _, e := io.ReadFull(client, gotResponse); e != nil || !bytes.Equal(gotResponse, response) {
		t.Fatal("client decoded response mismatch", e)
	}
	gotRequest := <-originRequest
	<-responseReady

	// Keep the actual protocol session idle through the production report ticker.
	// The observer records native Core responses; no manual report call is made.
	var heartbeat json.RawMessage
	liveProtocolWait(t, done, 10*time.Second, func() bool { heartbeat = liveProtocolHeartbeat(t, dir, startedAt); return len(heartbeat) > 0 })
	if !svc.kernel.IsRunning() {
		t.Fatal("Service stopped before scheduled heartbeat")
	}
	if svc.tracker.HasTraffic() {
		t.Fatal("v2 bytes entered legacy traffic tracker")
	}
	if err := raw.CloseWrite(); err != nil {
		t.Fatal("actual TCP upload FIN", err)
	}
	var eof [1]byte
	if n, e := client.Read(eof[:]); n != 0 || e != io.EOF {
		t.Fatal("protocol response EOF incomplete", n, e)
	}
	if err := <-originResult; err != nil {
		t.Fatal(err)
	}
	var captured usagev2.Record
	liveProtocolWait(t, done, 8*time.Second, func() bool {
		files, _ := filepath.Glob(filepath.Join(cfg.UsageV2.Directory, "spool", "*.json"))
		if len(files) != 1 {
			return false
		}
		body, e := os.ReadFile(files[0])
		if e != nil || usagev2.StrictDecode(body, &captured, usagev2.MaxPayloadBytes) != nil {
			return false
		}
		return captured.Validate() == nil && captured.Receipt != nil && captured.Receipt.ReceiptStatus == "persisted"
	})
	if len(captured.Submission.Payload.Entries) != 1 {
		t.Fatal("expected one immutable decoded entry")
	}
	entry := captured.Submission.Payload.Entries[0]
	if entry.RawUpBytes != strconv.Itoa(len(gotRequest)) || entry.RawDownBytes != strconv.Itoa(len(gotResponse)) {
		t.Fatalf("actual decoded count-site mismatch: up=%s/down=%s origin=%d/client=%d", entry.RawUpBytes, entry.RawDownBytes, len(gotRequest), len(gotResponse))
	}
	if svc.tracker.HasTraffic() {
		t.Fatal("legacy tracker contains protocol bytes")
	}
	capture := liveProtocolCapture{Session: captured.Session, Submission: captured.Submission, Pending: *captured.Receipt, Protocol: fixture.Protocol, RequestBytes: len(gotRequest), ResponseBytes: len(gotResponse), RequestSHA256: liveProtocolSHA(gotRequest), ResponseSHA256: liveProtocolSHA(gotResponse), Heartbeat: heartbeat, Listener: nodeAddress, ActualService: true, ActualKernel: true, WrongUUIDRejected: true, NativeTrafficAbsent: true}
	// Snapshot must precede shutdown: the batch and heartbeat already exist.
	liveProtocolWrite(t, filepath.Join(dir, "live-capture.json"), capture)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("normal Service stop", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Service shutdown timed out")
	}
	if svc.kernel.IsRunning() {
		t.Fatal("listener survived normal stop")
	}
}

func liveProtocolVerifySettled(t *testing.T, dir string, cfg *config.Config) {
	var capture liveProtocolCapture
	liveProtocolDecode(t, filepath.Join(dir, "live-capture.json"), &capture)
	cp := controlplane.NewTXBoardControlPlane(cfg.Panel, cfg.WS, cfg.Kernel)
	if err := cp.PrepareIsolatedUsageV2(cfg.UsageV2.CAFile); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := cp.Initial(context.Background(), nil, nil, nil)
	if err != nil || bootstrap.UsageV2Transport == nil {
		t.Fatal("native settled transport unavailable", err)
	}
	spool, err := usagev2.OpenSpool(filepath.Join(cfg.UsageV2.Directory, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := usagev2.NewReporter(capture.Session, spool, bootstrap.UsageV2Transport)
	if err != nil {
		spool.Close()
		t.Fatal(err)
	}
	if err := reporter.Deliver(context.Background()); err != nil {
		reporter.Close()
		t.Fatal(err)
	}
	records, err := spool.Records()
	if err != nil || len(records) != 1 || records[0].Receipt == nil || records[0].Receipt.SettlementStatus != "settled" || records[0].Receipt.ReceiptID != capture.Pending.ReceiptID {
		reporter.Close()
		t.Fatal("settled receipt changed identity")
	}
	duplicate, err := bootstrap.UsageV2Transport.Submit(context.Background(), capture.Submission)
	if err != nil || duplicate.ReceiptID != capture.Pending.ReceiptID || duplicate.SettlementStatus != "settled" {
		reporter.Close()
		t.Fatal("stable duplicate replay failed", err)
	}
	changed := capture.Submission
	changed.Payload.Entries = append([]usagev2.Entry(nil), changed.Payload.Entries...)
	changed.Payload.Entries[0].RawUpBytes = "44"
	canonical, err := json.Marshal(changed.Payload)
	if err != nil {
		t.Fatal(err)
	}
	changed.PayloadDigest = "sha256:" + liveProtocolSHA(canonical)
	_, conflict := bootstrap.UsageV2Transport.Submit(context.Background(), changed)
	var httpErr *usagev2.HTTPError
	if !errors.As(conflict, &httpErr) || httpErr.Status != 409 || !errors.Is(conflict, usagev2.ErrPayloadConflict) {
		reporter.Close()
		t.Fatal("changed original batch did not produce real conflict", conflict)
	}
	settled := *records[0].Receipt
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	// The same source epoch cannot create a fresh collector after recovery.
	restart, err := NewChecked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := restart.Run(ctx); err == nil || restart.kernel.IsRunning() {
		t.Fatal("same epoch live restart was admitted")
	}
	liveProtocolWrite(t, filepath.Join(dir, "live-settled.json"), map[string]any{"capture": capture, "settled_receipt": settled, "duplicate_receipt": duplicate, "changed_original_batch_status": httpErr.Status, "same_epoch_restart_refused": true, "production_authorization": false})
}

func liveProtocolDial(t *testing.T, protocol, address, uuid string, destination M.Socksaddr) (*net.TCPConn, net.Conn) {
	t.Helper()
	dialer := net.Dialer{Timeout: 2 * time.Second}
	socket, err := dialer.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := socket.(*net.TCPConn)
	if !ok {
		socket.Close()
		t.Fatal("non-TCP fixture client")
	}
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	var conn net.Conn
	if protocol == "vless" {
		client, e := vless.NewClient(uuid, "", logger.NOP())
		if e != nil {
			raw.Close()
			t.Fatal(e)
		}
		conn, err = client.DialConn(raw, destination)
	} else {
		client, e := vmess.NewClient(uuid, "aes-128-gcm", 0)
		if e != nil {
			raw.Close()
			t.Fatal(e)
		}
		conn, err = client.DialConn(raw, destination)
	}
	if err != nil {
		raw.Close()
		t.Fatal("locked protocol DialConn", err)
	}
	return raw, conn
}
func liveProtocolWait(t *testing.T, done <-chan error, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if ready() {
			return
		}
		select {
		case err := <-done:
			t.Fatal("Service terminated before protocol evidence", err)
		case <-deadline.C:
			t.Fatal("live protocol evidence timeout")
		case <-tick.C:
		}
	}
}
func liveProtocolHeartbeat(t *testing.T, dir string, started time.Time) json.RawMessage {
	t.Helper()
	file, err := os.Open(filepath.Join(dir, "native-observations.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		var record struct {
			Path     string  `json:"path"`
			Status   int     `json:"status"`
			Accepted bool    `json:"accepted"`
			Version  int     `json:"protocol_version"`
			Traffic  bool    `json:"traffic_present"`
			Batch    bool    `json:"traffic_batch_present"`
			Started  float64 `json:"started_at"`
		}
		line := scanner.Bytes()
		if json.Unmarshal(line, &record) != nil {
			continue
		}
		if record.Path != "/txapi/node/v1/report" {
			continue
		}
		if record.Traffic || record.Batch {
			t.Fatal("actual native report carried legacy traffic")
		}
		if record.Started >= float64(started.UnixNano())/1e9+4.5 && record.Status == 202 && record.Accepted && record.Version == 1 {
			return append(json.RawMessage(nil), line...)
		}
	}
	if scanner.Err() != nil {
		t.Fatal(scanner.Err())
	}
	return nil
}
func liveProtocolCheckListener(t *testing.T, port int) {
	t.Helper()
	match := fmt.Sprintf("%04X", port)
	found := false
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("Linux actual listener inspection", err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			address := strings.Split(fields[1], ":")
			if len(address) != 2 || address[1] != match {
				continue
			}
			if path != "/proc/net/tcp" || address[0] != "0100007F" {
				t.Fatal("isolated listener was not exclusively IPv4 loopback", fields[1])
			}
			found = true
		}
	}
	if !found {
		t.Fatal("actual live listener missing")
	}
}
func liveProtocolDecode(t *testing.T, path string, target any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || len(body) > 1<<20 || json.Unmarshal(body, target) != nil {
		t.Fatal("bounded fixture metadata unavailable", path, err)
	}
}
func liveProtocolWrite(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
func liveProtocolSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
