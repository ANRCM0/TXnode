package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
	M "github.com/sagernet/sing/common/metadata"
)

type revocationFlow struct {
	raw        *net.TCPConn
	client     net.Conn
	originDone chan error
	extra      atomic.Int64
	request    []byte
	response   []byte
}

// The kernel, native controlplane, tickers and collector are production-owned.
// Files are lifecycle barriers only; none provides raw counters or fake grants.
func TestServiceUsageV2LiveRevocation(t *testing.T) {
	dir := os.Getenv("TXBOARD_LIVE_REVOCATION_DIR")
	if dir == "" {
		t.Skip("requires exclusive live revocation Core fixture")
	}
	var fixture liveProtocolFixture
	liveProtocolDecode(t, filepath.Join(dir, "fixture.json"), &fixture)
	id, err := strconv.Atoi(fixture.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	caseName := os.Getenv("TXBOARD_LIVE_REVOCATION_CASE")
	cfg := &config.Config{InstanceID: "live-revocation-" + fixture.Protocol, Panel: config.PanelConfig{Provider: "txboard", URL: os.Getenv("TXBOARD_LIVE_REVOCATION_ENDPOINT"), NodeID: id, Token: "live-revocation-local-test-only"}, Kernel: config.KernelConfig{Type: "singbox", ConfigDir: filepath.Join(dir, "kernel"), LogLevel: "error", CustomRoute: []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{fixture.OriginPort}, "outbound": "direct"}}}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, PushInterval: 5, PullInterval: 1, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}, UsageV2: config.UsageV2Config{Enabled: true, IsolatedCopy: true, Directory: filepath.Join(dir, "mode"), CAFile: filepath.Join(dir, "cert.pem")}}
	if err := os.MkdirAll(cfg.Kernel.ConfigDir, 0700); err != nil {
		t.Fatal(err)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- svc.Run(ctx) }()
	liveProtocolWait(t, done, 12*time.Second, svc.kernel.IsRunning)
	liveProtocolCheckListener(t, fixture.NodePort)
	nodeAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.NodePort))
	dest := M.ParseSocksaddr(net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.OriginPort)))
	if os.Getenv("TXBOARD_LIVE_REVOCATION_PHASE") == "history" {
		flow := revocationExchange(t, origin, fixture.Protocol, nodeAddr, dest, 43, 79)
		if err := flow.raw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		var eof [1]byte
		if n, e := flow.client.Read(eof[:]); n != 0 || e != io.EOF {
			t.Fatal("history real protocol EOF", n, e)
		}
		if err := <-flow.originDone; err != nil {
			t.Fatal(err)
		}
		flow.client.Close()
		flow.raw.Close()
		var record usagev2.Record
		liveProtocolWait(t, done, 8*time.Second, func() bool { return revocationRecord(cfg.UsageV2.Directory, &record) && record.Receipt != nil })
		entry := record.Submission.Payload.Entries[0]
		if entry.RawUpBytes != "43" || entry.RawDownBytes != "79" {
			t.Fatal("real history directions changed")
		}
		var heartbeat json.RawMessage
		liveProtocolWait(t, done, 8*time.Second, func() bool { heartbeat = liveProtocolHeartbeat(t, dir, started); return len(heartbeat) > 0 })
		capture := liveProtocolCapture{Session: record.Session, Submission: record.Submission, Pending: *record.Receipt, Protocol: fixture.Protocol, RequestBytes: 43, ResponseBytes: 79, RequestSHA256: liveProtocolSHA(flow.request), ResponseSHA256: liveProtocolSHA(flow.response), Heartbeat: heartbeat, Listener: nodeAddr, ActualService: true, ActualKernel: true, NativeTrafficAbsent: true}
		liveProtocolWrite(t, filepath.Join(dir, "history-capture.json"), capture)
		liveProtocolWrite(t, filepath.Join(dir, "history-ready.json"), map[string]any{"batch_id": record.Submission.Payload.BatchID, "actual_service_live": true})
		liveProtocolWait(t, done, 12*time.Second, func() bool {
			return revocationRecord(cfg.UsageV2.Directory, &record) && record.Receipt != nil && record.Receipt.SettlementStatus == "settled"
		})
		if caseName == "history" {
			cancel()
			revocationStopped(t, done, false)
			return
		}
	} else if os.Getenv("TXBOARD_LIVE_REVOCATION_PHASE") != "tail" {
		t.Fatal("invalid live revocation phase")
	}

	// A separate live flow has real measured bytes and an unfinished read. The
	// worker must retain that tail, rather than generating a final successful batch.
	tail := revocationExchange(t, origin, fixture.Protocol, nodeAddr, dest, 17, 41)
	defer tail.client.Close()
	defer tail.raw.Close()
	liveProtocolWrite(t, filepath.Join(dir, "tail-ready.json"), map[string]any{"case": caseName, "upload_bytes": 17, "download_bytes": 41, "request_sha256": liveProtocolSHA(tail.request), "response_sha256": liveProtocolSHA(tail.response), "actual_listener": nodeAddr, "opened_at": time.Now().UnixNano(), "service_live": svc.kernel.IsRunning()})
	if caseName == "shutdown" {
		revocationWaitFile(t, done, dir, "trigger.json", 10*time.Second)
		cancel()
		revocationStopped(t, done, false)
	} else if caseName == "ban-baseline" {
		liveProtocolWait(t, done, 8*time.Second, func() bool { return revocationEmptyPoll(dir) })
		// Wait through further genuine polls after the native sole-user removal.
		deadline := time.Now().Add(1500 * time.Millisecond)
		for time.Now().Before(deadline) {
			select {
			case err := <-done:
				t.Fatal("baseline unexpectedly stopped", err)
			case <-time.After(25 * time.Millisecond):
			}
		}
		if !svc.kernel.IsRunning() {
			t.Fatal("baseline listener unexpectedly stopped")
		}
		probe := []byte("after-ban")
		if n, e := tail.client.Write(probe); n != len(probe) || e != nil {
			t.Fatal("baseline continued stream probe", n, e)
		}
		liveProtocolWait(t, done, 2*time.Second, func() bool { return tail.extra.Load() == int64(len(probe)) })
		liveProtocolWrite(t, filepath.Join(dir, "baseline-ignored-empty.json"), map[string]any{"native_users200_empty_observed": true, "service_still_running": true, "postban_origin_bytes": tail.extra.Load(), "postban_probe_sha256": liveProtocolSHA(probe), "case": "ban-baseline", "production_authorization": false})
		cancel()
		revocationStopped(t, done, false)
		t.Fatal("LIVE_REVOCATION_EMPTY_USERS_IGNORED_REAL_PROTOCOL")
	} else {
		revocationStopped(t, done, true)
	}
	if svc.kernel.IsRunning() {
		t.Fatal("actual listener remained after boundary")
	}
	// The origin must observe actual connection termination. Buffered local writes
	// are not accepted as evidence that the origin received post-stop bytes.
	select {
	case err := <-tail.originDone:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal("tail origin termination", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin live tail not closed")
	}
	if tail.extra.Load() != 0 {
		t.Fatal("unexpected post-trigger origin bytes", tail.extra.Load())
	}
	if svc.tracker.HasTraffic() {
		t.Fatal("unknown v2 tail entered native traffic tracker")
	}
	var historical usagev2.Record
	if !revocationRecord(cfg.UsageV2.Directory, &historical) || historical.Receipt == nil || historical.Receipt.SettlementStatus != "settled" {
		t.Fatal("settled original history missing")
	}
	if historical.Submission.Payload.Entries[0].RawUpBytes != "43" || historical.Submission.Payload.Entries[0].RawDownBytes != "79" {
		t.Fatal("history mutated by tail")
	}
	liveProtocolWrite(t, filepath.Join(dir, "boundary-result.json"), map[string]any{"case": caseName, "protocol": fixture.Protocol, "actual_service_run": true, "actual_kernel": "sing-box", "listener_closed": true, "origin_connection_closed": true, "unknown_tail_upload_bytes": 17, "unknown_tail_download_bytes": 41, "unknown_tail_successful_batch": false, "legacy_traffic_absent": true, "historical_batch": historical.Submission.Payload.BatchID, "historical_receipt": historical.Receipt.ReceiptID, "production_authorization": false})
}

func revocationExchange(t *testing.T, origin *net.TCPListener, protocol, nodeAddr string, dest M.Socksaddr, up, down int) *revocationFlow {
	t.Helper()
	flow := &revocationFlow{originDone: make(chan error, 1), request: bytes.Repeat([]byte("u"), up), response: bytes.Repeat([]byte("D"), down)}
	ready := make(chan error, 1)
	go func() {
		conn, err := origin.AcceptTCP()
		if err != nil {
			ready <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		request := make([]byte, up)
		if _, err := io.ReadFull(conn, request); err != nil {
			ready <- err
			return
		}
		if !bytes.Equal(request, flow.request) {
			ready <- errors.New("origin decoded request mismatch")
			return
		}
		if n, e := conn.Write(flow.response); n != down || e != nil {
			ready <- errors.New("origin response incomplete")
			return
		}
		ready <- nil
		buffer := make([]byte, 128)
		for {
			n, e := conn.Read(buffer)
			if n > 0 {
				flow.extra.Add(int64(n))
			}
			if e != nil {
				if e == io.EOF {
					e = conn.CloseWrite()
				}
				flow.originDone <- e
				return
			}
		}
	}()
	flow.raw, flow.client = liveProtocolDial(t, protocol, nodeAddr, liveProtocolUUID, dest)
	if n, e := flow.client.Write(flow.request); n != up || e != nil {
		t.Fatal("actual request incomplete", n, e)
	}
	got := make([]byte, down)
	if _, e := io.ReadFull(flow.client, got); e != nil || !bytes.Equal(got, flow.response) {
		t.Fatal("actual response mismatch", e)
	}
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin readiness timeout")
	}
	return flow
}
func revocationRecord(modeDir string, record *usagev2.Record) bool {
	files, _ := filepath.Glob(filepath.Join(modeDir, "spool", "*.json"))
	if len(files) != 1 {
		return false
	}
	body, e := os.ReadFile(files[0])
	return e == nil && usagev2.StrictDecode(body, record, usagev2.MaxPayloadBytes) == nil && record.Validate() == nil
}
func revocationStopped(t *testing.T, done <-chan error, wantFailure bool) {
	t.Helper()
	select {
	case err := <-done:
		if wantFailure != (err != nil) {
			t.Fatal("unexpected actual Service boundary outcome", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("actual Service failed to stop on boundary")
	}
}
func revocationWaitFile(t *testing.T, done <-chan error, dir, name string, timeout time.Duration) {
	t.Helper()
	liveProtocolWait(t, done, timeout, func() bool { _, e := os.Stat(filepath.Join(dir, name)); return e == nil })
}
func revocationEmptyPoll(dir string) bool {
	body, e := os.ReadFile(filepath.Join(dir, "native-observations.jsonl"))
	if e != nil {
		return false
	}
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		var observation struct {
			Path   string `json:"path"`
			Status int    `json:"status"`
			Count  *int   `json:"user_count"`
		}
		if json.Unmarshal(line, &observation) == nil && observation.Path == "/txapi/node/v1/users" && observation.Status == 200 && observation.Count != nil && *observation.Count == 0 {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf
