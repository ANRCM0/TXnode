package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

func TestNativePendingOnlyPeriodRecoveryBlocksRealListenerUntilOriginalBatchAcknowledged(t *testing.T) {
	for _, reject := range []int{503, 401} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			port := authorityPort(t)
			var mu sync.Mutex
			status := reject
			reports := []controlplane.ReportPayload{}
			listenerDuringReplay := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer period-recovery-test" || r.Header.Get("X-TX-Node-ID") != "42" {
					t.Error("native configured request identity missing")
				}
				switch r.URL.Path {
				case "/txapi/node/v1/handshake":
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"protocol_version": 1, "node_id": 42, "mode": "node", "websocket": map[string]any{"enabled": false}, "settings": map[string]any{"push_interval": 60, "pull_interval": 60}}})
				case "/txapi/node/v1/config":
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"protocol_version": 1, "node_id": 42, "config": map[string]any{"protocol": "vless", "server_port": port, "listen_ip": "127.0.0.1", "tls": 0}}})
				case "/txapi/node/v1/users":
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"protocol_version": 1, "node_id": 42, "users": []map[string]any{{"id": 7, "uuid": liveProtocolUUID, "traffic_period": "opaque-current"}}}})
				case "/txapi/node/v1/report":
					var body struct {
						ID       string                 `json:"traffic_batch_id"`
						Traffic  map[int][2]int64       `json:"traffic"`
						Segments []model.TrafficSegment `json:"traffic_segments"`
					}
					if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
						t.Error(e)
					}
					connection, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 20*time.Millisecond)
					mu.Lock()
					if e == nil {
						listenerDuringReplay = true
						connection.Close()
					}
					reports = append(reports, controlplane.ReportPayload{BatchID: body.ID, Traffic: body.Traffic, TrafficSegments: body.Segments})
					code := status
					mu.Unlock()
					w.WriteHeader(code)
					if code == 202 {
						_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"protocol_version": 1, "accepted": true, "traffic_batch_id": body.ID, "settlement": "queued", "receipt_status": "persisted", "receipt_id": "1"}})
					} else {
						_ = json.NewEncoder(w).Encode(map[string]any{"request_id": "synthetic-report-error", "error": map[string]any{"code": "NODE_UNAUTHORIZED", "message": "refused"}})
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			cfg := &config.Config{InstanceID: "period-pending-only", Panel: config.PanelConfig{Provider: "txboard", URL: server.URL, NodeID: 42, Token: "period-recovery-test"}, Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 60, PullInterval: 60, PushInterval: 60, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}}
			seed, e := NewChecked(cfg)
			if e != nil {
				t.Fatal(e)
			}
			old := []model.TrafficSegment{{UserID: 7, Period: "opaque-old", Upload: 13, Download: 17}}
			if e := seed.reporter.PushSync(func() reporting.Batch {
				return reporting.Batch{Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{7: {13, 17}}, TrafficSegments: old}}
			}); e == nil {
				t.Fatal("pending creation unexpectedly acknowledged")
			}
			original, e := os.ReadFile(seed.legacyPendingPath)
			if e != nil {
				t.Fatal(e)
			}
			if seed.reporter.HasTerminalTail() {
				t.Fatal("test must exercise pending-only recovery")
			}
			blocked, e := NewChecked(cfg)
			if e != nil {
				t.Fatal(e)
			}
			if e := blocked.Run(context.Background()); e == nil {
				t.Fatal("failed report replay allowed Service admission")
			}
			if blocked.kernel.IsRunning() {
				t.Fatal("real kernel running before recovery ack")
			}
			retained, e := os.ReadFile(seed.legacyPendingPath)
			if e != nil || !bytes.Equal(retained, original) {
				t.Fatal("failed recovery mutated original spool body")
			}
			mu.Lock()
			status = 202
			mu.Unlock()
			fresh, e := NewChecked(cfg)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- fresh.Run(ctx) }()
			authorityWaitListener(t, port)
			mu.Lock()
			if listenerDuringReplay || len(reports) != 3 || reports[0].BatchID != reports[1].BatchID || reports[1].BatchID != reports[2].BatchID || len(reports[2].TrafficSegments) != 1 || reports[2].TrafficSegments[0] != old[0] {
				mu.Unlock()
				cancel()
				t.Fatal("pending-only fresh authority/replay/listener order wrong", reports)
			}
			mu.Unlock()
			cancel()
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cleanup")
			}
		})
	}
}
