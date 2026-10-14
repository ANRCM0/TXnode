package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	M "github.com/sagernet/sing/common/metadata"
)

type trafficCoreLiveUser struct {
	ID    int    `json:"id"`
	UUID  string `json:"uuid"`
	Quota int64  `json:"quota"`
}
type trafficCoreLiveFixture struct {
	NodeID     int                   `json:"node_id"`
	Protocol   string                `json:"protocol"`
	NodePort   int                   `json:"node_port"`
	OriginPort int                   `json:"origin_port"`
	Users      []trafficCoreLiveUser `json:"users"`
}

// Ordinary production Service with real trusted Core HTTP/WSS, asynchronous
// queue worker and actual decoded protocol bytes. No fabricated traffic maps.
func TestNativeCoreTrafficLive(t *testing.T) {
	directory := os.Getenv("TXBOARD_NATIVE_TRAFFIC_DIR")
	if directory == "" {
		t.Skip("requires dedicated native traffic Core/Workerman/Redis-worker fixture")
	}
	if os.Getenv("TXBOARD_NATIVE_TRAFFIC_URL") == "" || os.Getenv("SSL_CERT_FILE") == "" {
		t.Fatal("trusted traffic endpoint required")
	}
	var fixture trafficCoreLiveFixture
	trafficCoreDecode(t, filepath.Join(directory, "fixture.json"), &fixture)
	if fixture.NodeID <= 0 || len(fixture.Users) != 2 || (fixture.Protocol != "vless" && fixture.Protocol != "vmess") || fixture.NodePort < 1024 || fixture.OriginPort < 1024 {
		t.Fatal("invalid actual traffic fixture")
	}
	origin, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.OriginPort)))
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	connections := map[net.Conn]struct{}{}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = origin.Close()
		mu.Lock()
		for c := range connections {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := origin.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			connections[c] = struct{}{}
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(connections, c); mu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(150 * time.Second))
				for {
					var first [1]byte
					if _, e := io.ReadFull(c, first[:]); e != nil {
						return
					}
					up, down := 0, 0
					switch first[0] {
					case 'a':
						up, down = 43, 79
					case 'q':
						up, down = 4096, 8192
					case 's':
						up, down = 37, 19
					case 'r':
						up, down = 17, 29
					case 'k':
						up, down = 23, 31
					case 'f':
						up, down = 41, 53
					case 'h':
						up, down = 59, 61
					case 'g':
						up, down = 67, 71
					default:
						return
					}
					remaining := make([]byte, up-1)
					if _, e := io.ReadFull(c, remaining); e != nil || !bytes.Equal(remaining, bytes.Repeat(first[:], up-1)) {
						return
					}
					if _, e := c.Write(bytes.Repeat(first[:], down)); e != nil {
						return
					}
				}
			}()
		}
	}()
	cfg := &config.Config{InstanceID: "actual-native-traffic-" + fixture.Protocol, Panel: config.PanelConfig{Provider: "txboard", URL: os.Getenv("TXBOARD_NATIVE_TRAFFIC_URL"), NodeID: fixture.NodeID, Token: "native-traffic-local-test-only"}, Kernel: config.KernelConfig{Type: "singbox", ConfigDir: filepath.Join(directory, "kernel"), LogLevel: "error"}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, PushInterval: 5, PullInterval: 1, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60, HandshakeTimeout: 5, BackoffInitial: 1, BackoffMax: 3}}
	if e := os.MkdirAll(cfg.Kernel.ConfigDir, 0700); e != nil {
		t.Fatal(e)
	}
	svc, e := NewChecked(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Errorf("traffic Service stop: %v", e)
			}
		case <-time.After(8 * time.Second):
			t.Error("traffic Service cleanup timeout")
		}
	})
	liveProtocolWait(t, done, 8*time.Second, func() bool { return snapshotListener(fixture.NodePort) })
	destination := M.ParseSocksaddr(origin.Addr().String())
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.NodePort))
	dial := func(user trafficCoreLiveUser) net.Conn {
		raw, stream := liveProtocolDial(t, fixture.Protocol, address, user.UUID, destination)
		t.Cleanup(func() { raw.Close(); stream.Close() })
		return stream
	}
	initialPeriod := trafficCoreObservedPeriod(t, svc, fixture.Users[0].ID)
	if os.Getenv("TXBOARD_NATIVE_TRAFFIC_PHASE") == "resume" {
		// This is a distinct OS process using the exact persisted pending body.
		// Do not generate any new protocol traffic before that body is replayed.
		trafficCoreAwaitAck(t, directory, "initial-bytes")
	} else if os.Getenv("TXBOARD_NATIVE_TRAFFIC_PHASE") == "capture" {
		first := dial(fixture.Users[0])
		trafficCoreExchange(t, first, 'a', 43, 79)
		trafficCoreBarrier(t, directory, "initial-bytes", map[string]any{"actual_request_bytes": 43, "actual_response_bytes": 79, "protocol": fixture.Protocol, "observed_period": initialPeriod, "observed_epoch": trafficCoreEpoch(t, initialPeriod)})
		t.Fatal("capture process was expected to terminate at the runner SIGKILL boundary")
	} else {
		t.Fatal("explicit capture or resumed OS process phase required")
	}
	// Runner has now observed first durable acceptance, lost its actual ACK,
	// frozen rate1.5 before rate2.5 update, replayed same ID and recovered SQL.
	sibling := dial(fixture.Users[1])
	trafficCoreExchange(t, sibling, 's', 37, 19)
	quota := dial(fixture.Users[0])
	trafficCoreExchange(t, quota, 'q', 4096, 8192)
	trafficCoreBarrier(t, directory, "quota-bytes", map[string]any{"actual_primary_upload": 4096, "actual_primary_download": 8192, "actual_sibling_upload": 37, "actual_sibling_download": 19})
	trafficCoreClosed(t, quota)
	if !snapshotReject(t, fixture.Protocol, fixture.NodePort, fixture.Users[0].UUID, destination) {
		t.Fatal("quota-exhausted UUID still authenticated")
	}
	trafficCoreExchange(t, sibling, 's', 37, 19)
	trafficCoreBarrier(t, directory, "quota-enforced", map[string]any{"actual_old_streams_closed": true, "quota_uuid_rejected": true, "existing_sibling_stream_continued": true})
	// A reset first advances desired users, then reconstructs the listener.
	// Admit the test connection only after that exact new period is applied.
	epoch1 := trafficCoreWaitNextPeriod(t, svc, done, fixture.Users[0].ID, initialPeriod, 1)
	restored := dial(fixture.Users[0])
	trafficCoreExchange(t, restored, 'r', 17, 29)
	trafficCoreBarrier(t, directory, "reset-bytes", map[string]any{"actual_upload": 17, "actual_download": 29, "fresh_protocol_authentication": true})
	trafficCoreBarrier(t, directory, "queued-late-start", map[string]any{"observed_epoch": 1, "observed_period": epoch1})
	trafficCoreExchange(t, restored, 'k', 23, 31)
	trafficCoreBarrier(t, directory, "queued-late-bytes", map[string]any{"upload": 23, "download": 31, "observed_period": epoch1})
	trafficCoreClosed(t, restored)
	epoch2 := trafficCoreWaitNextPeriod(t, svc, done, fixture.Users[0].ID, epoch1, 2)
	queuedFresh := dial(fixture.Users[0])
	trafficCoreExchange(t, queuedFresh, 'f', 41, 53)
	trafficCoreBarrier(t, directory, "queued-fresh-bytes", map[string]any{"upload": 41, "download": 53, "observed_period": epoch2})
	// Admission to Core is held at the network boundary before new bytes exist.
	trafficCoreBarrier(t, directory, "held-report-start", map[string]any{"observed_period": epoch2, "observed_epoch": 2})
	trafficCoreExchange(t, queuedFresh, 'h', 59, 61)
	trafficCoreBarrier(t, directory, "held-old-bytes", map[string]any{"upload": 59, "download": 61, "observed_period": epoch2})
	trafficCoreClosed(t, queuedFresh)
	epoch3 := trafficCoreWaitNextPeriod(t, svc, done, fixture.Users[0].ID, epoch2, 3)
	trafficCoreBarrier(t, directory, "held-new-period", map[string]any{"observed_period": epoch3, "observed_epoch": 3})
	final := dial(fixture.Users[0])
	trafficCoreExchange(t, final, 'g', 67, 71)
	trafficCoreBarrier(t, directory, "held-fresh-bytes", map[string]any{"upload": 67, "download": 71, "observed_period": epoch3})
	trafficCoreWrite(t, filepath.Join(directory, "traffic-live-result.json"), map[string]any{"ordinary_native_service": true, "actual_protocol": fixture.Protocol, "actual_byte_phases": true, "old_quota_streams_closed": true, "unaffected_sibling_stream_continued": true, "reset_fresh_authentication": true, "pending_only_process_restart": true, "signed_observed_reset_epochs": []int{0, 1, 2, 3}, "queued_before_reset_historical_settlement": true, "report_after_reset_historical_settlement": true, "offline_time_lease_proved": false})
}
func trafficCoreExchange(t *testing.T, c net.Conn, character byte, up, down int) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	request := bytes.Repeat([]byte{character}, up)
	if n, e := c.Write(request); e != nil || n != up {
		t.Fatal("actual traffic request", e)
	}
	response := make([]byte, down)
	if _, e := io.ReadFull(c, response); e != nil || !bytes.Equal(response, bytes.Repeat([]byte{character}, down)) {
		t.Fatal("actual traffic response", e)
	}
	_ = c.SetDeadline(time.Now().Add(120 * time.Second))
}
func trafficCoreClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
	var b [1]byte
	n, e := c.Read(b[:])
	if n != 0 || e == nil {
		t.Fatal("quota stream still serving")
	}
	if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		t.Fatal("quota stream timed out instead of closing")
	}
}
func trafficCoreDecode(t *testing.T, path string, value any) {
	t.Helper()
	body, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(body, value); e != nil {
		t.Fatal(e)
	}
}
func trafficCoreWrite(t *testing.T, path string, value any) {
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
		t.Fatal("traffic barrier write", e, closeerr)
	}
	if e := os.Rename(temporary, path); e != nil {
		t.Fatal(e)
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		t.Fatal(e)
	}
	e = d.Sync()
	_ = d.Close()
	if e != nil {
		t.Fatal(e)
	}
}
func trafficCoreBarrier(t *testing.T, directory, stage string, value any) {
	t.Helper()
	trafficCoreWrite(t, filepath.Join(directory, stage+".ready.json"), value)
	trafficCoreAwaitAck(t, directory, stage)
}
func trafficCoreAwaitAck(t *testing.T, directory, stage string) {
	t.Helper()
	deadline := time.NewTimer(50 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, e := os.Stat(filepath.Join(directory, stage+".ack.json")); e == nil {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("traffic runner stage %s timeout", stage)
		}
	}
}

func trafficCoreEpoch(t *testing.T, period string) int {
	t.Helper()
	parts := strings.Split(period, ".")
	if len(parts) != 4 || parts[0] != "p1" {
		t.Fatal("real Core signed period required")
	}
	epoch, err := strconv.Atoi(parts[2])
	if err != nil || epoch < 0 {
		t.Fatal("invalid observed epoch")
	}
	return epoch
}
func trafficCoreObservedPeriod(t *testing.T, svc *Service, userID int) string {
	t.Helper()
	for _, user := range svc.users.Users() {
		if user.ID == userID {
			if user.TrafficPeriod == "" {
				t.Fatal("Core traffic_period missing")
			}
			return user.TrafficPeriod
		}
	}
	t.Fatal("actual authorized user snapshot absent")
	return ""
}
func trafficCoreWaitNextPeriod(t *testing.T, svc *Service, done chan error, userID int, previous string, expected int) string {
	t.Helper()
	var next string
	liveProtocolWait(t, done, 8*time.Second, func() bool {
		users := svc.users.Users()
		for _, user := range users {
			if user.ID == userID && user.TrafficPeriod != previous {
				svc.metricsMu.RLock()
				applied := svc.appliedUserHash == computeUserHash(users) && svc.applicationFailure == ""
				port := 0
				if svc.lastConfig != nil {
					port = svc.lastConfig.ServerPort
				}
				svc.metricsMu.RUnlock()
				// Confirm actual admission after the completed kernel operation,
				// rather than using desired membership as a readiness signal.
				if applied && svc.kernel.IsRunning() && port > 0 && snapshotListener(port) {
					next = user.TrafficPeriod
					return true
				}
			}
		}
		return false
	})
	if trafficCoreEpoch(t, next) != expected {
		t.Fatal("Core issued wrong reset epoch")
	}
	return next
}
