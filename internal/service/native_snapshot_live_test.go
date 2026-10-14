package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/panel"
	M "github.com/sagernet/sing/common/metadata"
)

const snapshotSecondUUID = "ffeeddcc-bbaa-4998-8776-554433221100"

type snapshotLiveHTTP struct {
	mu                sync.Mutex
	protocol          string
	port              int
	configVersion     int
	usersVersion      int
	users             []panel.User
	failUsers         int
	blockNextUsers    chan struct{}
	blocked           chan struct{}
	requested         chan string
	conditionalConfig chan struct{}
	conditionalUsers  chan struct{}
}

func (f *snapshotLiveHTTP) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer snapshot-local-test-only" || r.Header.Get("X-TX-Node-ID") != "42" {
		w.WriteHeader(401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	switch r.URL.Path {
	case "/txapi/node/v1/handshake":
		f.mu.Unlock()
		snapshotEnvelope(w, map[string]any{"protocol_version": 1, "node_id": 42, "mode": "node", "websocket": map[string]any{"enabled": false}, "settings": map[string]any{"push_interval": 60, "pull_interval": 1}})
	case "/txapi/node/v1/config":
		port, version, protocol := f.port, f.configVersion, f.protocol
		f.mu.Unlock()
		tag := fmt.Sprintf(`"config-%d"`, version)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(304)
			select {
			case f.conditionalConfig <- struct{}{}:
			default:
			}
			return
		}
		w.Header().Set("ETag", tag)
		snapshotEnvelope(w, map[string]any{"protocol_version": 1, "node_id": 42, "config": panel.NodeConfig{Protocol: protocol, ListenIP: "127.0.0.1", ServerPort: port}})
	case "/txapi/node/v1/users":
		users, version := append([]panel.User{}, f.users...), f.usersVersion
		fail := f.failUsers > 0
		if fail {
			f.failUsers--
		}
		block := f.blockNextUsers
		blocked := f.blocked
		f.blockNextUsers = nil
		f.mu.Unlock()
		if block != nil {
			close(blocked)
			select {
			case <-block:
			case <-r.Context().Done():
				return
			}
		}
		if fail {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"code":"TEST_TEMPORARY","message":"synthetic"},"request_id":"snapshot-failure"}`))
			select {
			case f.requested <- "users503":
			default:
			}
			return
		}
		tag := fmt.Sprintf(`"users-%d"`, version)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(304)
			select {
			case f.conditionalUsers <- struct{}{}:
			default:
			}
			return
		}
		w.Header().Set("ETag", tag)
		snapshotEnvelope(w, map[string]any{"protocol_version": 1, "node_id": 42, "users": users})
		select {
		case f.requested <- "users200":
		default:
		}
	case "/txapi/node/v1/report":
		f.mu.Unlock()
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(202)
		snapshotEnvelope(w, map[string]any{"protocol_version": 1, "accepted": true, "traffic_batch_id": body["traffic_batch_id"], "settlement": "queued"})
	default:
		f.mu.Unlock()
		w.WriteHeader(404)
	}
}

func snapshotEnvelope(w http.ResponseWriter, data any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "request_id": "snapshot-live-local"})
}

type snapshotLiveRuntime struct {
	service     *Service
	cancel      context.CancelFunc
	done        chan error
	fixture     *snapshotLiveHTTP
	origin      net.Listener
	destination M.Socksaddr
}

func newSnapshotLiveRuntime(t *testing.T, protocol string, port int) *snapshotLiveRuntime {
	t.Helper()
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		for {
			connection, err := origin.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				payload := make([]byte, 4)
				if _, err := io.ReadFull(connection, payload); err == nil {
					_, _ = connection.Write(payload)
				}
			}()
		}
	}()
	fixture := &snapshotLiveHTTP{protocol: protocol, port: port, configVersion: 1, usersVersion: 1,
		users:     []panel.User{{ID: 7, UUID: liveProtocolUUID}, {ID: 8, UUID: snapshotSecondUUID}},
		requested: make(chan string, 64), conditionalConfig: make(chan struct{}, 64), conditionalUsers: make(chan struct{}, 64)}
	server := httptest.NewServer(http.HandlerFunc(fixture.handle))
	t.Cleanup(server.Close)
	directory := filepath.Join(t.TempDir(), "kernel")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	originPort := origin.Addr().(*net.TCPAddr).Port
	cfg := &config.Config{InstanceID: "snapshot-live-" + protocol,
		Panel:  config.PanelConfig{Provider: "txboard", URL: server.URL, NodeID: 42, Token: "snapshot-local-test-only"},
		Kernel: config.KernelConfig{Type: "singbox", ConfigDir: directory, LogLevel: "error", CustomRoute: []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{originPort}, "outbound": "direct"}}},
		Cert:   config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, PushInterval: 60, PullInterval: 1, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}}
	service, err := NewChecked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &snapshotLiveRuntime{service: service, cancel: cancel, done: make(chan error, 1), fixture: fixture, origin: origin, destination: M.ParseSocksaddr(origin.Addr().String())}
	go func() { runtime.done <- service.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runtime.done:
			if err != nil {
				t.Errorf("ordinary Service stop: %v", err)
			}
		case <-time.After(8 * time.Second):
			t.Error("Service cleanup exceeded deadline")
		}
	})
	snapshotWait(t, runtime, 5*time.Second, func() bool { return snapshotListener(port) })
	snapshotEcho(t, protocol, port, liveProtocolUUID, runtime.destination)
	return runtime
}

func snapshotListener(port int) bool {
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 30*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func snapshotWait(t *testing.T, runtime *snapshotLiveRuntime, limit time.Duration, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case err := <-runtime.done:
			runtime.done <- err
			t.Fatalf("Service exited while awaiting live state: %v", err)
		case <-deadline.C:
			t.Fatal("live snapshot condition exceeded deadline")
		}
	}
}

func snapshotEcho(t *testing.T, protocol string, port int, uuid string, destination M.Socksaddr) {
	t.Helper()
	raw, stream := liveProtocolDial(t, protocol, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), uuid, destination)
	defer raw.Close()
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := stream.Write([]byte("live")); err != nil {
		t.Fatal("real protocol write:", err)
	}
	received := make([]byte, 4)
	if _, err := io.ReadFull(stream, received); err != nil || !bytes.Equal(received, []byte("live")) {
		t.Fatalf("real protocol echo: %q %v", received, err)
	}
}

func snapshotReject(t *testing.T, protocol string, port int, uuid string, destination M.Socksaddr) bool {
	t.Helper()
	raw, stream := liveProtocolDial(t, protocol, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), uuid, destination)
	defer raw.Close()
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := stream.Write([]byte("deny")); err != nil {
		return true
	}
	reply := make([]byte, 4)
	_, err := io.ReadFull(stream, reply)
	return err != nil
}

func snapshotAwaitRequest(t *testing.T, runtime *snapshotLiveRuntime, expected string) {
	t.Helper()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case value := <-runtime.fixture.requested:
			if value == expected {
				return
			}
		case err := <-runtime.done:
			runtime.done <- err
			t.Fatalf("Service stopped before %s: %v", expected, err)
		case <-deadline.C:
			t.Fatalf("HTTP request %s not observed", expected)
		}
	}
}

func TestNativeSnapshotLiveConfigSurvivesUsersFailureAnd304(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			portA, portB := authorityPort(t), authorityPort(t)
			runtime := newSnapshotLiveRuntime(t, protocol, portA)
			fixture := runtime.fixture
			fixture.mu.Lock()
			fixture.port = portB
			fixture.configVersion++
			fixture.usersVersion++
			fixture.failUsers = 1
			fixture.mu.Unlock()
			snapshotAwaitRequest(t, runtime, "users503")
			snapshotWait(t, runtime, 8*time.Second, func() bool { return snapshotListener(portB) && !snapshotListener(portA) })
			select {
			case <-fixture.conditionalConfig:
			default:
				t.Fatal("new cached config not redelivered through304")
			}
			snapshotEcho(t, protocol, portB, liveProtocolUUID, runtime.destination)
			snapshotEcho(t, protocol, portB, snapshotSecondUUID, runtime.destination)
		})
	}
}

func TestNativeSnapshotLiveOccupiedPortRetriesSameDesiredConfig(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			occupied, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			portB := occupied.Addr().(*net.TCPAddr).Port
			portA := authorityPort(t)
			runtime := newSnapshotLiveRuntime(t, protocol, portA)
			fixture := runtime.fixture
			fixture.mu.Lock()
			fixture.port = portB
			fixture.configVersion++
			fixture.usersVersion++
			fixture.mu.Unlock()
			snapshotWait(t, runtime, 6*time.Second, func() bool {
				runtime.service.metricsMu.RLock()
				defer runtime.service.metricsMu.RUnlock()
				return runtime.service.applicationFailure != ""
			})
			if err := occupied.Close(); err != nil {
				t.Fatal(err)
			}
			snapshotWait(t, runtime, 7*time.Second, func() bool { return snapshotListener(portB) && !snapshotListener(portA) })
			snapshotEcho(t, protocol, portB, liveProtocolUUID, runtime.destination)
			select {
			case <-fixture.conditionalConfig:
			default:
				t.Fatal("identical config did not retry through304")
			}
		})
	}
}

func TestNativeSnapshotLiveDelayedPollCannotReviveWSRemovedUUID(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			port := authorityPort(t)
			runtime := newSnapshotLiveRuntime(t, protocol, port)
			fixture := runtime.fixture
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			fixture.mu.Lock()
			fixture.usersVersion++
			fixture.blockNextUsers = release
			fixture.blocked = make(chan struct{})
			blocked := fixture.blocked
			fixture.mu.Unlock()
			select {
			case <-blocked:
			case <-time.After(5 * time.Second):
				t.Fatal("old poll did not enter users handler")
			}
			// This exercises the production main-loop event queue boundary. It
			// does not attest a real Workerman/websocket transport deployment.
			runtime.service.push.EventSink() <- controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 7, UUID: liveProtocolUUID}}}
			snapshotWait(t, runtime, 4*time.Second, func() bool { return snapshotReject(t, protocol, port, liveProtocolUUID, runtime.destination) })
			snapshotEcho(t, protocol, port, snapshotSecondUUID, runtime.destination)
			reconcileRelease := make(chan struct{})
			defer func() {
				select {
				case <-reconcileRelease:
				default:
					close(reconcileRelease)
				}
			}()
			fixture.mu.Lock()
			fixture.users = []panel.User{{ID: 8, UUID: snapshotSecondUUID}}
			fixture.usersVersion++
			fixture.blockNextUsers = reconcileRelease
			fixture.blocked = make(chan struct{})
			reconcileBlocked := fixture.blocked
			fixture.mu.Unlock()
			close(release)
			select {
			case <-reconcileBlocked:
			case <-time.After(5 * time.Second):
				t.Fatal("discarded stale poll did not reconcile")
			}
			// The first HTTP handler captured both users before the removal and
			// has now completed. Hold the fresh response so it cannot hide any
			// stale re-add by immediately removing that user again.
			if !snapshotReject(t, protocol, port, liveProtocolUUID, runtime.destination) {
				t.Fatal("completed old poll restored a removed UUID before reconciliation")
			}
			current := runtime.service.users.Users()
			if len(current) != 1 || current[0].ID != 8 {
				t.Fatalf("stale poll replaced newer desired users: %#v", current)
			}
			close(reconcileRelease)
			snapshotWait(t, runtime, 7*time.Second, func() bool {
				runtime.service.metricsMu.RLock()
				defer runtime.service.metricsMu.RUnlock()
				return runtime.service.appliedUserHash == computeUserHash([]model.UserSpec{{ID: 8, UUID: snapshotSecondUUID}})
			})
			snapshotEcho(t, protocol, port, snapshotSecondUUID, runtime.destination)
			fixture.mu.Lock()
			fixture.users = []panel.User{}
			fixture.usersVersion++
			fixture.mu.Unlock()
			snapshotWait(t, runtime, 7*time.Second, func() bool { return !snapshotListener(port) })
		})
	}
}
