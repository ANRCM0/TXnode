package service

import (
	"bytes"
	"context"
	"encoding/binary"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/panel"
	M "github.com/sagernet/sing/common/metadata"
)

type kernelApplyHTTP struct {
	mu             sync.Mutex
	config         panel.NodeConfig
	users          []panel.User
	revision       int
	usersRevision  int
	configRequests atomic.Int32
}

func (f *kernelApplyHTTP) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer kernel-apply-local-only" || r.Header.Get("X-TX-Node-ID") != "42" {
		w.WriteHeader(401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	cfg, users, revision, usersRevision := f.config, append([]panel.User{}, f.users...), f.revision, f.usersRevision
	f.mu.Unlock()
	switch r.URL.Path {
	case "/txapi/node/v1/handshake":
		snapshotEnvelope(w, map[string]any{"protocol_version": 1, "node_id": 42, "mode": "node", "websocket": map[string]any{"enabled": false}, "settings": map[string]any{"push_interval": 60, "pull_interval": 1}})
	case "/txapi/node/v1/config":
		f.configRequests.Add(1)
		tag := fmt.Sprintf(`"kernel-config-%d"`, revision)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", tag)
		snapshotEnvelope(w, map[string]any{"protocol_version": 1, "node_id": 42, "config": cfg})
	case "/txapi/node/v1/users":
		tag := fmt.Sprintf(`"kernel-users-%d"`, usersRevision)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", tag)
		snapshotEnvelope(w, map[string]any{"protocol_version": 1, "node_id": 42, "users": users})
	case "/txapi/node/v1/report":
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(202)
		snapshotEnvelope(w, map[string]any{"protocol_version": 1, "accepted": true, "traffic_batch_id": body["traffic_batch_id"], "settlement": "queued"})
	default:
		w.WriteHeader(404)
	}
}

type kernelApplyRuntime struct {
	service           *Service
	fixture           *kernelApplyHTTP
	done              chan error
	cancel            context.CancelFunc
	destination       M.Socksaddr
	originConnections atomic.Int32
}

func kernelApplyStart(t *testing.T, kernelType, protocol string, configure func(*panel.NodeConfig, int)) *kernelApplyRuntime {
	t.Helper()
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtime := &kernelApplyRuntime{done: make(chan error, 1), destination: M.ParseSocksaddr(origin.Addr().String())}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		for {
			connection, err := origin.Accept()
			if err != nil {
				return
			}
			runtime.originConnections.Add(1)
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
				buffer := make([]byte, 4096)
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
	port := authorityPort(t)
	cfgBody := panel.NodeConfig{Protocol: protocol, ListenIP: "127.0.0.1", ServerPort: port}
	originPort := origin.Addr().(*net.TCPAddr).Port
	if configure != nil {
		configure(&cfgBody, originPort)
	}
	fixture := &kernelApplyHTTP{config: cfgBody, revision: 1, usersRevision: 1, users: []panel.User{{ID: 7, UUID: liveProtocolUUID}, {ID: 8, UUID: snapshotSecondUUID}}}
	runtime.fixture = fixture
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	directory := filepath.Join(t.TempDir(), "kernel")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{InstanceID: "kernel-apply-" + kernelType + "-" + protocol, Panel: config.PanelConfig{Provider: "txboard", URL: server.URL, NodeID: 42, Token: "kernel-apply-local-only"}, Kernel: config.KernelConfig{Type: kernelType, ConfigDir: directory, LogLevel: "error", CustomRoute: []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{originPort}, "outbound": "direct"}}}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, PushInterval: 60, PullInterval: 1, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}}
	// Local loopback route uses the selected kernel's real raw rule grammar.
	if kernelType == "xray" {
		cfg.Kernel.CustomRoute = []map[string]any{{"type": "field", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": strconv.Itoa(originPort), "outboundTag": "direct"}}
	}
	svc, err := NewChecked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runtime.service = svc
	ctx, cancel := context.WithCancel(context.Background())
	runtime.cancel = cancel
	go func() { runtime.done <- svc.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runtime.done:
			if err != nil {
				t.Errorf("Service cleanup: %v", err)
			}
		case <-time.After(12 * time.Second):
			t.Error("Service did not stop")
		}
	})
	kernelApplyWait(t, runtime, 6*time.Second, func() bool { return snapshotListener(port) })
	snapshotEcho(t, protocol, port, liveProtocolUUID, runtime.destination)
	return runtime
}
func kernelApplyWait(t *testing.T, r *kernelApplyRuntime, timeout time.Duration, ready func() bool) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-ticker.C:
		case err := <-r.done:
			r.done <- err
			t.Fatalf("Service exited: %v", err)
		case <-timer.C:
			t.Fatal("kernel application condition deadline")
		}
	}
}
func kernelApplyPort(r *kernelApplyRuntime) int {
	r.fixture.mu.Lock()
	defer r.fixture.mu.Unlock()
	return r.fixture.config.ServerPort
}
func kernelApplyPush(t *testing.T, r *kernelApplyRuntime, event controlplane.Event) {
	t.Helper()
	select {
	case r.service.push.EventSink() <- event:
	case <-time.After(time.Second):
		t.Fatal("Service event queue stalled")
	}
}

// Local SOCKS5 servers forward actual protocol traffic to the loopback origin.
// Counting completed CONNECT handshakes proves which desired outbound is used.
type kernelApplySOCKS struct {
	listener    net.Listener
	connections atomic.Int32
}

func kernelApplyProxy(t *testing.T) *kernelApplySOCKS {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &kernelApplySOCKS{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
				header := make([]byte, 2)
				if _, err := io.ReadFull(connection, header); err != nil || header[0] != 5 {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, err := io.ReadFull(connection, methods); err != nil {
					return
				}
				if _, err := connection.Write([]byte{5, 0}); err != nil {
					return
				}
				request := make([]byte, 4)
				if _, err := io.ReadFull(connection, request); err != nil || request[1] != 1 {
					return
				}
				var host string
				switch request[3] {
				case 1:
					address := make([]byte, 4)
					if _, err := io.ReadFull(connection, address); err != nil {
						return
					}
					host = net.IP(address).String()
				case 3:
					size := []byte{0}
					if _, err := io.ReadFull(connection, size); err != nil {
						return
					}
					address := make([]byte, int(size[0]))
					if _, err := io.ReadFull(connection, address); err != nil {
						return
					}
					host = string(address)
				case 4:
					address := make([]byte, 16)
					if _, err := io.ReadFull(connection, address); err != nil {
						return
					}
					host = net.IP(address).String()
				default:
					return
				}
				port := make([]byte, 2)
				if _, err := io.ReadFull(connection, port); err != nil {
					return
				}
				if host != "127.0.0.1" {
					return
				}
				upstream, err := net.DialTimeout("tcp4", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
				proxy.connections.Add(1)
				if _, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				copied := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, connection)
					if tcp, ok := upstream.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					close(copied)
				}()
				_, _ = io.Copy(connection, upstream)
				_ = connection.Close()
				<-copied
			}()
		}
	}()
	return proxy
}
func kernelApplyProxyConfig(cfg *panel.NodeConfig, proxy *kernelApplySOCKS, originPort int) {
	cfg.CustomOutbounds = []panel.OutboundConfig{{Tag: "selected-proxy", Protocol: "socks", Settings: map[string]any{"server": "127.0.0.1", "server_port": proxy.listener.Addr().(*net.TCPAddr).Port, "version": "5"}}}
	cfg.CustomRoutes = []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{originPort}, "outbound": "selected-proxy"}}
}

func TestNativeKernelApplyLiveSingBoxCustomOutboundReconstruction(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			proxyA, proxyB := kernelApplyProxy(t), kernelApplyProxy(t)
			var originPort int
			runtime := kernelApplyStart(t, "singbox", protocol, func(cfg *panel.NodeConfig, port int) { originPort = port; kernelApplyProxyConfig(cfg, proxyA, port) })
			if proxyA.connections.Load() != 1 || proxyB.connections.Load() != 0 {
				t.Fatal("initial traffic did not use proxy A")
			}
			fixture := runtime.fixture
			fixture.mu.Lock()
			kernelApplyProxyConfig(&fixture.config, proxyB, originPort)
			fixture.revision++
			desired := model.NodeSpecFromPanel(&fixture.config)
			fixture.mu.Unlock()
			kernelApplyWait(t, runtime, 8*time.Second, func() bool {
				runtime.service.metricsMu.RLock()
				defer runtime.service.metricsMu.RUnlock()
				return runtime.service.appliedConfigHash == computeConfigHash(desired)
			})
			port := kernelApplyPort(runtime)
			snapshotEcho(t, protocol, port, liveProtocolUUID, runtime.destination)
			if proxyB.connections.Load() != 1 || proxyA.connections.Load() != 1 {
				t.Fatalf("outbound reconstruction retained old topology: A=%d B=%d", proxyA.connections.Load(), proxyB.connections.Load())
			}
			// A raw rule referring to an unknown outbound reaches kernel route validation.
			fixture.mu.Lock()
			fixture.config.CustomRoutes = []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{originPort}, "outbound": "nonexistent-kernel-outbound"}}
			fixture.revision++
			invalid := model.NodeSpecFromPanel(&fixture.config)
			fixture.mu.Unlock()
			kernelApplyWait(t, runtime, 8*time.Second, func() bool {
				runtime.service.metricsMu.RLock()
				defer runtime.service.metricsMu.RUnlock()
				return runtime.service.applicationFailure != "" && runtime.service.appliedConfigHash != computeConfigHash(invalid)
			})
			fixture.mu.Lock()
			kernelApplyProxyConfig(&fixture.config, proxyB, originPort)
			fixture.revision++
			fixture.mu.Unlock()
			kernelApplyWait(t, runtime, 8*time.Second, func() bool { return snapshotListener(port) })
			kernelApplyWait(t, runtime, 8*time.Second, func() bool {
				runtime.service.metricsMu.RLock()
				defer runtime.service.metricsMu.RUnlock()
				return runtime.service.applicationFailure == "" && runtime.service.appliedConfigHash == computeConfigHash(desired)
			})
			snapshotEcho(t, protocol, port, liveProtocolUUID, runtime.destination)
			if proxyB.connections.Load() != 2 || proxyA.connections.Load() != 1 {
				t.Fatal("valid desired configuration did not recover proxy B")
			}
		})
	}
}

func TestNativeKernelApplyLiveXrayRemovalAndUUIDReplacementCloseExistingStream(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		for _, operation := range []string{"remove", "rotate"} {
			t.Run(protocol+"/"+operation, func(t *testing.T) {
				runtime := kernelApplyStart(t, "xray", protocol, nil)
				port := kernelApplyPort(runtime)
				raw, stream := liveProtocolDial(t, protocol, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), liveProtocolUUID, runtime.destination)
				defer raw.Close()
				defer stream.Close()
				_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
				payload := bytes.Repeat([]byte("actual-xray-meter"), 256)
				if _, err := stream.Write(payload); err != nil {
					t.Fatal(err)
				}
				received := make([]byte, len(payload))
				if _, err := io.ReadFull(stream, received); err != nil || !bytes.Equal(received, payload) {
					t.Fatal("established Xray stream did not echo", err)
				}
				kernelApplyWait(t, runtime, 4*time.Second, func() bool { return runtime.service.tracker.HasTraffic() })
				unsampled := bytes.Repeat([]byte("last-meter-tail"), 257)
				if _, err := stream.Write(unsampled); err != nil {
					t.Fatal(err)
				}
				lastReply := make([]byte, len(unsampled))
				if _, err := io.ReadFull(stream, lastReply); err != nil || !bytes.Equal(lastReply, unsampled) {
					t.Fatal("last native bytes did not reach origin", err)
				}
				replacement := "11223344-5566-4778-899a-aabbccddeeff"
				runtime.fixture.mu.Lock()
				if operation == "remove" {
					runtime.fixture.users = []panel.User{{ID: 8, UUID: snapshotSecondUUID}}
				} else {
					runtime.fixture.users = []panel.User{{ID: 7, UUID: replacement}, {ID: 8, UUID: snapshotSecondUUID}}
				}
				runtime.fixture.usersRevision++
				runtime.fixture.mu.Unlock()
				event := controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 7, UUID: liveProtocolUUID}}}
				if operation == "rotate" {
					event.DeltaAction = "add"
					event.DeltaUsers = []model.UserSpec{{ID: 7, UUID: replacement}}
				}
				kernelApplyPush(t, runtime, event)
				_ = stream.SetReadDeadline(time.Now().Add(8 * time.Second))
				probe := make([]byte, 1)
				if n, err := stream.Read(probe); n != 0 || err == nil {
					t.Fatal("revoked established stream stayed open")
				} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("revoked established stream merely timed out instead of closing")
				}
				expected := []model.UserSpec{{ID: 8, UUID: snapshotSecondUUID}}
				if operation == "rotate" {
					expected = append(expected, model.UserSpec{ID: 7, UUID: replacement})
				}
				kernelApplyWait(t, runtime, 8*time.Second, func() bool {
					runtime.service.metricsMu.RLock()
					ready := runtime.service.applicationFailure == "" && runtime.service.appliedUserHash == computeUserHash(expected)
					runtime.service.metricsMu.RUnlock()
					return ready && snapshotListener(port)
				})
				snapshotEcho(t, protocol, port, snapshotSecondUUID, runtime.destination)
				if !snapshotReject(t, protocol, port, liveProtocolUUID, runtime.destination) {
					t.Fatal("revoked Xray UUID authenticated")
				}
				if operation == "rotate" {
					snapshotEcho(t, protocol, port, replacement, runtime.destination)
				}
				tail := runtime.service.tracker.FlushTraffic()
				if total := tail[7][0] + tail[7][1]; total < int64(len(payload)+len(unsampled))*2 {
					t.Fatalf("native Xray traffic lost across revocation: %v want >=%d", tail, int64(len(payload)+len(unsampled))*2)
				}
				runtime.service.tracker.RestoreTraffic(tail)
			})
		}
	}
}

func TestNativeKernelApplyLiveSingBoxProtocolReplacementRemovesOldInbound(t *testing.T) {
	for _, oldProtocol := range []string{"vless", "vmess"} {
		t.Run(oldProtocol, func(t *testing.T) {
			runtime := kernelApplyStart(t, "singbox", oldProtocol, nil)
			oldPort, newPort := kernelApplyPort(runtime), authorityPort(t)
			newProtocol := "vmess"
			if oldProtocol == "vmess" {
				newProtocol = "vless"
			}
			runtime.fixture.mu.Lock()
			runtime.fixture.config.Protocol = newProtocol
			runtime.fixture.config.ServerPort = newPort
			runtime.fixture.revision++
			desired := model.NodeSpecFromPanel(&runtime.fixture.config)
			runtime.fixture.mu.Unlock()
			kernelApplyWait(t, runtime, 8*time.Second, func() bool {
				runtime.service.metricsMu.RLock()
				confirmed := runtime.service.appliedConfigHash == computeConfigHash(desired)
				runtime.service.metricsMu.RUnlock()
				return confirmed && snapshotListener(newPort) && !snapshotListener(oldPort)
			})
			snapshotEcho(t, newProtocol, newPort, liveProtocolUUID, runtime.destination)
			snapshotEcho(t, newProtocol, newPort, snapshotSecondUUID, runtime.destination)
			if snapshotListener(oldPort) {
				t.Fatal("old protocol listener remained open")
			}
		})
	}
}
