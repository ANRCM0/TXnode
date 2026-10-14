package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	singM "github.com/sagernet/sing/common/metadata"
)

const reloadUUID = "550e8400-e29b-41d4-a716-446655440000"

type reloadOrigin struct {
	listener net.Listener
	prefix   string
	calls    atomic.Int32
	mu       sync.Mutex
	clients  map[net.Conn]bool
	wg       sync.WaitGroup
}

func newReloadOrigin(t *testing.T, prefix string) *reloadOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := &reloadOrigin{listener: listener, prefix: prefix, clients: make(map[net.Conn]bool)}
	origin.wg.Add(1)
	go func() {
		defer origin.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			origin.calls.Add(1)
			origin.mu.Lock()
			origin.clients[conn] = true
			origin.wg.Add(1)
			origin.mu.Unlock()
			go func() {
				defer origin.wg.Done()
				defer func() { conn.Close(); origin.mu.Lock(); delete(origin.clients, conn); origin.mu.Unlock() }()
				buffer := make([]byte, 4096)
				for {
					n, err := conn.Read(buffer)
					if n > 0 {
						if _, werr := conn.Write(append([]byte(prefix), buffer[:n]...)); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		origin.mu.Lock()
		for conn := range origin.clients {
			conn.Close()
		}
		origin.mu.Unlock()
		origin.wg.Wait()
	})
	return origin
}

type reloadSocks struct {
	listener net.Listener
	mu       sync.Mutex
	clients  map[net.Conn]bool
	wg       sync.WaitGroup
}

func newReloadSocks(t *testing.T, origin *reloadOrigin) *reloadSocks {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &reloadSocks{listener: listener, clients: make(map[net.Conn]bool)}
	proxy.wg.Add(1)
	go func() {
		defer proxy.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			proxy.mu.Lock()
			proxy.clients[conn] = true
			proxy.wg.Add(1)
			proxy.mu.Unlock()
			go func() {
				defer proxy.wg.Done()
				defer func() { conn.Close(); proxy.mu.Lock(); delete(proxy.clients, conn); proxy.mu.Unlock() }()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				var header [2]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				var command [4]byte
				if _, err := io.ReadFull(conn, command[:]); err != nil || command[0] != 5 || command[1] != 1 {
					return
				}
				size := 0
				switch command[3] {
				case 1:
					size = 4
				case 4:
					size = 16
				case 3:
					var length [1]byte
					if _, err := io.ReadFull(conn, length[:]); err != nil {
						return
					}
					size = int(length[0])
				default:
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(size+2)); err != nil {
					return
				}
				upstream, err := net.DialTimeout("tcp", origin.listener.Addr().String(), time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				conn.SetDeadline(time.Time{})
				done := make(chan struct{})
				go func() { io.Copy(upstream, conn); upstream.Close(); close(done) }()
				io.Copy(conn, upstream)
				conn.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		proxy.mu.Lock()
		for conn := range proxy.clients {
			conn.Close()
		}
		proxy.mu.Unlock()
		proxy.wg.Wait()
	})
	return proxy
}
func reloadPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}
func reloadSpec(protocol string, port int, proxy *reloadSocks) *model.NodeSpec {
	return &model.NodeSpec{Protocol: protocol, ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp", CustomOutbounds: []model.OutboundConfig{{Tag: "proxy", Protocol: "socks", Settings: map[string]any{"server": "127.0.0.1", "server_port": proxy.listener.Addr().(*net.TCPAddr).Port, "version": "5"}}}, CustomRoutes: []map[string]any{{"outbound": "proxy"}}}
}
func reloadDial(t *testing.T, protocol string, port int, uuid string, destination net.Addr) net.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	target := singM.ParseSocksaddr(destination.String())
	var conn net.Conn
	if protocol == "vless" {
		client, err := vless.NewClient(uuid, "", logger.NOP())
		if err != nil {
			t.Fatal(err)
		}
		conn, err = client.DialConn(raw, target)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
	} else {
		client, err := vmess.NewClient(uuid, "aes-128-gcm", 0)
		if err != nil {
			t.Fatal(err)
		}
		conn, err = client.DialConn(raw, target)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	return conn
}
func reloadExchange(t *testing.T, conn net.Conn, prefix, payload string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(prefix)+len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != prefix+payload {
		t.Fatalf("actual origin response %q wanted %q", response, prefix+payload)
	}
}
func reloadProbe(t *testing.T, protocol string, port int, origin *reloadOrigin, prefix, payload string) {
	t.Helper()
	conn := reloadDial(t, protocol, port, reloadUUID, origin.listener.Addr())
	defer conn.Close()
	reloadExchange(t, conn, prefix, payload)
}
func reloadReject(t *testing.T, protocol string, port int, uuid string, origin *reloadOrigin) {
	t.Helper()
	conn := reloadDial(t, protocol, port, uuid, origin.listener.Addr())
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write([]byte("refused")); err != nil {
		return
	}
	var response [1]byte
	if n, err := conn.Read(response[:]); err == nil || n != 0 {
		t.Fatal("rejected route/credential reached origin")
	}
}

func TestReloadFullReconstructionChangesActualCustomOutboundAndRejectsRouting(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			originA, originB := newReloadOrigin(t, "A:"), newReloadOrigin(t, "B:")
			proxyA, proxyB := newReloadSocks(t, originA), newReloadSocks(t, originB)
			port := reloadPort(t)
			initial, next := reloadSpec(protocol, port, proxyA), reloadSpec(protocol, port, proxyB)
			users := []model.UserSpec{{ID: 7, UUID: reloadUUID}}
			runtime := New(config.KernelConfig{Type: "singbox", LogLevel: "error", ConfigDir: t.TempDir()})
			defer runtime.Stop()
			if err := runtime.Start(initial, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			reloadProbe(t, protocol, port, originA, "A:", "before")
			box, tracker, hash := runtime.box, runtime.connTracker, runtime.constructionHash
			if err := runtime.Reload(next, users, kernel.TLSCert{}); !errors.Is(err, ErrFullRestartRequired) {
				t.Fatalf("outbound change falsely applied: %v", err)
			}
			if runtime.box != box || runtime.connTracker != tracker || runtime.constructionHash != hash || runtime.nodeConfig != initial {
				t.Fatal("restart requirement partially mutated live kernel")
			}
			reloadProbe(t, protocol, port, originA, "A:", "still-confirmed-A")
			if originB.calls.Load() != 0 {
				t.Fatal("unconfirmed desired outbound accepted")
			}
			runtime.Stop()
			tail, _, _, err := runtime.GetUserTraffic(context.Background())
			if err != nil || tail[7][0] == 0 || tail[7][1] == 0 {
				t.Fatalf("stop discarded native cumulative tail: %v %v", tail, err)
			}
			if err := runtime.Start(next, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			oldCalls := originA.calls.Load()
			reloadProbe(t, protocol, port, originA, "B:", "after")
			if originA.calls.Load() != oldCalls || originB.calls.Load() != 1 {
				t.Fatalf("actual outbound unchanged A=%d B=%d", originA.calls.Load(), originB.calls.Load())
			}
			blocked := reloadSpec(protocol, port, proxyB)
			blocked.CustomRoutes = []map[string]any{{"outbound": "block"}}
			if err := runtime.Reload(blocked, users, kernel.TLSCert{}); !errors.Is(err, ErrFullRestartRequired) {
				t.Fatalf("route change falsely applied: %v", err)
			}
			runtime.Stop()
			if err := runtime.Start(blocked, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			bCalls := originB.calls.Load()
			reloadReject(t, protocol, port, reloadUUID, originA)
			if originA.calls.Load() != oldCalls || originB.calls.Load() != bCalls {
				t.Fatal("disallowed route connected to origin")
			}
		})
	}
}

func TestReloadUserOnlyKeepsListenerReplayOwnerAndNativeCumulativeMeters(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			origin := newReloadOrigin(t, "O:")
			proxy := newReloadSocks(t, origin)
			port := reloadPort(t)
			spec := reloadSpec(protocol, port, proxy)
			users := []model.UserSpec{{ID: 7, UUID: reloadUUID}}
			runtime := New(config.KernelConfig{Type: "singbox", LogLevel: "error", ConfigDir: t.TempDir()})
			defer runtime.Stop()
			if err := runtime.Start(spec, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			conn := reloadDial(t, protocol, port, reloadUUID, origin.listener.Addr())
			defer conn.Close()
			reloadExchange(t, conn, "O:", "before")
			before, _, _, err := runtime.GetUserTraffic(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			originalBox, originalTracker := runtime.box, runtime.connTracker
			next := []model.UserSpec{{ID: 7, UUID: reloadUUID, SpeedLimit: 2}, {ID: 8, UUID: "550e8400-e29b-41d4-a716-446655440001"}}
			if err := runtime.Reload(spec, next, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			if runtime.box != originalBox || runtime.connTracker != originalTracker {
				t.Fatal("user-only update reconstructed runtime/replay owner")
			}
			reloadExchange(t, conn, "O:", "after")
			after, _, _, err := runtime.GetUserTraffic(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if after[7][0]-before[7][0] != int64(len("after")) || after[7][1]-before[7][1] != int64(len("O:after")) {
				t.Fatalf("user-only update lost/doubled meters before=%v after=%v", before, after)
			}
			added := reloadDial(t, protocol, port, next[1].UUID, origin.listener.Addr())
			defer added.Close()
			reloadExchange(t, added, "O:", "added")
			meters, _, _, err := runtime.GetUserTraffic(context.Background())
			if err != nil || meters[8] != [2]int64{5, 7} {
				t.Fatalf("new identity meters=%v err=%v", meters, err)
			}
		})
	}
}

func TestReloadProtocolPortAndConstructionChangesAreAtomicRestartRequirements(t *testing.T) {
	origin := newReloadOrigin(t, "O:")
	proxy := newReloadSocks(t, origin)
	port := reloadPort(t)
	spec := reloadSpec("vless", port, proxy)
	users := []model.UserSpec{{ID: 7, UUID: reloadUUID}}
	runtime := New(config.KernelConfig{Type: "singbox", LogLevel: "error", ConfigDir: t.TempDir()})
	defer runtime.Stop()
	if err := runtime.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		modify func(*model.NodeSpec)
	}{
		{"port", func(n *model.NodeSpec) { n.ServerPort = reloadPort(t) }},
		{"protocol", func(n *model.NodeSpec) { n.Protocol = "vmess" }},
		{"flow", func(n *model.NodeSpec) { n.Flow = "xtls-rprx-vision" }},
		{"transport", func(n *model.NodeSpec) { n.Network = "ws"; n.NetworkSettings = map[string]any{"path": "/other"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := reloadSpec("vless", port, proxy)
			tc.modify(next)
			if err := runtime.Reload(next, users, kernel.TLSCert{}); !errors.Is(err, ErrFullRestartRequired) {
				t.Fatalf("construction change accepted: %v", err)
			}
			if runtime.nodeConfig != spec || !runtime.IsRunning() {
				t.Fatal("old confirmed state mutated")
			}
		})
	}
	next := reloadSpec("vmess", port, proxy)
	if err := runtime.Reload(next, users, kernel.TLSCert{}); !errors.Is(err, ErrFullRestartRequired) {
		t.Fatal(err)
	}
	runtime.Stop()
	if err := runtime.Start(next, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	beforeCalls := origin.calls.Load()
	reloadReject(t, "vless", port, reloadUUID, origin)
	if origin.calls.Load() != beforeCalls {
		t.Fatal("old protocol inbound remained after reconstruction")
	}
	reloadProbe(t, "vmess", port, origin, "O:", "new-protocol")
}

func TestReloadInvalidConstructionCannotMarkAppliedOrLeakConfiguration(t *testing.T) {
	origin := newReloadOrigin(t, "O:")
	proxy := newReloadSocks(t, origin)
	port := reloadPort(t)
	spec := reloadSpec("vless", port, proxy)
	users := []model.UserSpec{{ID: 7, UUID: reloadUUID}}
	runtime := New(config.KernelConfig{Type: "singbox", LogLevel: "error", ConfigDir: t.TempDir()})
	defer runtime.Stop()
	if err := runtime.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	priorBox, priorTracker, priorHash := runtime.box, runtime.connTracker, runtime.constructionHash
	cases := []struct {
		name   string
		modify func(*model.NodeSpec)
	}{
		{"unresolved outbound", func(n *model.NodeSpec) {
			n.CustomRouteRules = []model.CustomRouteRule{{Match: model.RouteMatch{Networks: []string{"tcp"}}, Action: model.RouteAction{Type: "route", Target: "secret-target"}}}
		}},
		{"malformed raw rule", func(n *model.NodeSpec) { n.CustomRoutes = []map[string]any{{"outbound": "proxy", "network": 12345}} }},
		{"unencodable setting", func(n *model.NodeSpec) { n.CustomOutbounds[0].Settings["password"] = make(chan int) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := reloadSpec("vless", port, proxy)
			tc.modify(next)
			err := runtime.Reload(next, users, kernel.TLSCert{})
			if err == nil {
				t.Fatal("invalid construction confirmed")
			}
			if runtime.box != priorBox || runtime.connTracker != priorTracker || runtime.constructionHash != priorHash || runtime.nodeConfig != spec {
				t.Fatal("invalid request partially mutated live kernel")
			}
			if contains := fmt.Sprint(err); contains == "" || strings.Contains(contains, "secret-target") {
				t.Fatalf("unsafe diagnostic %q", contains)
			}
		})
	}
	reloadProbe(t, "vless", port, origin, "O:", "still-confirmed")
}

func TestReloadDetectsChangedDNSAndInvalidCustomSource(t *testing.T) {
	origin := newReloadOrigin(t, "O:")
	proxy := newReloadSocks(t, origin)
	port := reloadPort(t)
	custom := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(custom, []byte(`{"dns":{"servers":[{"type":"local","tag":"resolver"}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	spec := reloadSpec("vless", port, proxy)
	users := []model.UserSpec{{ID: 7, UUID: reloadUUID}}
	runtime := New(config.KernelConfig{Type: "singbox", LogLevel: "error", ConfigDir: t.TempDir(), CustomConfig: custom})
	defer runtime.Stop()
	if err := runtime.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(custom, []byte(`{"dns":{"servers":[{"type":"local","tag":"changed"}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Reload(spec, users, kernel.TLSCert{}); !errors.Is(err, ErrFullRestartRequired) {
		t.Fatalf("DNS change silently ignored: %v", err)
	}
	if err := os.WriteFile(custom, []byte(`{"secret-token":`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Reload(spec, users, kernel.TLSCert{}); err == nil {
		t.Fatal("bad custom source silently discarded")
	}
}

func TestReloadConcurrentClientsNeverObserveUnconfirmedRoutePublication(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			originA, originB := newReloadOrigin(t, "A:"), newReloadOrigin(t, "B:")
			proxyA, proxyB := newReloadSocks(t, originA), newReloadSocks(t, originB)
			port := reloadPort(t)
			initial, next := reloadSpec(protocol, port, proxyA), reloadSpec(protocol, port, proxyB)
			users := []model.UserSpec{{ID: 7, UUID: reloadUUID}}
			runtime := New(config.KernelConfig{Type: "singbox", LogLevel: "error", ConfigDir: t.TempDir()})
			defer runtime.Stop()
			if err := runtime.Start(initial, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 25; i++ {
					if err := runtime.Reload(next, users, kernel.TLSCert{}); !errors.Is(err, ErrFullRestartRequired) {
						t.Errorf("unconfirmed construction published: %v", err)
						return
					}
				}
			}()
			for i := 0; i < 12; i++ {
				reloadProbe(t, protocol, port, originA, "A:", "concurrent")
			}
			wg.Wait()
			if originA.calls.Load() != 12 || originB.calls.Load() != 0 {
				t.Fatalf("unconfirmed routing leaked A=%d B=%d", originA.calls.Load(), originB.calls.Load())
			}
		})
	}
}

func TestReloadNewPortReconstructionLeavesNoOldListener(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			origin := newReloadOrigin(t, "O:")
			proxy := newReloadSocks(t, origin)
			oldPort, newPort := reloadPort(t), reloadPort(t)
			initial, next := reloadSpec(protocol, oldPort, proxy), reloadSpec(protocol, newPort, proxy)
			users := []model.UserSpec{{ID: 7, UUID: reloadUUID}}
			runtime := New(config.KernelConfig{Type: "singbox", LogLevel: "error", ConfigDir: t.TempDir()})
			defer runtime.Stop()
			if err := runtime.Start(initial, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Reload(next, users, kernel.TLSCert{}); !errors.Is(err, ErrFullRestartRequired) {
				t.Fatal(err)
			}
			runtime.Stop()
			if err := runtime.Start(next, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(oldPort)), time.Second)
			if err == nil {
				conn.Close()
				t.Fatal("old listener remained open")
			}
			reloadProbe(t, protocol, newPort, origin, "O:", "new-port")
		})
	}
}

func TestReloadRawMissingOutboundFailsBeforeStartOrLiveMutation(t *testing.T) {
	origin := newReloadOrigin(t, "O:")
	proxy := newReloadSocks(t, origin)
	port := reloadPort(t)
	users := []model.UserSpec{{ID: 7, UUID: reloadUUID}}
	initial := reloadSpec("vless", port, proxy)
	invalid := reloadSpec("vless", port, proxy)
	invalid.CustomRoutes = []map[string]any{{"outbound": "secret-nonexistent"}}
	runtime := New(config.KernelConfig{Type: "singbox", LogLevel: "error", ConfigDir: t.TempDir()})
	defer runtime.Stop()
	if err := runtime.Start(invalid, users, kernel.TLSCert{}); err == nil || err.Error() != "KERNEL_ROUTE_OUTBOUND_UNKNOWN" {
		t.Fatalf("invalid raw route started or leaked: %v", err)
	}
	if runtime.IsRunning() || runtime.constructionConfirmed {
		t.Fatal("failed fresh Start confirmed runtime")
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("invalid fresh construction opened listener")
	}
	if err := runtime.Start(initial, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	oldBox, oldTracker, oldHash := runtime.box, runtime.connTracker, runtime.constructionHash
	if err := runtime.Reload(invalid, users, kernel.TLSCert{}); err == nil || err.Error() != "KERNEL_ROUTE_OUTBOUND_UNKNOWN" {
		t.Fatalf("invalid Reload falsely confirmed: %v", err)
	}
	if runtime.box != oldBox || runtime.connTracker != oldTracker || runtime.constructionHash != oldHash || runtime.nodeConfig != initial {
		t.Fatal("bad Reload mutated confirmed runtime")
	}
	if err := runtime.Start(invalid, users, kernel.TLSCert{}); err == nil {
		t.Fatal("bad direct Start accepted")
	}
	if runtime.box != oldBox || runtime.connTracker != oldTracker || runtime.constructionHash != oldHash || runtime.nodeConfig != initial {
		t.Fatal("bad Start mutated confirmed runtime")
	}
	reloadProbe(t, "vless", port, origin, "O:", "still-valid")
}

func TestGeneratedConstructionOutboundReferenceBoundary(t *testing.T) {
	cases := []struct {
		name  string
		extra map[string]any
		valid bool
	}{
		{"builtins and reject", map[string]any{"route": map[string]any{"final": "direct", "rules": []any{map[string]any{"outbound": "block"}, map[string]any{"action": "reject"}, map[string]any{"action": "direct"}}}}, true},
		{"unknown raw default", map[string]any{"route": map[string]any{"rules": []any{map[string]any{"outbound": "unknown"}}}}, false},
		{"unknown raw explicit route", map[string]any{"route": map[string]any{"rules": []any{map[string]any{"action": "route", "outbound": "unknown"}}}}, false},
		{"nested logical route", map[string]any{"route": map[string]any{"rules": []any{map[string]any{"type": "logical", "mode": "or", "rules": []any{map[string]any{"action": "route", "outbound": "unknown"}}}}}}, false},
		{"unknown final", map[string]any{"route": map[string]any{"final": "unknown"}}, false},
		{"missing detour", map[string]any{"outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}, map[string]any{"tag": "block", "type": "block"}, map[string]any{"tag": "socks", "type": "socks", "detour": "unknown"}}}, false},
		{"missing selector member", map[string]any{"outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}, map[string]any{"tag": "block", "type": "block"}, map[string]any{"tag": "choice", "type": "selector", "outbounds": []any{"unknown"}}}}, false},
		{"missing selector default", map[string]any{"outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}, map[string]any{"tag": "choice", "type": "selector", "outbounds": []any{"direct"}, "default": "unknown"}}}, false},
		{"missing urltest member", map[string]any{"outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}, map[string]any{"tag": "choice", "type": "urltest", "outbounds": []any{"unknown"}}}}, false},
		{"valid selector", map[string]any{"outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}, map[string]any{"tag": "choice", "type": "selector", "outbounds": []any{"direct"}, "default": "direct"}}, "route": map[string]any{"final": "choice"}}, true},
		{"DNS unknown detour", map[string]any{"dns": map[string]any{"servers": []any{map[string]any{"tag": "dns", "type": "udp", "detour": "unknown"}}}}, false},
		{"DNS outbound matching is not route reference", map[string]any{"dns": map[string]any{"rules": []any{map[string]any{"outbound": []any{"any"}, "server": "dns"}}}}, true},
		{"endpoint target", map[string]any{"endpoints": []any{map[string]any{"tag": "wg", "type": "wireguard"}}, "route": map[string]any{"final": "wg"}}, true},
		{"duplicate namespace tag", map[string]any{"endpoints": []any{map[string]any{"tag": "direct", "type": "wireguard"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			construction := map[string]any{"outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}, map[string]any{"tag": "block", "type": "block"}}}
			for key, value := range tc.extra {
				construction[key] = value
			}
			body, err := json.Marshal(construction)
			if err != nil {
				t.Fatal(err)
			}
			err = validateConstructionReferences(body)
			if (err == nil) != tc.valid {
				t.Fatalf("reference accepted=%v wanted=%v err=%v", err == nil, tc.valid, err)
			}
		})
	}
}
