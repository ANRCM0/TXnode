package service

// Deployment-level end-to-end test: a real fake panel over HTTP, the real
// Service (control plane → nodesync → kernel lifecycle), the native txnode
// kernel, and a SOCKS5 client. The unit suites cover each layer separately;
// this test covers the seams between them.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
)

const deployE2EUUID = "00112233-4455-4677-8899-aabbccddeeff"

// fakePanel serves the Xboard-compatible REST surface the node pulls from.
type fakePanel struct {
	mu       sync.Mutex
	pushed   map[string][2]int64
	port     int
	listener string
}

func (p *fakePanel) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/server/handshake", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"websocket":{"enabled":false},"settings":{"push_interval":1,"pull_interval":1}}`)
	})
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cfg := map[string]any{
			"protocol":    "vless",
			"listen_ip":   "127.0.0.1",
			"server_port": p.port,
		}
		_ = json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/api/v1/server/UniProxy/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"users":[{"id":1,"uuid":"`+deployE2EUUID+`"}]}`)
	})
	mux.HandleFunc("/api/v2/server/report", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var body struct {
			Traffic map[string][2]int64 `json:"traffic"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Logf("panel report decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		for user, traffic := range body.Traffic {
			prev := p.pushed[user]
			p.pushed[user] = [2]int64{prev[0] + traffic[0], prev[1] + traffic[1]}
		}
		p.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/server/UniProxy/alive", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/server/UniProxy/status", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// freePort returns an unused loopback port for the node listener.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func waitForPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("node listener on %d never accepted", port)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// vlessConnect performs the VLESS TCP handshake for dest and returns the
// stream connection.
func vlessConnect(t *testing.T, port int, dest string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := hex.DecodeString(strings.ReplaceAll(deployE2EUUID, "-", ""))
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	req := []byte{0}
	req = append(req, uuid...)
	req = append(req, 0, 1) // no addons, command TCP
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(portStr)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(p))
	req = append(req, pb[:]...)
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 1)
		req = append(req, ip4...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	return conn
}

func TestDeploymentPanelToNodeToClient(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "deploy-ok")
	}))
	defer origin.Close()

	panel := &fakePanel{port: freePort(t), pushed: map[string][2]int64{}}
	panelServer := httptest.NewServer(panel.handler(t))
	defer panelServer.Close()

	cfg := &config.Config{
		Panel: config.PanelConfig{
			Provider: "xboard",
			URL:      panelServer.URL,
			Token:    "token",
			NodeID:   1,
		},
		Kernel: config.KernelConfig{Type: "txnode"},
		Node: config.NodeConfig{
			PushInterval: 1, PullInterval: 1, TrackInterval: 1, DeviceReportInterval: 1,
		},
		WS: config.WSConfig{DiscoveryInterval: 300},
	}
	svc, err := NewChecked(cfg)
	if err != nil {
		t.Fatalf("service: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- svc.Run(ctx) }()

	waitForPort(t, panel.port)

	conn := vlessConnect(t, panel.port, origin.Listener.Addr().String())
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The VLESS server prefixes its first response record with [version][addons]
	// (both zero for no encryption and no addons), so consume it before the HTTP
	// response parse.
	reader := bufio.NewReader(conn)
	if _, err := reader.Discard(2); err != nil {
		t.Fatalf("vless response header: %v", err)
	}
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || strings.TrimSpace(string(body)) != "deploy-ok" {
		t.Fatalf("body = %q err = %v", body, err)
	}

	// The panel must receive the relayed bytes through the normal report loop.
	deadline := time.Now().Add(10 * time.Second)
	for {
		panel.mu.Lock()
		up, down := panel.pushed["1"][0], panel.pushed["1"][1]
		panel.mu.Unlock()
		if up > 0 && down > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("panel never received traffic: up=%d down=%d", up, down)
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	select {
	case <-runErr:
	case <-time.After(15 * time.Second):
		t.Fatal("service did not stop")
	}
}
