//go:build linux

package txnode

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

func startMieruPatternClient(t *testing.T, port int, transport string, pattern map[string]any) string {
	t.Helper()
	bin := mieruBinary(t)
	socksPort := freePortTB(t)
	profile := map[string]any{
		"profileName": "interop", "user": map[string]any{"name": "interop", "password": "secret"},
		"servers": []any{map[string]any{"ipAddress": "127.0.0.1", "portBindings": []any{map[string]any{"port": port, "protocol": transport}}}},
		"mtu":     1400, "trafficPattern": pattern,
	}
	cfg, err := json.Marshal(map[string]any{
		"profiles": []any{profile}, "activeProfile": "interop", "socks5Port": socksPort, "loggingLevel": mieruLogLevel(),
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(configPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "client.log")
	output, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = output.Close()
		if raw, err := os.ReadFile(logPath); err == nil && len(raw) > 0 {
			t.Logf("official Mieru explicit-pattern client log:\n%s", raw)
		}
	})
	cmd := exec.Command(bin, "run")
	cmd.Env = append(os.Environ(), "MIERU_CONFIG_JSON_FILE="+configPath)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("official Mieru explicit-pattern SOCKS listener did not open")
	return ""
}

func mieruBulkRoundTrip(t *testing.T, socksAddr string, payload []byte) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(io.LimitReader(r.Body, int64(len(payload))+1))
		if err != nil || !bytes.Equal(got, payload) {
			http.Error(w, "upload payload mismatch", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer origin.Close()
	conn, err := socksNoAuthConnectE(socksAddr, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("official Mieru CONNECT: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	req, err := http.NewRequest(http.MethodPost, "http://origin/upload", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Close = true
	if err := req.Write(conn); err != nil {
		t.Fatalf("upload: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("download headers: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(payload))+1))
	if err != nil || resp.StatusCode != http.StatusOK || !bytes.Equal(got, payload) {
		t.Fatalf("bidirectional payload: status=%d bytes=%d err=%v", resp.StatusCode, len(got), err)
	}
}

func TestInteropMieruOfficialUDPTransport(t *testing.T) {
	mieruBinary(t)
	port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "mieru", Transport: "udp"}, kernel.TLSCert{},
		[]model.UserSpec{{ID: 1, UUID: "interop:secret"}})
	addr := startMieruOfficial(t, port, "UDP")
	t.Run("tcp-over-udp-bulk", func(t *testing.T) {
		mieruBulkRoundTrip(t, addr, bytes.Repeat([]byte("official-mieru-udp-stream/"), 45000))
	})
	t.Run("application-udp-over-udp", func(t *testing.T) {
		echo := udpEcho(t)
		payload := bytes.Repeat([]byte("fragmented-datagram/"), 100)
		got, err := udpThroughSocksE(t, addr, echo, payload)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("application UDP=%d bytes err=%v", len(got), err)
		}
	})
	t.Run("idle-and-reuse", func(t *testing.T) {
		time.Sleep(25 * time.Second)
		origin := startInteropOrigin(t)
		body, err := fetchThroughE(t, addr, origin.Listener.Addr().String())
		if err != nil || body != "interop-ok" {
			t.Fatalf("UDP underlay after idle: body=%q err=%v", body, err)
		}
	})
}

func TestInteropMieruOfficialTrafficPatterns(t *testing.T) {
	mieruBinary(t)
	for _, transport := range []string{"TCP", "UDP"} {
		for _, mode := range []int{32, 40, 48, 56} {
			t.Run(fmt.Sprintf("%s/low-entropy-%d", transport, mode), func(t *testing.T) {
				pattern := map[string]any{
					"nonce":       map[string]any{"type": "NONCE_TYPE_FIXED", "customHexStrings": []string{"010203040506"}, "applyToAllUDPPacket": true},
					"padding":     map[string]any{"maxMiddlePaddingLen": 13, "maxEndPaddingLen": 19},
					"lowEntropy":  map[string]any{"mode": fmt.Sprintf("LOW_ENTROPY_MODE_%d", mode), "maskRotation": "LOW_ENTROPY_MASK_ROTATE_LEFT_3"},
					"tcpFragment": map[string]any{"enable": true, "maxSleepMs": 0},
				}
				raw, err := json.Marshal(pattern)
				if err != nil {
					t.Fatal(err)
				}
				port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "mieru", Transport: strings.ToLower(transport), TrafficPattern: string(raw)}, kernel.TLSCert{},
					[]model.UserSpec{{ID: 1, UUID: "interop:secret"}})
				addr := startMieruPatternClient(t, port, transport, pattern)
				mieruBulkRoundTrip(t, addr, bytes.Repeat([]byte{0, 0xff, 1, 2, 3, 0x8f, 0x37}, 10000))
				echo := udpEcho(t)
				payload := bytes.Repeat([]byte("pattern-packet/"), 120)
				got, err := udpThroughSocksE(t, addr, echo, payload)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("explicit pattern application UDP bytes=%d err=%v", len(got), err)
				}
			})
		}
	}
}

func TestInteropMieruOfficialImplicitPatterns(t *testing.T) {
	mieruBinary(t)
	for _, transport := range []string{"TCP", "UDP"} {
		for _, fixture := range []struct {
			name string
			seed *int32
		}{
			{"seed-zero", pointerInt32(0)},
			{"seed-min", pointerInt32(-2147483648)},
			{"seed-max", pointerInt32(2147483647)},
			{"host-seed", nil},
		} {
			t.Run(transport+"/"+fixture.name, func(t *testing.T) {
				pattern := map[string]any{"unlockAll": true, "tcpFragment": map[string]any{"maxSleepMs": 0}}
				if fixture.seed != nil {
					pattern["seed"] = *fixture.seed
				}
				raw, err := json.Marshal(pattern)
				if err != nil {
					t.Fatal(err)
				}
				port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "mieru", Transport: strings.ToLower(transport), TrafficPattern: string(raw)}, kernel.TLSCert{},
					[]model.UserSpec{{ID: 1, UUID: "interop:secret"}})
				addr := startMieruPatternClient(t, port, transport, pattern)
				mieruBulkRoundTrip(t, addr, bytes.Repeat([]byte("implicit-pattern/"), 3000))
				payload := bytes.Repeat([]byte("implicit-udp/"), 130)
				got, err := udpThroughSocksE(t, addr, udpEcho(t), payload)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("implicit pattern application UDP bytes=%d err=%v", len(got), err)
				}
			})
		}
	}
}

func pointerInt32(value int32) *int32 { return &value }
