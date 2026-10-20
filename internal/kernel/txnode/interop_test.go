//go:build linux

package txnode

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"

	"fmt"
	"io"
	"log/slog"
	"math/big"
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

	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	nativeoutbound "github.com/ANRCM0/TX-Node/internal/dataplane/outbound"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// The interop suite drives the native data plane with a real third-party client
// (Xray). The client is a test tool only: it is never built into the node, is
// not referenced by go.mod. Discovery may skip unconfigured clients; strict CI
// requires every selected client's executable and treats transport errors as failures.
const interopUUID = "00112233-4455-4677-8899-aabbccddeeff"

func xrayBinary(t *testing.T) string {
	t.Helper()
	return interopBinary(t, "TXNODE_INTEROP_XRAY")
}

func startInteropOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("TXNODE_ORIGIN_DEBUG") != "" {
			t.Logf("origin request from %s method=%s url=%s host=%s close=%v proto=%s",
				r.RemoteAddr, r.Method, r.URL, r.Host, r.Close, r.Proto)
		}
		_, _ = io.WriteString(w, "interop-ok")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func startInteropKernel(t *testing.T, spec *model.NodeSpec, cert kernel.TLSCert) int {
	t.Helper()
	return startInteropKernelUsers(t, spec, cert, []model.UserSpec{{ID: 1, UUID: interopUUID}})
}

func startInteropKernelUsers(t *testing.T, spec *model.NodeSpec, cert kernel.TLSCert, users []model.UserSpec) int {
	t.Helper()
	port := freePortTB(t)
	spec.ListenIP = "127.0.0.1"
	spec.ServerPort = port
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	k := New(RuntimeConfig{TrustedProxies: "private", MaxFresh: 64, HandshakeTimeout: 5 * time.Second, Logger: logger})
	t.Cleanup(func() {
		if t.Failed() || t.Skipped() {
			t.Logf("txnode log:\n%s", logs.String())
		}
	})
	if err := k.Start(spec, users, cert); err != nil {
		t.Fatalf("kernel start: %v", err)
	}
	t.Cleanup(k.Stop)
	return port
}

func startXrayClient(t *testing.T, cfg map[string]any) string {
	t.Helper()
	bin := xrayBinary(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() || t.Skipped() {
			t.Logf("xray output:\n%s", output.String())
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	addr := cfg["_socks"].(string)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("xray socks listener did not open; output:\n%s", output.String())
	return ""
}

// xrayClientConfig builds a minimal Xray client: one SOCKS inbound and the given
// outbound.
func xrayClientConfig(t *testing.T, outbound map[string]any) (map[string]any, string) {
	return xrayClientConfigLevel(t, outbound, "warning")
}

func xrayClientConfigDebug(t *testing.T, outbound map[string]any) (map[string]any, string) {
	return xrayClientConfigLevel(t, outbound, "debug")
}

func xrayClientConfigLevel(t *testing.T, outbound map[string]any, level string) (map[string]any, string) {
	t.Helper()
	socksPort := freePortTB(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	return map[string]any{
		"log": map[string]any{"loglevel": level},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{outbound},
		"_socks":    addr,
	}, addr
}

// fetchThrough connects to the client's SOCKS inbound, CONNECTs to the origin and
// performs one HTTP/1.1 request.
func fetchThrough(t *testing.T, socksAddr, originAddr string) string {
	t.Helper()
	body, err := fetchThroughE(t, socksAddr, originAddr)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	return body
}

func fetchThroughE(t *testing.T, socksAddr, originAddr string) (string, error) {
	t.Helper()
	conn, err := socksNoAuthConnectE(socksAddr, originAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n"); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func socksNoAuthConnect(t *testing.T, socksAddr, dest string) net.Conn {
	t.Helper()
	conn, err := socksNoAuthConnectE(socksAddr, dest)
	if err != nil {
		t.Fatalf("socks connect: %v", err)
	}
	return conn
}

func socksNoAuthConnectE(socksAddr, dest string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil || method[0] != 0x05 || method[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks method reply: %v %v", method, err)
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host).To4(); ip != nil {
		req = append(req, 0x01)
		req = append(req, ip...)
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := readSocksConnectReply(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

type socksConnectReplyError struct {
	reply byte
}

func (e *socksConnectReplyError) Error() string {
	return fmt.Sprintf("SOCKS5 CONNECT rejected with REP=0x%02x", e.reply)
}

// Parse the complete frame before classifying a rejection; truncated or malformed
// handshakes must not satisfy a target-connection-refused assertion.
func readSocksConnectReply(r io.Reader) error {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return fmt.Errorf("read SOCKS5 CONNECT reply: %w", err)
	}
	if head[0] != 0x05 || head[2] != 0x00 {
		return fmt.Errorf("invalid SOCKS5 CONNECT reply header: %v", head)
	}
	var tailLength int
	switch head[3] {
	case 0x01:
		tailLength = 6
	case 0x04:
		tailLength = 18
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return fmt.Errorf("read SOCKS5 CONNECT domain length: %w", err)
		}
		if length[0] == 0 {
			return fmt.Errorf("invalid empty SOCKS5 CONNECT domain")
		}
		tailLength = int(length[0]) + 2
	default:
		return fmt.Errorf("invalid SOCKS5 CONNECT reply address type: 0x%02x", head[3])
	}
	if _, err := io.CopyN(io.Discard, r, int64(tailLength)); err != nil {
		return fmt.Errorf("read SOCKS5 CONNECT bound address: %w", err)
	}
	if head[1] != 0x00 {
		return &socksConnectReplyError{reply: head[1]}
	}
	return nil
}

// selfSignedFiles returns the PEM pair plus the certificate file path Xray needs
// for pinned verification.
func selfSignedFiles(t *testing.T) (kernel.TLSCert, string) {
	t.Helper()
	cert := selfSignedPEM(t)
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, cert.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, path
}

func selfSignedPEM(t *testing.T) kernel.TLSCert {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return kernel.TLSCert{CertPEM: certPEM, KeyPEM: keyPEM}
}

func vlessOutbound(port int, stream map[string]any) map[string]any {
	if stream == nil {
		stream = map[string]any{"network": "tcp"}
	}
	return map[string]any{
		"protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port,
			"users": []any{map[string]any{"id": interopUUID, "encryption": "none"}},
		}}},
		"streamSettings": stream,
	}
}

func TestInteropXrayVLESS(t *testing.T) {
	origin := startInteropOrigin(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "vless", Network: "tcp"}, kernel.TLSCert{})
	cfg, socks := xrayClientConfig(t, vlessOutbound(port, nil))
	startXrayClient(t, cfg)
	if got := fetchThrough(t, socks, origin.Listener.Addr().String()); got != "interop-ok" {
		t.Fatalf("body = %q", got)
	}
}

func TestInteropXrayVLESSWebSocket(t *testing.T) {
	origin := startInteropOrigin(t)
	spec := &model.NodeSpec{
		Protocol:        "vless",
		Network:         "ws",
		NetworkSettings: map[string]any{"path": "/ray"},
	}
	port := startInteropKernel(t, spec, kernel.TLSCert{})
	stream := map[string]any{
		"network":    "ws",
		"wsSettings": map[string]any{"path": "/ray", "headers": map[string]any{"Host": "example.com"}},
	}
	cfg, socks := xrayClientConfig(t, vlessOutbound(port, stream))
	startXrayClient(t, cfg)
	if got := fetchThrough(t, socks, origin.Listener.Addr().String()); got != "interop-ok" {
		t.Fatalf("body = %q", got)
	}
}

func TestInteropXrayVMess(t *testing.T) {
	origin := startInteropOrigin(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "vmess", Network: "tcp", Cipher: "auto"}, kernel.TLSCert{})
	outbound := map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port,
			"users": []any{map[string]any{"id": interopUUID, "security": "auto", "level": 0}},
		}}},
		"streamSettings": map[string]any{"network": "tcp"},
	}
	cfg, socks := xrayClientConfigDebug(t, outbound)
	startXrayClient(t, cfg)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("VMess handshake with Xray failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestInteropXrayVMessNativeOutbound(t *testing.T) {
	xrayBinary(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
		if _, err := io.Copy(w, r.Body); err != nil {
			t.Errorf("echo request: %v", err)
		}
	}))
	t.Cleanup(origin.Close)
	port := freePortTB(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	startXrayClient(t, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vmess",
			"settings":       map[string]any{"clients": []any{map[string]any{"id": interopUUID, "alterId": 0}}},
			"streamSettings": map[string]any{"network": "tcp"},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
		// The existing process helper probes the configured TCP listener.
		"_socks": addr,
	})
	for _, method := range []string{"aes-128-gcm", "chacha20-poly1305", "none"} {
		t.Run(method, func(t *testing.T) {
			client, err := nativeoutbound.New("vmess", opt.Opt{
				"server": "127.0.0.1", "port": port, "uuid": interopUUID,
				"method": method, "network": "tcp",
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			stream, err := client.DialTCP(ctx, socks.FromNetAddr(origin.Listener.Addr()))
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			reader := bufio.NewReader(stream)
			// Reuse one authenticated stream through multiple nonce advances and
			// a body larger than a single 16-bit wire chunk.
			for _, size := range []int{1024, 32768, 131072} {
				body := bytes.Repeat([]byte{0x00, 0xa5, 0x7f, 0x42}, size/4)
				request, err := http.NewRequest(http.MethodPost, origin.URL, bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				if err := stream.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := request.Write(stream); err != nil {
					t.Fatalf("write %d-byte request: %v", size, err)
				}
				response, err := http.ReadResponse(reader, request)
				if err != nil {
					t.Fatalf("read %d-byte response: %v", size, err)
				}
				received, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(received, body) {
					t.Fatalf("VMess %s body mismatch at %d bytes: status=%d bytes=%d err=%v", method, size, response.StatusCode, len(received), readErr)
				}
			}
		})
	}
}

func TestInteropXrayTrojanTLS(t *testing.T) {
	origin := startInteropOrigin(t)
	cert, certPath := selfSignedFiles(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "trojan", TLS: 1, ServerName: "localhost"}, cert)
	outbound := map[string]any{
		"protocol": "trojan",
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "password": interopUUID,
		}}},
		"streamSettings": map[string]any{
			"network":  "tcp",
			"security": "tls",
			"tlsSettings": map[string]any{
				"serverName": "localhost",
				// Xray 26 removed allowInsecure: trust the generated certificate
				// explicitly instead.
				"certificates": []any{map[string]any{
					"usage": "verify", "certificateFile": certPath,
				}},
			},
		},
	}
	cfg, socks := xrayClientConfig(t, outbound)
	startXrayClient(t, cfg)
	if got := fetchThrough(t, socks, origin.Listener.Addr().String()); got != "interop-ok" {
		t.Fatalf("body = %q", got)
	}
}

func TestInteropXrayShadowsocks(t *testing.T) {
	origin := startInteropOrigin(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "shadowsocks", Cipher: "aes-128-gcm"}, kernel.TLSCert{})
	outbound := map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "method": "aes-128-gcm", "password": interopUUID,
		}}},
	}
	cfg, socks := xrayClientConfig(t, outbound)
	startXrayClient(t, cfg)
	if got := fetchThrough(t, socks, origin.Listener.Addr().String()); got != "interop-ok" {
		t.Fatalf("body = %q", got)
	}
}

// TestInteropXrayVLESSReality checks the REALITY handshake against the real Xray
// client. The borrowed site must be reachable because the server relays the
// ClientHello to it; override with TXNODE_INTEROP_REALITY_DEST.
func TestInteropXrayVLESSReality(t *testing.T) {
	xrayBinary(t)
	dest := os.Getenv("TXNODE_INTEROP_REALITY_DEST")
	if dest == "" {
		dest = "www.cloudflare.com:443"
	}
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub := interopRealityKeypair(t)

	origin := startInteropOrigin(t)
	spec := &model.NodeSpec{
		Protocol: "vless",
		Network:  "tcp",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": priv,
			"short_id":    "0123456789abcdef",
			"dest":        dest,
			"server_name": []any{host},
		},
	}
	port := startInteropKernel(t, spec, kernel.TLSCert{})
	outbound := vlessOutbound(port, map[string]any{
		"network":  "tcp",
		"security": "reality",
		"realitySettings": map[string]any{
			"serverName":  host,
			"fingerprint": "chrome",
			"publicKey":   pub,
			"shortId":     "0123456789abcdef",
			"spiderX":     "/",
			"show":        true,
		},
	})
	cfg, socks := xrayClientConfigDebug(t, outbound)
	startXrayClient(t, cfg)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("REALITY handshake with Xray failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

func interopRealityKeypair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate REALITY fixture keypair: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

func mihomoBinary(t *testing.T) string {
	t.Helper()
	return interopBinary(t, "TXNODE_INTEROP_MIHOMO")
}

// startMihomo writes a SOCKS-only config whose single proxy is the given YAML
// block, starts the client and returns its SOCKS address.
func startMihomo(t *testing.T, proxyBlock string) string {
	t.Helper()
	bin := mihomoBinary(t)
	dir := t.TempDir()
	socksPort := freePortTB(t)
	cfg := "log-level: debug\n" +
		"allow-lan: false\n" +
		"mode: rule\n" +
		"ipv6: false\n" +
		"socks-port: " + strconv.Itoa(socksPort) + "\n" +
		"proxies:\n" + proxyBlock +
		"rules:\n  - MATCH,interop\n"
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd := exec.Command(bin, "-d", dir, "-f", path)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mihomo: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() || t.Skipped() {
			t.Logf("mihomo output:\n%s", output.String())
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			// The proxy is configured lazily; give it a moment so the first
			// SOCKS request does not race initialization.
			time.Sleep(100 * time.Millisecond)
			return addr
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("mihomo socks listener did not open; output:\n%s", output.String())
	return ""
}

// TestInteropMihomoHysteria2 drives the QUIC inbound with Mihomo's official
// Hysteria2 client.
func TestInteropMihomoHysteria2(t *testing.T) {
	cert := selfSignedPEM(t)
	spec := &model.NodeSpec{
		Protocol:   "hysteria",
		Version:    2,
		TLS:        1,
		ServerName: "localhost",
		UpMbps:     100,
		DownMbps:   100,
	}
	port := startInteropKernel(t, spec, cert)
	origin := startInteropOrigin(t)

	proxy := "  - name: interop\n" +
		"    type: hysteria2\n" +
		"    server: 127.0.0.1\n" +
		"    port: " + strconv.Itoa(port) + "\n" +
		"    password: " + interopUUID + "\n" +
		"    sni: localhost\n" +
		"    skip-cert-verify: true\n" +
		"    up: \"100 Mbps\"\n" +
		"    down: \"100 Mbps\"\n"
	socks := startMihomo(t, proxy)
	// Mihomo finishes its provider bootstrap asynchronously; the first SOCKS
	// request right after the listener opens can be dropped, so retry briefly.
	var body string
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		body, err = fetchThroughE(t, socks, origin.Listener.Addr().String())
		if err == nil {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Hysteria2 interop with Mihomo %s failed: %v", versionOf(t, "mihomo"), err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

// versionOf is a small diagnostic helper for failure messages.
func versionOf(t *testing.T, name string) string {
	t.Helper()
	switch name {
	case "mihomo":
		bin := os.Getenv("TXNODE_INTEROP_MIHOMO")
		if bin == "" {
			return "unknown"
		}
		out, err := exec.Command(bin, "-v").CombinedOutput()
		if err != nil {
			return "unknown"
		}
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "Meta" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return "unknown"
}

// TestInteropMihomoVLESSReality drives the REALITY inbound with Mihomo's VLESS
// client, which implements REALITY independently of Xray's uTLS fork.
func TestInteropMihomoVLESSReality(t *testing.T) {
	mihomoBinary(t)
	dest := os.Getenv("TXNODE_INTEROP_REALITY_DEST")
	if dest == "" {
		dest = "www.cloudflare.com:443"
	}
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub := interopRealityKeypair(t)
	origin := startInteropOrigin(t)
	spec := &model.NodeSpec{
		Protocol: "vless",
		Network:  "tcp",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": priv,
			"short_id":    "0123456789abcdef",
			"dest":        dest,
			"server_name": []any{host},
		},
	}
	port := startInteropKernel(t, spec, kernel.TLSCert{})
	proxy := "  - name: interop\n" +
		"    type: vless\n" +
		"    server: 127.0.0.1\n" +
		"    port: " + strconv.Itoa(port) + "\n" +
		"    uuid: " + interopUUID + "\n" +
		"    network: tcp\n" +
		"    tls: true\n" +
		"    servername: " + host + "\n" +
		"    client-fingerprint: chrome\n" +
		"    reality-opts:\n" +
		"      public-key: " + pub + "\n" +
		"      short-id: \"0123456789abcdef\"\n"
	socks := startMihomo(t, proxy)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("REALITY handshake with Mihomo failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

// tlsClientStream returns a TLS client stream with the generated test
// certificate pinned via Xray's certificates usage=verify.
func tlsClientStream(serverName, certPath string) map[string]any {
	return map[string]any{
		"security": "tls",
		"tlsSettings": map[string]any{
			"serverName": serverName,
			"certificates": []any{map[string]any{
				"usage": "verify", "certificateFile": certPath,
			}},
		},
	}
}

func TestInteropXrayVLESSTLS(t *testing.T) {
	origin := startInteropOrigin(t)
	cert, certPath := selfSignedFiles(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "vless", Network: "tcp", TLS: 1, ServerName: "localhost"}, cert)
	stream := tlsClientStream("localhost", certPath)
	stream["network"] = "tcp"
	cfg, socks := xrayClientConfig(t, vlessOutbound(port, stream))
	startXrayClient(t, cfg)
	if got := fetchThrough(t, socks, origin.Listener.Addr().String()); got != "interop-ok" {
		t.Fatalf("body = %q", got)
	}
}

func TestInteropXrayVLESSGRPC(t *testing.T) {
	origin := startInteropOrigin(t)
	cert, certPath := selfSignedFiles(t)
	port := startInteropKernel(t, &model.NodeSpec{
		Protocol: "vless", Network: "grpc", TLS: 1, ServerName: "localhost",
		NetworkSettings: map[string]any{"serviceName": "interop"},
	}, cert)
	stream := tlsClientStream("localhost", certPath)
	stream["network"] = "grpc"
	stream["grpcSettings"] = map[string]any{"serviceName": "interop"}
	cfg, socks := xrayClientConfig(t, vlessOutbound(port, stream))
	startXrayClient(t, cfg)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("gRPC transport interop failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestInteropXrayVLESSH2Removed(t *testing.T) {
	// Xray 26 removed the standalone HTTP/2 transport ("migrated to XHTTP
	// stream-one H2 & H3"); the H2 path is covered by the XHTTP test instead.
	skipInteropKnownGap(t, "H2-REMOVED")
}

func TestInteropXrayVLESSHTTPUpgrade(t *testing.T) {
	origin := startInteropOrigin(t)
	cert, certPath := selfSignedFiles(t)
	port := startInteropKernel(t, &model.NodeSpec{
		Protocol: "vless", Network: "httpupgrade", TLS: 1, ServerName: "localhost",
		NetworkSettings: map[string]any{"path": "/up"},
	}, cert)
	stream := tlsClientStream("localhost", certPath)
	stream["network"] = "httpupgrade"
	stream["httpupgradeSettings"] = map[string]any{"path": "/up", "host": "localhost"}
	cfg, socks := xrayClientConfig(t, vlessOutbound(port, stream))
	startXrayClient(t, cfg)
	if got := fetchThrough(t, socks, origin.Listener.Addr().String()); got != "interop-ok" {
		t.Fatalf("body = %q", got)
	}
}

func TestInteropXrayVLESSXHTTP(t *testing.T) {
	origin := startInteropOrigin(t)
	cert, certPath := selfSignedFiles(t)
	port := startInteropKernel(t, &model.NodeSpec{
		Protocol: "vless", Network: "xhttp", TLS: 1, ServerName: "localhost",
		NetworkSettings: map[string]any{"path": "/xhttp"},
	}, cert)
	stream := tlsClientStream("localhost", certPath)
	stream["network"] = "xhttp"
	stream["xhttpSettings"] = map[string]any{"path": "/xhttp", "host": "localhost", "mode": "auto"}
	cfg, socks := xrayClientConfig(t, vlessOutbound(port, stream))
	startXrayClient(t, cfg)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("XHTTP transport interop failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestInteropXrayVMessWebSocket(t *testing.T) {
	origin := startInteropOrigin(t)
	port := startInteropKernel(t, &model.NodeSpec{
		Protocol: "vmess", Network: "ws", Cipher: "auto",
		NetworkSettings: map[string]any{"path": "/vm"},
	}, kernel.TLSCert{})
	outbound := map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port,
			"users": []any{map[string]any{"id": interopUUID, "security": "auto", "level": 0}},
		}}},
		"streamSettings": map[string]any{
			"network":    "ws",
			"wsSettings": map[string]any{"path": "/vm", "headers": map[string]any{"Host": "example.com"}},
		},
	}
	cfg, socks := xrayClientConfig(t, outbound)
	startXrayClient(t, cfg)
	if got := fetchThrough(t, socks, origin.Listener.Addr().String()); got != "interop-ok" {
		t.Fatalf("body = %q", got)
	}
}

func TestInteropXrayShadowsocks2022(t *testing.T) {
	origin := startInteropOrigin(t)
	// 16-byte PSK (base64) for 2022-blake3-aes-128-gcm.
	psk := base64Raw16()
	port := startInteropKernelUsers(t, &model.NodeSpec{
		Protocol: "shadowsocks", Cipher: "2022-blake3-aes-128-gcm", ServerKey: psk,
	}, kernel.TLSCert{}, []model.UserSpec{{ID: 1, UUID: psk}})
	outbound := map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "method": "2022-blake3-aes-128-gcm", "password": psk,
		}}},
	}
	cfg, socks := xrayClientConfig(t, outbound)
	startXrayClient(t, cfg)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SS2022 interop with Xray failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

// base64Raw16 returns a deterministic 16-byte PSK in raw base64 (SS2022 form).
func base64Raw16() string {
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
}

func TestInteropMihomoTUIC(t *testing.T) { mihomoBinary(t); testMihomoTUIC(t) }

func singBoxBinary(t *testing.T) string {
	t.Helper()
	return interopBinary(t, "TXNODE_INTEROP_SINGBOX")
}

// startSingBoxClient writes a socks-in/one-outbound config, starts sing-box and
// returns the SOCKS address.
func startSingBoxClient(t *testing.T, outbound map[string]any) string {
	t.Helper()
	bin := singBoxBinary(t)
	dir := t.TempDir()
	socksPort := freePortTB(t)
	cfg := map[string]any{
		"log": map[string]any{"level": "debug"},
		"inbounds": []any{map[string]any{
			"type": "socks", "listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []any{outbound},
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd := exec.Command(bin, "run", "-c", path, "-D", dir)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sing-box: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() || t.Skipped() {
			t.Logf("sing-box output:\n%s", output.String())
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			time.Sleep(100 * time.Millisecond)
			return addr
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("sing-box socks listener did not open; output:\n%s", output.String())
	return ""
}

func TestInteropSingBoxAnyTLS(t *testing.T) {
	origin := startInteropOrigin(t)
	cert, _ := selfSignedFiles(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "anytls", TLS: 1, ServerName: "localhost"}, cert)
	outbound := map[string]any{
		"type": "anytls", "tag": "interop",
		"server": "127.0.0.1", "server_port": port,
		"password": interopUUID,
		"tls":      map[string]any{"enabled": true, "server_name": "localhost", "insecure": true},
	}
	socks := startSingBoxClient(t, outbound)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("AnyTLS interop with sing-box failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestInteropSingBoxTUIC(t *testing.T) {
	origin := startInteropOrigin(t)
	cert := selfSignedPEM(t)
	port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "tuic", TLS: 1, ServerName: "localhost"}, cert,
		[]model.UserSpec{{ID: 1, UUID: interopUUID + ":" + interopUUID}})
	outbound := map[string]any{
		"type": "tuic", "tag": "interop",
		"server": "127.0.0.1", "server_port": port,
		"uuid": interopUUID, "password": interopUUID,
		"congestion_control": "bbr",
		"tls":                map[string]any{"enabled": true, "server_name": "localhost", "insecure": true, "alpn": []any{"h3"}},
	}
	socks := startSingBoxClient(t, outbound)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("TUIC QUIC session not established with sing-box: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestInteropSingBoxHysteria2(t *testing.T) {
	origin := startInteropOrigin(t)
	cert := selfSignedPEM(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "hysteria", Version: 2, TLS: 1, ServerName: "localhost"}, cert)
	outbound := map[string]any{
		"type": "hysteria2", "tag": "interop",
		"server": "127.0.0.1", "server_port": port,
		"password": interopUUID,
		"tls":      map[string]any{"enabled": true, "server_name": "localhost", "insecure": true},
	}
	socks := startSingBoxClient(t, outbound)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Hysteria2 handshake with sing-box failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestInteropSingBoxShadowsocks2022(t *testing.T) {
	origin := startInteropOrigin(t)
	psk := base64Raw16()
	port := startInteropKernelUsers(t, &model.NodeSpec{
		Protocol: "shadowsocks", Cipher: "2022-blake3-aes-128-gcm", ServerKey: psk,
	}, kernel.TLSCert{}, []model.UserSpec{{ID: 1, UUID: psk}})
	outbound := map[string]any{
		"type": "shadowsocks", "tag": "interop",
		"server": "127.0.0.1", "server_port": port,
		"method": "2022-blake3-aes-128-gcm", "password": psk,
	}
	socks := startSingBoxClient(t, outbound)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SS2022 interop with sing-box failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

// udpEcho starts a local UDP echo server.
func udpEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

// udpThroughSocks sends one datagram through a SOCKS5 UDP ASSOCIATE and returns
// the echoed payload.
func udpThroughSocks(t *testing.T, socksAddr, dest string, payload []byte) []byte {
	t.Helper()
	body, err := udpThroughSocksE(t, socksAddr, dest, payload)
	if err != nil {
		t.Fatalf("udp through socks: %v", err)
	}
	return body
}

func udpThroughSocksE(t *testing.T, socksAddr, dest string, payload []byte) ([]byte, error) {
	t.Helper()
	ctl, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer ctl.Close()
	_ = ctl.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := ctl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	var m [2]byte
	if _, err := io.ReadFull(ctl, m[:]); err != nil || m[1] != 0x00 {
		return nil, fmt.Errorf("socks method: %v %v", m, err)
	}
	if _, err := ctl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var head [4]byte
	if _, err := io.ReadFull(ctl, head[:]); err != nil || head[1] != 0x00 {
		return nil, fmt.Errorf("udp associate reply: %v %v", head, err)
	}
	var relayHost string
	var relayPort int
	switch head[3] {
	case 0x01:
		var b [6]byte
		if _, err := io.ReadFull(ctl, b[:]); err != nil {
			return nil, err
		}
		relayHost, relayPort = net.IP(b[:4]).String(), int(binary.BigEndian.Uint16(b[4:]))
	case 0x04:
		var b [18]byte
		if _, err := io.ReadFull(ctl, b[:]); err != nil {
			return nil, err
		}
		relayHost, relayPort = net.IP(b[:16]).String(), int(binary.BigEndian.Uint16(b[16:]))
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(ctl, l[:]); err != nil {
			return nil, err
		}
		host := make([]byte, int(l[0]))
		if _, err := io.ReadFull(ctl, host); err != nil {
			return nil, err
		}
		var p [2]byte
		if _, err := io.ReadFull(ctl, p[:]); err != nil {
			return nil, err
		}
		relayHost, relayPort = string(host), int(binary.BigEndian.Uint16(p[:]))
	default:
		return nil, fmt.Errorf("unexpected relay atyp %d", head[3])
	}
	if relayHost == "0.0.0.0" || relayHost == "::" {
		relayHost = "127.0.0.1"
	}
	uc, err := net.DialTimeout("udp", net.JoinHostPort(relayHost, strconv.Itoa(relayPort)), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(8 * time.Second))
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	pkt := []byte{0, 0, 0}
	if ip := net.ParseIP(host).To4(); ip != nil {
		pkt = append(pkt, 0x01)
		pkt = append(pkt, ip...)
	} else {
		pkt = append(pkt, 0x03, byte(len(host)))
		pkt = append(pkt, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	pkt = append(pkt, pb[:]...)
	pkt = append(pkt, payload...)
	if _, err := uc.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := uc.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 4 {
		return nil, fmt.Errorf("short udp reply %d", n)
	}
	switch buf[3] {
	case 0x01:
		return append([]byte(nil), buf[10:n]...), nil
	case 0x04:
		return append([]byte(nil), buf[22:n]...), nil
	case 0x03:
		l := int(buf[4])
		return append([]byte(nil), buf[5+l+2:n]...), nil
	}
	return nil, fmt.Errorf("bad udp reply atyp %d", buf[3])
}

func TestInteropSingBoxHysteria2UDP(t *testing.T) {
	echo := udpEcho(t)
	cert := selfSignedPEM(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "hysteria", Version: 2, TLS: 1, ServerName: "localhost"}, cert)
	outbound := map[string]any{
		"type": "hysteria2", "tag": "interop",
		"server": "127.0.0.1", "server_port": port,
		"password": interopUUID,
		"tls":      map[string]any{"enabled": true, "server_name": "localhost", "insecure": true},
	}
	socks := startSingBoxClient(t, outbound)
	body, err := udpThroughSocksE(t, socks, echo, []byte("udp-interop"))
	if err != nil {
		t.Fatalf("Hysteria2 UDP failed: %v", err)
	}
	if string(body) != "udp-interop" {
		t.Fatalf("udp echo = %q", body)
	}
}

// TestInteropSingBoxTUICUDP drives a UDP association through a TUIC session.
func TestInteropSingBoxTUICUDP(t *testing.T) {
	echo := udpEcho(t)
	cert := selfSignedPEM(t)
	port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "tuic", TLS: 1, ServerName: "localhost"}, cert,
		[]model.UserSpec{{ID: 1, UUID: interopUUID + ":" + interopUUID}})
	outbound := map[string]any{
		"type": "tuic", "tag": "interop",
		"server": "127.0.0.1", "server_port": port,
		"uuid": interopUUID, "password": interopUUID,
		"congestion_control": "bbr",
		"tls":                map[string]any{"enabled": true, "server_name": "localhost", "insecure": true, "alpn": []any{"h3"}},
	}
	socks := startSingBoxClient(t, outbound)
	body, err := udpThroughSocksE(t, socks, echo, []byte("tuic-udp"))
	if err != nil {
		t.Fatalf("TUIC UDP failed: %v", err)
	}
	if string(body) != "tuic-udp" {
		t.Fatalf("udp echo = %q", body)
	}
}

// TestInteropSingBoxXUDP documents the one remaining UDP gap: sing-box sends
// Xray's XUDP framing: a per-packet destination header with an optional UUID
// hint and global ID, on the VLESS UDP stream. The node serves the plain
// length-prefixed VLESS UDP framing, so a client that negotiates xudp fails;
// the skip records the gap instead of pretending it works. Hysteria2, TUIC and
// Shadowsocks2022 UDP are covered by their own cases.
func TestInteropSingBoxXUDP(t *testing.T) {
	echo := udpEcho(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "vless", Transport: "tcp"}, kernel.TLSCert{})
	outbound := map[string]any{
		"type": "vless", "tag": "interop",
		"server": "127.0.0.1", "server_port": port,
		"uuid": interopUUID, "packet_encoding": "xudp",
	}
	socks := startSingBoxClient(t, outbound)
	body, err := udpThroughSocksE(t, socks, echo, []byte("xudp-interop"))
	if err != nil {
		t.Fatalf("XUDP failed: %v", err)
	}
	if string(body) != "xudp-interop" {
		t.Fatalf("udp echo = %q", body)
	}
}

// TestInteropSingBoxMux drives the mux inbound path with sing-box
// multiplexing: one mux connection carries several streams, each with its own
// SOCKS destination header.
func TestInteropSingBoxMux(t *testing.T) {
	for _, protocol := range []string{"smux", "yamux"} {
		t.Run(protocol, func(t *testing.T) {
			origin := startInteropOrigin(t)
			port := startInteropKernel(t, &model.NodeSpec{Protocol: "vless", Transport: "tcp"}, kernel.TLSCert{})
			outbound := map[string]any{
				"type": "vless", "tag": "interop",
				"server": "127.0.0.1", "server_port": port,
				"uuid":      interopUUID,
				"multiplex": map[string]any{"enabled": true, "protocol": protocol, "max_streams": 8},
			}
			if !singBoxSupports(t, outbound) {
				t.Fatalf("required sing-box %s multiplexing configuration rejected", protocol)
			}
			socks := startSingBoxClient(t, outbound)
			// The first request opens the mux connection, the following ones
			// reuse it: every session must be relayed independently.
			for round := 0; round < 3; round++ {
				body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
				if err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
				if body != "interop-ok" {
					t.Fatalf("round %d: body = %q", round, body)
				}
			}
		})
	}
}

// Fixed sing-box v1.14.3 / sing-mux caf09fe32475 packet stream framing.
func TestInteropSingBoxMuxUDP(t *testing.T) { singBoxBinary(t); testSingBoxMuxUDP(t) }

// TestInteropXrayMux drives Xray Mux.Cool (v1.mux.cool): the node parses the
// [len][session][status][network][target] frames and relays each session.
func TestInteropXrayMux(t *testing.T) {
	origin := startInteropOrigin(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "vless", Transport: "tcp"}, kernel.TLSCert{})
	outbound := vlessOutbound(port, nil)
	outbound["mux"] = map[string]any{"enabled": true, "concurrency": 8}
	cfg, socks := xrayClientConfigDebug(t, outbound)
	startXrayClient(t, cfg)
	for round := 0; round < 3; round++ {
		body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if body != "interop-ok" {
			t.Fatalf("round %d: body = %q", round, body)
		}
	}
}

func TestInteropSingBoxMieru(t *testing.T) {
	origin := startInteropOrigin(t)
	port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "mieru", Transport: "tcp"}, kernel.TLSCert{},
		[]model.UserSpec{{ID: 1, UUID: "interop:secret"}})
	outbound := map[string]any{
		"type": "mieru", "tag": "interop",
		"server": "127.0.0.1", "server_port": port,
		"username": "interop", "password": "secret",
		"transport": "tcp",
	}
	checkOutput, checkErr := singBoxCheck(t, outbound)
	if checkErr != nil {
		if strings.Contains(strings.ToLower(checkOutput), "unknown outbound type: mieru") && skipInteropKnownGap(t, "SINGBOX-MIERU") {
			return
		}
		t.Fatalf("sing-box Mieru configuration rejected: %v\n%s", checkErr, checkOutput)
	}
	socks := startSingBoxClient(t, outbound)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("mieru interop with sing-box failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestInteropSingBoxSnell(t *testing.T) {
	origin := startInteropOrigin(t)
	port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "snell", Version: 4}, kernel.TLSCert{},
		[]model.UserSpec{{ID: 1, UUID: "interop-psk"}})
	outbound := map[string]any{
		"type": "snell", "tag": "interop",
		"server": "127.0.0.1", "server_port": port,
		"psk": "interop-psk", "version": 4,
	}
	if !singBoxSupports(t, outbound) {
		t.Fatal("required sing-box Snell v4 configuration rejected")
	}
	socks := startSingBoxClient(t, outbound)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Snell interop failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestInteropSingBoxNaive(t *testing.T) { singBoxBinary(t); testSingBoxNaiveTrust(t) }

func TestInteropXrayVLESSEncryption(t *testing.T) {
	bin := xrayBinary(t)
	out, err := exec.Command(bin, "vlessenc").CombinedOutput()
	if err != nil {
		t.Fatalf("xray vlessenc: %v\n%s", err, out)
	}
	var decryption, encryption string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "\"decryption\":") && decryption == "" {
			decryption = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "\"decryption\":")), "\",")
		}
		if strings.HasPrefix(line, "\"encryption\":") && encryption == "" {
			encryption = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "\"encryption\":")), "\",")
		}
		if decryption != "" && encryption != "" {
			break
		}
	}
	if decryption == "" || encryption == "" {
		t.Fatal("could not parse required xray vlessenc output")
	}
	origin := startInteropOrigin(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "vless", Network: "tcp", Decryption: decryption}, kernel.TLSCert{})
	outbound := map[string]any{
		"protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port,
			"users": []any{map[string]any{"id": interopUUID, "encryption": encryption}},
		}}},
		"streamSettings": map[string]any{"network": "tcp"},
	}
	cfg, socks := xrayClientConfig(t, outbound)
	startXrayClient(t, cfg)
	body, err := fetchThroughE(t, socks, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("VLESS Encryption interop failed: %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

// singBoxSupports checks the exact client configuration before starting it.
func singBoxSupports(t *testing.T, outbound map[string]any) bool {
	t.Helper()
	out, err := singBoxCheck(t, outbound)
	if err != nil {
		t.Logf("sing-box check: %v\n%s", err, out)
		return false
	}
	return true
}

func singBoxCheck(t *testing.T, outbound map[string]any) (string, error) {
	t.Helper()
	bin := singBoxBinary(t)
	dir := t.TempDir()
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": 1080}},
		"outbounds": []any{outbound},
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "check.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", path, "-D", dir).CombinedOutput()
	return string(out), err
}

// TestInteropCurlNaiveH2 drives the naive inbound with curl's HTTP/2 CONNECT
// proxy mode independently of the sing-box certificate fixture.
func TestInteropCurlNaiveH2(t *testing.T) {
	bin := interopCurlBinary(t)
	version, err := exec.Command(bin, "--disable", "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("curl version: %v\n%s", err, version)
	}
	help, err := exec.Command(bin, "--disable", "--help", "all").CombinedOutput()
	if err != nil {
		t.Fatalf("curl options: %v\n%s", err, help)
	}
	if !bytes.Contains(version, []byte("HTTP2")) || !bytes.Contains(help, []byte("--proxy-http2")) {
		t.Fatal("required curl client has no HTTP/2 proxy support")
	}
	origin := startInteropOrigin(t)
	cert, _ := selfSignedFiles(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "naive", Network: "h2", TLS: 1, ServerName: "localhost"}, cert)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// HTTP targets need CONNECT explicitly; ignore local proxy bypass settings.
	cmd := exec.CommandContext(ctx, bin, "--disable", "-sS", "--max-time", "8",
		"--proxy-insecure", "--proxy-http2", "--proxytunnel", "--noproxy", "",
		"-x", "https://127.0.0.1:"+strconv.Itoa(port),
		"-U", "interop:"+interopUUID,
		"http://"+origin.Listener.Addr().String()+"/")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl HTTP/2 CONNECT failed: %v\n%s", err, out)
	}
	if string(out) != "interop-ok" {
		t.Fatalf("body = %q", out)
	}
}

func mieruBinary(t *testing.T) string {
	t.Helper()
	return interopBinary(t, "TXNODE_INTEROP_MIERU")
}

// mieruLogLevel lets a run raise the client log level without editing the test.
func mieruLogLevel() string {
	if v := os.Getenv("TXNODE_INTEROP_MIERU_LOG"); v != "" {
		return v
	}
	return "INFO"
}

// startMieruOfficial launches the official mieru client against a mieru inbound
// on port and returns its SOCKS5 address once the listener is up.
func startMieruOfficial(t *testing.T, port int, transport string) string {
	if transport == "" {
		transport = "TCP"
	}
	t.Helper()
	bin := mieruBinary(t)
	socksPort := freePortTB(t)
	dir := t.TempDir()
	cfg := fmt.Sprintf(`{
  "profiles": [{
    "profileName": "interop",
    "user": {"name": "interop", "password": "secret"},
    "servers": [{"ipAddress": "127.0.0.1", "portBindings": [{"port": %d, "protocol": "%s"}]}],
    "mtu": 1400
  }],
  "activeProfile": "interop",
  "socks5Port": %d,
  "loggingLevel": "%s"
}`, port, transport, socksPort, mieruLogLevel())
	cfgPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "MIERU_CONFIG_JSON_FILE="+cfgPath)
	logPath := filepath.Join(dir, "mieru.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	t.Cleanup(func() {
		if b, err := os.ReadFile(logPath); err == nil && len(b) > 0 {
			t.Logf("mieru client log:\n%s", b)
		}
	})
	start := exec.Command(bin, "run")
	start.Env = env
	// The mieru daemon keeps inherited descriptors open; give it a file rather
	// than a pipe so Run() returns when the parent exits.
	start.Stdout = logFile
	start.Stderr = logFile
	if err := start.Start(); err != nil {
		logs, _ := os.ReadFile(logPath)
		t.Fatalf("mieru start: %v\n%s", err, logs)
	}
	t.Cleanup(func() {
		_ = start.Process.Kill()
		_, _ = start.Process.Wait()
	})

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	deadline := time.Now().Add(8 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("mieru socks listener did not open")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestInteropMieruOfficialClient drives the mieru inbound with the official
// mieru client (the sing-box 1.14 release has no mieru outbound).
func TestInteropMieruOfficialClient(t *testing.T) {
	origin := startInteropOrigin(t)
	port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "mieru", Transport: "tcp"}, kernel.TLSCert{},
		[]model.UserSpec{{ID: 1, UUID: "interop:secret"}})
	addr := startMieruOfficial(t, port, "TCP")
	body, err := fetchThroughE(t, addr, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("mieru v2 data phase failed (MIERU-1): %v", err)
	}
	if body != "interop-ok" {
		t.Fatalf("body = %q", body)
	}
}

// TestInteropMieruOfficialIdle keeps the client and server silent across the
// server heartbeat interval and then transfers again. Each round owns a fresh
// SOCKS connection and a fresh HTTP exchange (Connection: close), so a stale
// origin keep-alive cannot be mistaken for a mieru data-path failure.
func TestInteropMieruOfficialIdle(t *testing.T) {
	origin := startInteropOrigin(t)
	port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "mieru", Transport: "tcp"}, kernel.TLSCert{},
		[]model.UserSpec{{ID: 1, UUID: "interop:secret"}})
	addr := startMieruOfficial(t, port, "TCP")

	gap := 25 * time.Second
	if v := os.Getenv("TXNODE_INTEROP_IDLE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			gap = d
		}
	}
	for round := 0; round < 2; round++ {
		if round > 0 {
			time.Sleep(gap)
		}
		conn, err := socksNoAuthConnectE(addr, origin.Listener.Addr().String())
		if err != nil {
			t.Fatalf("round %d: socks connect: %v", round, err)
		}
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n"); err != nil {
			_ = conn.Close()
			t.Fatalf("round %d: write: %v", round, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			_ = conn.Close()
			t.Fatalf("round %d: read response: %v", round, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		_ = conn.Close()
		if err != nil {
			t.Fatalf("round %d: read body: %v", round, err)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "interop-ok" {
			t.Fatalf("round %d: status %d body = %q", round, resp.StatusCode, body)
		}
	}
}

// TestInteropMieruOfficialDialFailure checks that an unreachable destination
// reaches the inner SOCKS5 client as an error instead of a stalled session.
func TestInteropMieruOfficialDialFailure(t *testing.T) {
	mieruBinary(t)
	testMieruOfficialDialFailure(t)
}

// TestInteropMieruOfficialBulk moves 1 MiB each way through one session so the
// data/ack metadata fields, MTU fragmentation and sequence numbers are all
// exercised (a single small request never crosses a fragment boundary).
func TestInteropMieruOfficialBulk(t *testing.T) {
	const size = 1 << 20
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !bytes.Equal(got, payload) {
			http.Error(w, fmt.Sprintf("body mismatch: %d bytes", len(got)), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	}))
	t.Cleanup(origin.Close)

	port := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "mieru", Transport: "tcp"}, kernel.TLSCert{},
		[]model.UserSpec{{ID: 1, UUID: "interop:secret"}})
	addr := startMieruOfficial(t, port, "TCP")

	conn, err := socksNoAuthConnectE(addr, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("socks connect: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://origin/upload", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(payload))
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %q", resp.StatusCode, body)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("echo mismatch: got %d bytes", len(body))
	}
}
