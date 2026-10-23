//go:build linux

package txnode

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	dataplanemux "github.com/ANRCM0/TX-Node/internal/dataplane/mux"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// sing-box v1.14.3 protocol/naive/outbound.go passes certificate(_path) to
// cronet.TrustedRootCertificates; its SPKI option is not consumed there.
func interopCA(t *testing.T) (kernel.TLSCert, string) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TXnode interop CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	cert := kernel.TLSCert{CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})}
	return cert, ca
}

func testSingBoxNaiveTrust(t *testing.T) {
	origin := startInteropOrigin(t)
	cert, ca := interopCA(t)
	port := startInteropKernel(t, &model.NodeSpec{Protocol: "naive", Network: "h2", TLS: 1, ServerName: "localhost"}, cert)
	outbound := func(root, name string) map[string]any {
		return map[string]any{"type": "naive", "tag": "interop", "server": "127.0.0.1", "server_port": port, "username": "interop", "password": interopUUID, "tls": map[string]any{"enabled": true, "server_name": name, "certificate": []any{root}}}
	}
	// Keep a real successful control on the same server before negative probes.
	good := startSingBoxClient(t, outbound(ca, "localhost"))
	if got := fetchThrough(t, good, origin.Listener.Addr().String()); got != "interop-ok" {
		t.Fatalf("Naive body=%q", got)
	}
	_, wrongCA := interopCA(t)
	for _, test := range []struct{ name, root, sni string }{{"untrusted-root", wrongCA, "localhost"}, {"wrong-san", ca, "wrong.invalid"}} {
		t.Run(test.name, func(t *testing.T) {
			client := startSingBoxClient(t, outbound(test.root, test.sni))
			if _, err := fetchThroughE(t, client, origin.Listener.Addr().String()); err == nil {
				t.Fatal("Naive accepted an invalid certificate")
			}
		})
	}
}

func mihomoTUICProxy(port int, password, mode string) string {
	return fmt.Sprintf("  - name: interop\n    type: tuic\n    server: 127.0.0.1\n    port: %d\n    uuid: %s\n    password: %s\n    sni: localhost\n    skip-cert-verify: true\n    alpn: [h3]\n    congestion-controller: bbr\n    udp-relay-mode: %s\n    udp: true\n", port, interopUUID, password, mode)
}

// Both sides use the same Mihomo executable/version. The reference server is
// only a CI test process and is never linked into the native data plane.
func startMihomoTUICReference(t *testing.T, cert kernel.TLSCert) int {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, cert.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	port, readyPort := freePortTB(t), freePortTB(t)
	config := map[string]any{"log-level": "debug", "allow-lan": false, "mode": "rule", "ipv6": false, "socks-port": readyPort, "rules": []any{"MATCH,DIRECT"}, "tuic-server": map[string]any{"enable": true, "listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "users": map[string]string{interopUUID: interopUUID}, "certificate": certPath, "private-key": keyPath, "alpn": []any{"h3"}, "congestion-controller": "bbr"}}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(mihomoBinary(t), "-d", dir, "-f", path)
	output, err := os.Create(filepath.Join(dir, "mihomo.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = output.Close()
		if t.Failed() {
			log, _ := os.ReadFile(output.Name())
			t.Logf("reference Mihomo:\n%s", log)
		}
	})
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(readyPort)), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return port
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("reference Mihomo did not become ready")
	return 0
}

func testMihomoTUIC(t *testing.T) {
	origin := startInteropOrigin(t)
	cert := selfSignedPEM(t)
	native := startInteropKernelUsers(t, &model.NodeSpec{Protocol: "tuic", TLS: 1, ServerName: "localhost", CongestionControl: "bbr"}, cert, []model.UserSpec{{ID: 1, UUID: interopUUID + ":" + interopUUID}})
	for _, server := range []struct {
		name string
		port int
	}{{"reference", startMihomoTUICReference(t, cert)}, {"native", native}} {
		t.Run(server.name, func(t *testing.T) {
			for _, mode := range []string{"native", "quic"} {
				t.Run(mode, func(t *testing.T) {
					client := startMihomo(t, mihomoTUICProxy(server.port, interopUUID, mode))
					if got := fetchThrough(t, client, origin.Listener.Addr().String()); got != "interop-ok" {
						t.Fatalf("TUIC body=%q", got)
					}
					association := openInteropUDPAssociation(t, client)
					echo := udpEcho(t)
					for _, size := range []int{1, 1200, 4096} {
						payload := bytes.Repeat([]byte{byte(size % 251)}, size)
						if got := association.exchange(t, echo, payload); !bytes.Equal(got, payload) {
							t.Fatalf("TUIC UDP size=%d got=%d bytes", size, len(got))
						}
					}
				})
			}
		})
	}
	t.Run("wrong-password", func(t *testing.T) {
		client := startMihomo(t, mihomoTUICProxy(native, "wrong-password", "native"))
		if _, err := fetchThroughE(t, client, origin.Listener.Addr().String()); err == nil {
			t.Fatal("TUIC accepted the wrong password")
		}
	})
}

type interopUDPAssociation struct{ control, packet net.Conn }

func openInteropUDPAssociation(t *testing.T, addr string) *interopUDPAssociation {
	t.Helper()
	control, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	_ = control.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(control, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("SOCKS method=%v err=%v", method, err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var header [3]byte
	if _, err := io.ReadFull(control, header[:]); err != nil || header != [3]byte{5, 0, 0} {
		t.Fatalf("SOCKS UDP reply=%v err=%v", header, err)
	}
	relay, err := dataplanemux.ReadAddr(control)
	if err != nil {
		t.Fatal(err)
	}
	if relay.Host == "0.0.0.0" || relay.Host == "::" {
		relay.Host = "127.0.0.1"
	}
	packet, err := net.DialTimeout("udp", relay.String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	_ = control.SetDeadline(time.Time{})
	return &interopUDPAssociation{control: control, packet: packet}
}

func (a *interopUDPAssociation) exchange(t *testing.T, target string, payload []byte) []byte {
	t.Helper()
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	dest := socks.Addr{Host: host, Port: uint16(port)}
	frame := dataplanemux.AppendAddr([]byte{0, 0, 0}, dest)
	frame = append(frame, payload...)
	_ = a.packet.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := a.packet.Write(frame); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535+260)
	n, err := a.packet.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 || !bytes.Equal(buffer[:3], []byte{0, 0, 0}) {
		t.Fatalf("invalid SOCKS UDP response size=%d", n)
	}
	reader := bytes.NewReader(buffer[3:n])
	source, err := dataplanemux.ReadAddr(reader)
	if err != nil {
		t.Fatal(err)
	}
	if source != dest {
		t.Fatalf("response source=%s want=%s", source.String(), dest.String())
	}
	return append([]byte(nil), buffer[n-reader.Len():n]...)
}

func testSingBoxMuxUDP(t *testing.T) {
	for _, protocol := range []string{"smux", "yamux"} {
		t.Run(protocol, func(t *testing.T) {
			origin := startInteropOrigin(t)
			port := startInteropKernel(t, &model.NodeSpec{Protocol: "vless", Transport: "tcp"}, kernel.TLSCert{})
			outbound := map[string]any{"type": "vless", "tag": "interop", "server": "127.0.0.1", "server_port": port, "uuid": interopUUID, "multiplex": map[string]any{"enabled": true, "protocol": protocol, "max_connections": 1, "max_streams": 8}}
			client := startSingBoxClient(t, outbound)
			if got := fetchThrough(t, client, origin.Listener.Addr().String()); got != "interop-ok" {
				t.Fatalf("TCP control=%q", got)
			}
			association := openInteropUDPAssociation(t, client)
			targets := []string{udpEcho(t), udpEcho(t)}
			for _, size := range []int{1, 255, 4096} {
				for index, target := range targets {
					payload := bytes.Repeat([]byte{byte(index + size%251)}, size)
					if got := association.exchange(t, target, payload); !bytes.Equal(got, payload) {
						t.Fatalf("mux %s UDP size=%d target=%d got=%d", protocol, size, index, len(got))
					}
				}
			}
			if got := fetchThrough(t, client, origin.Listener.Addr().String()); got != "interop-ok" {
				t.Fatalf("TCP after UDP=%q", got)
			}
		})
	}
}

type interopDialFailure struct {
	target string
	err    error
}
type interopDialObserver struct {
	failures chan interopDialFailure
	attrs    []slog.Attr
}

func (*interopDialObserver) Enabled(context.Context, slog.Level) bool { return true }
func (h *interopDialObserver) WithAttrs(attrs []slog.Attr) slog.Handler {
	copyHandler := *h
	copyHandler.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &copyHandler
}
func (h *interopDialObserver) WithGroup(string) slog.Handler { return h }
func (h *interopDialObserver) Handle(_ context.Context, record slog.Record) error {
	if record.Message != "dial failed" {
		return nil
	}
	var event interopDialFailure
	read := func(attr slog.Attr) bool {
		if attr.Key == "dest" {
			event.target = attr.Value.String()
		}
		if attr.Key == "err" {
			event.err, _ = attr.Value.Any().(error)
		}
		return true
	}
	for _, attr := range h.attrs {
		read(attr)
	}
	record.Attrs(read)
	select {
	case h.failures <- event:
	default:
	}
	return nil
}

func testMieruOfficialDialFailure(t *testing.T) {
	for _, transport := range []string{"TCP", "UDP"} {
		t.Run(transport, func(t *testing.T) { testMieruOfficialDialFailureTransport(t, transport) })
	}
}

func testMieruOfficialDialFailureTransport(t *testing.T, transport string) {
	origin := startInteropOrigin(t)
	observer := &interopDialObserver{failures: make(chan interopDialFailure, 8)}
	port := freePortTB(t)
	node := New(RuntimeConfig{TrustedProxies: "private", MaxFresh: 64, HandshakeTimeout: 5 * time.Second, Logger: slog.New(observer)})
	if err := node.Start(&model.NodeSpec{Protocol: "mieru", Transport: strings.ToLower(transport), ListenIP: "127.0.0.1", ServerPort: port}, []model.UserSpec{{ID: 1, UUID: "interop:secret"}}, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.Stop)
	client := startMieruOfficial(t, port, transport)
	target := origin.Listener.Addr().String()
	if got := fetchThrough(t, client, target); got != "interop-ok" {
		t.Fatalf("positive control=%q", got)
	}
	origin.Close()
	conn, connectErr := socksNoAuthConnectE(client, target)
	if connectErr == nil {
		_ = conn.Close()
		t.Fatal("closed target unexpectedly connected")
	}
	select {
	case event := <-observer.failures:
		if event.target != target || !errors.Is(event.err, syscall.ECONNREFUSED) {
			t.Fatalf("refusal event target=%q error=%v, client=%v", event.target, event.err, connectErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("closed target did not reach the authenticated core dial path; client=%v", connectErr)
	}
	// Official v3.38.1 proxySocks5ConnReq forwards connResp.Raw verbatim;
	// EOF without a complete REP=05 is a transport/reply regression.
	var replyErr *socksConnectReplyError
	if !errors.As(connectErr, &replyErr) || replyErr.reply != 5 {
		t.Fatalf("core refused target but official client did not forward complete REP=05: %v", connectErr)
	}
	second := startInteropOrigin(t)
	if got := fetchThrough(t, client, second.Listener.Addr().String()); got != "interop-ok" {
		t.Fatalf("client failed after target rejection: %q", got)
	}
}
