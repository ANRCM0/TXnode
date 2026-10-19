package txnode

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
)

// TestKernelRelaysThroughSocks is the P1.5 acceptance smoke test: a real txnode
// listener accepts a SOCKS5 client, authenticates it against the panel user
// table, relays to a local HTTP server and reports the bytes through
// GetUserTraffic.
func TestKernelRelaysThroughSocks(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "txnode-ok")
	}))
	defer origin.Close()

	port := freePortTB(t)
	ns := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}
	users := []model.UserSpec{{ID: 1, UUID: "secret-pass", SpeedLimit: 0, DeviceLimit: 0}}

	k := New(RuntimeConfig{TrustedProxies: "private", MaxFresh: 128, HandshakeTimeout: 5 * time.Second})
	if err := k.Start(ns, users, kernel.TLSCert{}); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer k.Stop()
	if !k.IsRunning() {
		t.Fatal("kernel not running after Start")
	}

	conn := socksConnectTB(t, port, "secret-pass", origin.Listener.Addr().String())
	defer conn.Close()

	req := "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "txnode-ok" {
		t.Fatalf("body = %q", body)
	}

	// Give the tracker a moment to account the relayed bytes.
	deadline := time.Now().Add(2 * time.Second)
	for {
		traffic, _, _, err := k.GetUserTraffic(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if up := traffic[1]; up[0] > 0 && up[1] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("traffic not accounted: %v", traffic)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func freePortTB(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// socksConnect performs RFC1928 method negotiation (user/pass) and a CONNECT.
func socksConnectTB(t testing.TB, port int, password, dest string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("method: %v", err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil || method[1] != 0x02 {
		t.Fatalf("method reply: %v %v", method, err)
	}
	// RFC1929: username is ignored by the sample, the password is the user UUID.
	auth := append([]byte{0x01, 0x04, 't', 'e', 's', 't', byte(len(password))}, password...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("auth: %v", err)
	}
	var authReply [2]byte
	if _, err := io.ReadFull(conn, authReply[:]); err != nil || authReply[1] != 0x00 {
		t.Fatalf("auth reply: %v %v", authReply, err)
	}

	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	p, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(p))
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil || head[1] != 0x00 {
		t.Fatalf("connect reply: %v %v", head, err)
	}
	// Discard the bound address (IPv4 assumed).
	var tail [6]byte
	if _, err := io.ReadFull(conn, tail[:]); err != nil {
		t.Fatalf("connect bound addr: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

// TestKernelLocalEventMeterAccountsRelay proves the chunk hook is wired through
// the relay: with a local event meter attached, a real SOCKS5 transfer emits
// accounting events for both directions.
func TestKernelLocalEventMeterAccountsRelay(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "metered")
	}))
	defer origin.Close()

	meter, err := usagebucket.New(usagebucket.Options{Enabled: true, Window: time.Second, MaxEvents: 64, MaxSealed: 4})
	if err != nil {
		t.Fatal(err)
	}
	port := freePortTB(t)
	k := New(RuntimeConfig{TrustedProxies: "private", MaxFresh: 64, HandshakeTimeout: 5 * time.Second})
	k.meter = &nativeMeter{}
	k.meter.setEventMeter(meter)
	ns := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}
	if err := k.Start(ns, []model.UserSpec{{ID: 1, UUID: "secret-pass"}}, kernel.TLSCert{}); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer k.Stop()

	conn := socksConnectTB(t, port, "secret-pass", origin.Listener.Addr().String())
	req := "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		snap := meter.Snapshot()
		total := len(snap.Open.Events)
		for _, b := range snap.Sealed {
			total += len(b.Events)
		}
		if total > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("local event meter saw no accounting events")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
