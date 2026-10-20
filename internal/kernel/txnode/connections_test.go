package txnode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

func TestNativeConnectionIDRejectsMalformedAndRestartedIDs(t *testing.T) {
	for _, id := range []string{"", "1", connectionEpoch + ":0", connectionEpoch + ":01", connectionEpoch + ":-1", connectionEpoch + ":18446744073709551616", strings.Repeat("z", 32) + ":1"} {
		if _, err := parseConnectionID(id); !errors.Is(err, kernel.ErrInvalidConnectionID) {
			t.Fatalf("malformed ID %q accepted: %v", id, err)
		}
	}
	stale := strings.Repeat("0", 32)
	if stale == connectionEpoch {
		stale = strings.Repeat("1", 32)
	}
	if _, err := parseConnectionID(stale + ":1"); !errors.Is(err, kernel.ErrConnectionNotFound) {
		t.Fatal("restarted process ID accepted", err)
	}
}

func TestKernelConnectionManagementPreservesOtherSessionsAndReloadOwnership(t *testing.T) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	users := []model.UserSpec{{ID: 7, UUID: "management-secret"}}
	k := New(RuntimeConfig{DrainTimeout: 2 * time.Second})
	ns := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePortTB(t)}
	if err := k.Start(ns, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer k.Stop()
	first := socksConnectTB(t, ns.ServerPort, users[0].UUID, origin.Addr().String())
	defer first.Close()
	second := socksConnectTB(t, ns.ServerPort, users[0].UUID, origin.Addr().String())
	defer second.Close()
	echo := func(c net.Conn, text string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(c, text); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(text))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, []byte(text)) {
			t.Fatalf("echo %q: %q %v", text, got, err)
		}
	}
	echo(first, "first")
	echo(second, "second")
	page, err := k.Connections(t.Context(), "", 1)
	if err != nil || len(page.Connections) != 1 || page.Total != 2 || page.Next == "" {
		t.Fatalf("connection page: %+v %v", page, err)
	}
	firstID := page.Connections[0].ID
	other := New(RuntimeConfig{})
	if err := other.CloseConnection(t.Context(), firstID); !errors.Is(err, kernel.ErrConnectionNotFound) {
		t.Fatal("ID escaped owning Node", err)
	}
	if err := k.Reload(ns, users, kernel.TLSCert{}); err != nil {
		t.Fatal("same-port reload", err)
	}
	if err := k.CloseConnection(t.Context(), firstID); err != nil {
		t.Fatal("draining generation lost ID", err)
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("closed session remained readable")
	}
	echo(second, "still-live")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := k.CloseConnection(ctx, page.Next); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled management request changed a session", err)
	}
	d := k.RuntimeDiagnostics()
	if d["config_generation"] != uint64(2) || d["reload_succeeded"] != uint64(1) || d["connection_close_requests"] != uint64(1) {
		t.Fatal("diagnostic generation or close counters incorrect", d)
	}
	body, err := json.Marshal(d)
	if err != nil || bytes.Contains(body, []byte(users[0].UUID)) || bytes.Contains(body, []byte(origin.Addr().String())) || bytes.Contains(body, []byte(firstID)) {
		t.Fatal("diagnostics exposed sensitive or unbounded identities", string(body), err)
	}
	second.Close()
	k.Stop()
	traffic, _, _, err := k.GetUserTraffic(t.Context())
	if err != nil || traffic[7] != [2]int64{21, 21} {
		t.Fatal("management close lost or duplicated relay tail", traffic, err)
	}
	if err := k.CloseConnection(t.Context(), firstID); !errors.Is(err, kernel.ErrConnectionNotFound) {
		t.Fatal("exited session ID remained active", err)
	}
}
