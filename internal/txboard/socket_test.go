package txboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/gorilla/websocket"
)

func TestNativeWSSHandshakeSyncAndHeartbeat(t *testing.T) {
	events := make(chan Event, 2)
	pong := make(chan bool, 1)
	statuses := make(chan bool, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != prefix+"/ws" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer native-ws-secret" || r.Header.Get("X-TX-Node-ID") != "42" {
			t.Error("native WS must use identity headers without query tokens")
			w.WriteHeader(401)
			return
		}
		up := websocket.Upgrader{}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"protocol_version": 1, "event": "session.ready", "request_id": "server-1", "data": map[string]any{"mode": "node", "node_id": 42}})
		_ = conn.WriteJSON(map[string]any{"protocol_version": 1, "event": "sync.users", "request_id": "server-2", "data": map[string]any{"users": []any{}}})
		_ = conn.WriteJSON(map[string]any{"protocol_version": 1, "event": "heartbeat.ping", "request_id": "server-3", "data": map[string]any{}})
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			var reply struct {
				Event   string          `json:"event"`
				Version int             `json:"protocol_version"`
				Data    json.RawMessage `json:"data"`
			}
			if err := conn.ReadJSON(&reply); err != nil {
				return
			}
			if reply.Event == "heartbeat.pong" && reply.Version == 1 {
				select {
				case pong <- true:
				default:
				}
				return
			}
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u := "ws" + strings.TrimPrefix(server.URL, "http") + prefix + "/ws"
	s := NewSocket(u, "native-ws-secret", 42, 0, config.WSConfig{HandshakeTimeout: 2, BackoffInitial: 1, BackoffMax: 1},
		func(e Event) {
			select {
			case events <- e:
			default:
			}
		}, func(status bool) {
			select {
			case statuses <- status:
			default:
			}
		})
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	timeout := time.After(5 * time.Second)
	gotEvent, gotPong, gotStatus := false, false, false
	for !(gotEvent && gotPong && gotStatus) {
		select {
		case e := <-events:
			if e.Name == "sync.users" {
				gotEvent = true
			}
		case <-pong:
			gotPong = true
		case status := <-statuses:
			if status {
				gotStatus = true
			}
		case <-timeout:
			t.Fatal("native WS handshake, sync or heartbeat timed out")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("native websocket did not stop")
	}
}

func TestNativeWSCancelBeforeSessionReadyClosesUpgradedConnection(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		<-release
	}))
	defer server.Close()
	defer close(release)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The HTTP upgrade has completed, so DialContext can no longer cancel it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	socket := NewSocket("", "", 42, 0, config.WSConfig{}, nil, nil)
	done := make(chan error, 1)
	go func() { done <- socket.runConnection(ctx, conn, 30*time.Second) }()
	select {
	case err := <-done:
		if err == nil || socket.IsConnected() {
			t.Fatal("canceled unauthenticated session became ready")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled upgraded connection waited for session.ready deadline")
	}
}
