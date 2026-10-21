package txboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/gorilla/websocket"
)

type Event struct {
	Name   string
	NodeID int
	Data   json.RawMessage
}
type frame struct {
	Version   int             `json:"protocol_version"`
	Event     string          `json:"event"`
	RequestID string          `json:"request_id"`
	Data      json.RawMessage `json:"data"`
}
type Socket struct {
	url, token        string
	nodeID, machineID int
	cfg               config.WSConfig
	onEvent           func(Event)
	onStatus          func(bool)
	connected         atomic.Bool
	send              chan []byte
}

func NewSocket(url, token string, nodeID, machineID int, cfg config.WSConfig, onEvent func(Event), onStatus func(bool)) *Socket {
	return &Socket{url: url, token: token, nodeID: nodeID, machineID: machineID, cfg: cfg,
		onEvent: onEvent, onStatus: onStatus, send: make(chan []byte, 128)}
}
func (s *Socket) IsConnected() bool { return s.connected.Load() }
func (s *Socket) Send(event string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	var b [16]byte
	if _, err = rand.Read(b[:]); err != nil {
		return
	}
	msg, err := json.Marshal(frame{Version: 1, Event: event, RequestID: hex.EncodeToString(b[:]), Data: data})
	if err != nil || len(msg) > 1<<20 {
		return
	}
	select {
	case s.send <- msg:
	default:
	}
}
func (s *Socket) Run(ctx context.Context) {
	backoff := time.Duration(s.cfg.BackoffInitial) * time.Second
	if backoff <= 0 {
		backoff = time.Second
	}
	maxBackoff := time.Duration(s.cfg.BackoffMax) * time.Second
	if maxBackoff < backoff {
		maxBackoff = 60 * time.Second
	}
	for ctx.Err() == nil {
		if err := s.connect(ctx); err != nil && ctx.Err() == nil {
			// Never log an authenticated URL, bearer token or untrusted frame.
			_ = err
		}
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
func (s *Socket) connect(ctx context.Context) error {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+s.token)
	if s.machineID > 0 {
		headers.Set("X-TX-Machine-ID", fmt.Sprint(s.machineID))
	}
	if s.nodeID > 0 {
		headers.Set("X-TX-Node-ID", fmt.Sprint(s.nodeID))
	}
	timeout := time.Duration(s.cfg.HandshakeTimeout) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	conn, _, err := (&websocket.Dialer{HandshakeTimeout: timeout}).DialContext(ctx, s.url, headers)
	if err != nil {
		return err
	}
	return s.runConnection(ctx, conn, timeout)
}
func (s *Socket) runConnection(ctx context.Context, conn *websocket.Conn, timeout time.Duration) error {
	defer conn.Close()
	// Cancellation must also interrupt session.ready reads and blocked writes.
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var first frame
	if err := conn.ReadJSON(&first); err != nil {
		return err
	}
	if first.Version != 1 || first.Event != "session.ready" {
		return errors.New("TXBoard WS missing session.ready")
	}
	var ready struct {
		Mode      string `json:"mode"`
		NodeID    *int   `json:"node_id"`
		MachineID *int   `json:"machine_id"`
	}
	if err := json.Unmarshal(first.Data, &ready); err != nil {
		return err
	}
	if s.machineID > 0 {
		if ready.Mode != "machine" || ready.MachineID == nil || *ready.MachineID != s.machineID {
			return errors.New("TXBoard WS machine identity mismatch")
		}
	} else if ready.Mode != "node" || ready.NodeID == nil || *ready.NodeID != s.nodeID {
		return errors.New("TXBoard WS node identity mismatch")
	}
	_ = conn.SetReadDeadline(time.Time{})
	s.connected.Store(true)
	if s.onStatus != nil {
		s.onStatus(true)
	}
	defer func() {
		s.connected.Store(false)
		if s.onStatus != nil {
			s.onStatus(false)
		}
	}()
	incoming := make(chan frame, 32)
	errCh := make(chan error, 1)
	go func() {
		defer close(incoming)
		for {
			var f frame
			if err := conn.ReadJSON(&f); err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			select {
			case incoming <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	heartbeat := time.NewTicker(55 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		case f, ok := <-incoming:
			if !ok {
				return errors.New("TXBoard WS reader stopped")
			}
			if f.Version != 1 {
				return errors.New("TXBoard WS protocol version mismatch")
			}
			if f.Event == "heartbeat.ping" {
				s.Send("heartbeat.pong", map[string]any{})
				continue
			}
			if f.Event == "error" {
				return errors.New("TXBoard WS server reported error")
			}
			if f.Event == "heartbeat.ack" || f.Event == "traffic.ack" || f.Event == "sync.ack" || f.Event == "ops.ack" {
				continue
			}
			var data map[string]json.RawMessage
			if err := json.Unmarshal(f.Data, &data); err != nil {
				continue
			}
			var nodeID int
			_ = json.Unmarshal(data["node_id"], &nodeID)
			if s.onEvent != nil {
				s.onEvent(Event{Name: f.Event, NodeID: nodeID, Data: f.Data})
			}
		case <-heartbeat.C:
			s.Send("heartbeat.ping", map[string]any{})
		case b := <-s.send:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
				return err
			}
		}
	}
}
