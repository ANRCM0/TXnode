//go:build linux

package txnode

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	dataplanemux "github.com/ANRCM0/TX-Node/internal/dataplane/mux"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

type muxLedger struct {
	mu        sync.Mutex
	pending   int
	totals    map[string][2]int64
	closed    map[uint64]string
	completed chan core.Chunk
	invalid   bool
}

func newMuxLedger() *muxLedger {
	return &muxLedger{totals: make(map[string][2]int64), closed: make(map[uint64]string), completed: make(chan core.Chunk, 64)}
}
func (m *muxLedger) Begin(c core.Chunk) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending++
	if c.UserID != 7 || c.ConnID == 0 {
		m.invalid = true
	}
	return c.ConnID, nil
}
func (m *muxLedger) Complete(c core.Chunk, token any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending--
	if token != c.ConnID {
		m.invalid = true
	}
	value := m.totals[c.Path]
	value[int(c.Dir)] += c.N
	m.totals[c.Path] = value
	select {
	case m.completed <- c:
	default:
	}
}
func (m *muxLedger) Close(c core.Chunk) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.closed[c.ConnID]; ok {
		m.invalid = true
	}
	m.closed[c.ConnID] = c.Path
}

func muxTestServer(t *testing.T, ledger *muxLedger, router *core.Router) (*core.Server, *core.Tracker) {
	t.Helper()
	tracker := core.NewTracker()
	tracker.SetUsers([]core.User{{ID: 7, UUID: "mux-owner", DeviceLimit: 1}})
	tracker.SetConnLimit(1)
	server := core.NewServer(core.ServerOptions{Tracker: tracker, Router: func() *core.Router { return router }, Hooks: ledger, HandshakeTimeout: time.Second, UDPTimeout: time.Second})
	t.Cleanup(func() { _ = server.Close() })
	return server, tracker
}

func muxTestPool(t *testing.T, server *core.Server, kind byte) (*dataplanemux.Pool, func(context.Context) (net.Conn, error), <-chan error) {
	t.Helper()
	pool := dataplanemux.NewPool(kind)
	t.Cleanup(func() { _ = pool.Close() })
	done := make(chan error, 1)
	var once sync.Once
	dial := func(ctx context.Context) (net.Conn, error) {
		var conn net.Conn
		once.Do(func() {
			client, parent := net.Pipe()
			conn = client
			go func() {
				done <- server.ServeSession(ctx, &core.Session{UserID: 7, Dest: socks.Addr{Host: "sp.mux.sing-box.arpa", Port: 444}, Conn: parent, SourceIP: netip.MustParseAddr("198.51.100.7"), AuthValid: func() bool { return true }})
			}()
		})
		if conn == nil {
			return nil, fmt.Errorf("unexpected replacement parent")
		}
		return conn, nil
	}
	return pool, dial, done
}

func muxTestAddr(t *testing.T, text string) socks.Addr {
	t.Helper()
	addr, err := netip.ParseAddrPort(text)
	if err != nil {
		t.Fatal(err)
	}
	return socks.Addr{Host: addr.Addr().String(), Port: addr.Port()}
}

func muxTestEchoTCP(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String()
}

func TestNativeMuxPacketOwnershipAndRevocation(t *testing.T) {
	installMuxServer()
	for _, kind := range []byte{dataplanemux.KindSmux, dataplanemux.KindYamux} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			ledger := newMuxLedger()
			server, tracker := muxTestServer(t, ledger, core.NewRouter())
			// Publishing another instance must not choose its policies or accounting.
			otherLedger := newMuxLedger()
			blocked := core.NewRouter()
			blocked.BlockPrivate = true
			other, _ := muxTestServer(t, otherLedger, blocked)
			publishMux(&Kernel{srv: other})
			pool, dial, done := muxTestPool(t, server, kind)
			stream, err := pool.Dial(t.Context(), muxTestAddr(t, muxTestEchoTCP(t)), dial)
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
			payload := []byte("mux-tcp")
			if _, err := stream.Write(payload); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(stream, response); err != nil || !bytes.Equal(response, payload) {
				t.Fatalf("TCP response=%q err=%v", response, err)
			}
			packets, err := pool.DialPacket(t.Context(), socks.Addr{Host: "sp.mux.sing-box.arpa", Port: 444}, dial)
			if err != nil {
				t.Fatal(err)
			}
			wantUDP := int64(0)
			for _, target := range []string{udpEcho(t), udpEcho(t)} {
				dest := muxTestAddr(t, target)
				body := []byte("mux-udp")
				if err := packets.WritePacket(body, dest); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 64)
				n, addr, err := packets.ReadPacket(buffer)
				if err != nil || addr != dest || !bytes.Equal(buffer[:n], body) {
					t.Fatalf("UDP response=%q addr=%v err=%v", buffer[:n], addr, err)
				}
				wantUDP += int64(len(body))
			}
			if alive := tracker.Alive()[7]; len(alive) != 1 || alive[0] != "198.51.100.7" {
				t.Fatalf("source/lease=%v", alive)
			}
			// One accounted parent owns both children; connection limit 1 must not
			// deny the TCP+UDP streams, and revocation cancels both together.
			tracker.SetUsers(nil)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("revoked mux parent/children did not finish")
			}
			ledger.mu.Lock()
			if ledger.pending != 0 || ledger.invalid || len(ledger.closed) != 2 || ledger.totals["udp"] != [2]int64{wantUDP, wantUDP} || ledger.totals["conn"] != [2]int64{int64(len(payload)), int64(len(payload))} {
				t.Errorf("meter pending=%d invalid=%v closed=%v totals=%v", ledger.pending, ledger.invalid, ledger.closed, ledger.totals)
			}
			ledger.mu.Unlock()
			if page := server.ConnectionPage(0, 10); page.Total != 0 {
				t.Fatalf("revoked sessions=%+v", page)
			}
			otherLedger.mu.Lock()
			if otherLedger.pending != 0 || len(otherLedger.totals) != 0 {
				t.Errorf("another node received meter work: %+v", otherLedger.totals)
			}
			otherLedger.mu.Unlock()
		})
	}
}

func TestNativeMuxPacketLimiterCancellation(t *testing.T) {
	installMuxServer()
	for _, kind := range []byte{dataplanemux.KindSmux, dataplanemux.KindYamux} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			ledger := newMuxLedger()
			server, tracker := muxTestServer(t, ledger, core.NewRouter())
			tracker.SetUserLimit(7, 1, 1, 1)
			pool, dial, done := muxTestPool(t, server, kind)
			packets, err := pool.DialPacket(t.Context(), socks.Addr{Host: "127.0.0.1", Port: 53}, dial)
			if err != nil {
				t.Fatal(err)
			}
			if err := packets.WritePacket(bytes.Repeat([]byte{'x'}, 4096), muxTestAddr(t, udpEcho(t))); err != nil {
				t.Fatal(err)
			}
			select {
			case chunk := <-ledger.completed:
				if chunk.N != 4096 || chunk.Path != "udp" || chunk.Dir != core.DirUpload {
					t.Fatalf("upload chunk=%+v", chunk)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("packet did not reach core before limiter")
			}
			// Parent disconnect must cancel limiter waits before waiting for child
			// meter tails, rather than waiting thousands of seconds for tokens.
			_ = pool.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("parent disconnect left limiter/child blocked")
			}
			ledger.mu.Lock()
			defer ledger.mu.Unlock()
			if ledger.pending != 0 || ledger.invalid || ledger.totals["udp"] != [2]int64{4096, 0} || len(ledger.closed) != 1 {
				t.Fatalf("limiter tail pending=%d invalid=%v totals=%v closed=%v", ledger.pending, ledger.invalid, ledger.totals, ledger.closed)
			}
		})
	}
}

func TestNativeMuxPacketRouteBlocked(t *testing.T) {
	installMuxServer()
	for _, kind := range []byte{dataplanemux.KindSmux, dataplanemux.KindYamux} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			ledger := newMuxLedger()
			router := core.NewRouter()
			router.BlockPrivate = true
			server, _ := muxTestServer(t, ledger, router)
			// A permissive second node cannot override the parent's route table.
			other, _ := muxTestServer(t, newMuxLedger(), core.NewRouter())
			publishMux(&Kernel{srv: other})
			target, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			pool, dial, done := muxTestPool(t, server, kind)
			packets, err := pool.DialPacket(t.Context(), socks.Addr{Host: "sp.mux.sing-box.arpa", Port: 444}, dial)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("blocked-mux-packet")
			if err := packets.WritePacket(payload, muxTestAddr(t, target.LocalAddr().String())); err != nil {
				t.Fatal(err)
			}
			select {
			case chunk := <-ledger.completed:
				if chunk.Path != "udp" || chunk.Dir != core.DirUpload || chunk.N != int64(len(payload)) {
					t.Fatalf("blocked upload=%+v", chunk)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocked packet did not enter owning core")
			}
			_ = target.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, _, err := target.ReadFrom(make([]byte, 64)); err == nil {
				t.Fatal("private packet escaped owning route policy")
			} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				t.Fatalf("blocked target read: %v", err)
			}
			_ = pool.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("blocked packet parent did not finish")
			}
			ledger.mu.Lock()
			defer ledger.mu.Unlock()
			if ledger.pending != 0 || ledger.invalid || len(ledger.closed) != 1 || ledger.totals["udp"] != [2]int64{int64(len(payload)), 0} {
				t.Fatalf("blocked accounting pending=%d invalid=%v totals=%v closed=%v", ledger.pending, ledger.invalid, ledger.totals, ledger.closed)
			}
		})
	}
}
