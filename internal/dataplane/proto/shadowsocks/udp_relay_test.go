package shadowsocks

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

func udpTestHandler(t *testing.T, users []core.User) *Handler {
	t.Helper()
	h, err := New(Options{Cipher: "aes-128-gcm", Users: users, UDP: true})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func udpTestDatagram(t *testing.T, h *Handler, index int, dest socks.Addr, payload string) []byte {
	t.Helper()
	pkt, err := h.sealUDP(dest, []byte(payload), &udpKeyState{key: h.users[index].key, user: h.users[index].user}, &udpSession{})
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func udpTestReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("UDP relay did not progress")
		var zero T
		return zero
	}
}

func TestNativeUDPUsesAuthenticatedPacketRelay(t *testing.T) {
	h := udpTestHandler(t, []core.User{{ID: 7, UUID: "first"}, {ID: 8, UUID: "second"}})
	events := make(chan *core.Session, 4)
	h.SetRelay(func(ctx context.Context, sess *core.Session) error {
		events <- sess
		<-sess.Packets.(*udpSession).done
		return nil
	})
	srv := &udpServer{h: h, ctx: context.Background(), sess: make(map[string]*udpSession)}
	defer srv.closeSessions()
	peer := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345}
	dest := socks.Addr{Host: "example.com", Port: 53}
	srv.handle(peer, udpTestDatagram(t, h, 0, dest, "first payload"))
	first := udpTestReceive(t, events)
	if first.UserID != 7 || first.SourceIP != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("relay identity = %+v", first)
	}
	buf := make([]byte, 100)
	n, gotDest, err := first.Packets.ReadPacket(buf)
	if err != nil || gotDest != dest || string(buf[:n]) != "first payload" {
		t.Fatalf("decoded packet = %s %q %v", gotDest, buf[:n], err)
	}
	srv.handle(peer, udpTestDatagram(t, h, 1, dest, "second payload"))
	second := udpTestReceive(t, events)
	if second.UserID != 8 || second.Packets == first.Packets {
		t.Fatal("users sharing an endpoint shared a packet stream")
	}
	_ = first.Packets.Close()
	if _, _, err := first.Packets.ReadPacket(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed read = %v", err)
	}
}

func TestNativeUDPRefreshesCredentialSnapshot(t *testing.T) {
	initial := udpTestHandler(t, []core.User{{ID: 7, UUID: "old"}})
	updated := udpTestHandler(t, []core.User{{ID: 7, UUID: "new"}})
	current := initial
	initial.SetCurrent(func() *Handler { return current })
	events := make(chan *core.Session, 4)
	initial.SetRelay(func(ctx context.Context, sess *core.Session) error {
		events <- sess
		<-sess.Packets.(*udpSession).done
		return nil
	})
	updated.SetRelay(initial.relay)
	srv := &udpServer{h: initial, ctx: context.Background(), sess: make(map[string]*udpSession)}
	defer srv.closeSessions()
	peer := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345}
	dest := socks.Addr{Host: "example.com", Port: 53}
	srv.handle(peer, udpTestDatagram(t, initial, 0, dest, "old"))
	old := udpTestReceive(t, events)
	current = updated
	srv.handle(peer, udpTestDatagram(t, initial, 0, dest, "rejected"))
	select {
	case <-old.Packets.(*udpSession).done:
	default:
		t.Fatal("old credential stream survived snapshot replacement")
	}
	srv.handle(peer, udpTestDatagram(t, updated, 0, dest, "new"))
	next := udpTestReceive(t, events)
	if next.Packets == old.Packets {
		t.Fatal("credential replacement reused old packet stream")
	}
	select {
	case <-events:
		t.Fatal("old credential authenticated after replacement")
	default:
	}
}

type udpTestOutbound struct{ seen chan socks.Addr }

func (*udpTestOutbound) Name() string { return "capture" }
func (*udpTestOutbound) DialTCP(context.Context, socks.Addr) (net.Conn, error) {
	return nil, errors.New("unexpected TCP")
}
func (o *udpTestOutbound) DialPacket(_ context.Context, dest socks.Addr) (core.PacketStream, error) {
	o.seen <- dest
	return &udpTestRemote{done: make(chan struct{})}, nil
}

type udpTestRemote struct {
	once sync.Once
	done chan struct{}
}

func (r *udpTestRemote) ReadPacket([]byte) (int, socks.Addr, error) {
	<-r.done
	return 0, socks.Addr{}, io.EOF
}
func (*udpTestRemote) WritePacket([]byte, socks.Addr) error { return nil }
func (r *udpTestRemote) Close() error                       { r.once.Do(func() { close(r.done) }); return nil }

func TestNativeUDPEnforcesCoreRouting(t *testing.T) {
	h := udpTestHandler(t, []core.User{{ID: 7, UUID: "user"}})
	tracker := core.NewTracker()
	tracker.SetUsers([]core.User{{ID: 7, UUID: "user"}})
	router := core.NewRouter()
	router.BlockPrivate = true
	outbound := &udpTestOutbound{seen: make(chan socks.Addr, 4)}
	router.SetOutbound("capture", outbound)
	router.SetDefault("capture")
	audit := make(chan string, 4)
	server := core.NewServer(core.ServerOptions{Tracker: tracker, Router: func() *core.Router { return router }, OnAudit: func(user int, domain, target, source string) {
		if user == 7 {
			audit <- source
		}
	}})
	defer server.Close()
	h.SetRelay(server.ServeSession)
	srv := &udpServer{h: h, ctx: context.Background(), sess: make(map[string]*udpSession)}
	defer srv.closeSessions()
	peer := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345}
	blocked := socks.Addr{Host: "127.0.0.1", Port: 53}
	allowed := socks.Addr{Host: "example.com", Port: 53}
	srv.handle(peer, udpTestDatagram(t, h, 0, blocked, "blocked"))
	srv.handle(peer, udpTestDatagram(t, h, 0, allowed, "allowed"))
	if got := udpTestReceive(t, outbound.seen); got != allowed {
		t.Fatalf("policy routed blocked target %s", got)
	}
	if source := udpTestReceive(t, audit); source != "198.51.100.7" {
		t.Fatalf("audit source = %q", source)
	}
	select {
	case extra := <-outbound.seen:
		t.Fatalf("unexpected outbound target: %s", extra)
	default:
	}
}
