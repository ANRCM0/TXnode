package mieru

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

func nativeUDPTestHandler(t *testing.T, users []core.User) *Handler {
	t.Helper()
	h, err := NewHandler(Options{Users: users, Iterations: 1})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func nativeUDPTestPacket(t *testing.T, h *Handler, index int, seq uint32, dest socks.Addr, payload string) []byte {
	t.Helper()
	cipher, err := newSegmentCipher(h.keys[index].key)
	if err != nil {
		t.Fatal(err)
	}
	return cipher.seal(segPacket, uint32(time.Now().Unix()), seq, append(encodeAddr(dest), []byte(payload)...))
}
func nativeUDPTestReceive(t *testing.T, ch <-chan *core.Session) *core.Session {
	t.Helper()
	select {
	case sess := <-ch:
		return sess
	case <-time.After(3 * time.Second):
		t.Fatal("native UDP relay did not progress")
		return nil
	}
}
func TestNativeMieruUDPUsesAuthenticatedRelay(t *testing.T) {
	h := nativeUDPTestHandler(t, []core.User{{ID: 4, UUID: "one:password"}, {ID: 5, UUID: "two:password"}})
	events := make(chan *core.Session, 4)
	h.SetRelay(func(ctx context.Context, sess *core.Session) error { events <- sess; <-ctx.Done(); return ctx.Err() })
	srv := &udpServer{pc: &nativeUDPTestConn{}, owner: h, ctx: context.Background(), peers: make(map[string]*udpPeer)}
	defer srv.closePeers()
	peer := &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 12345}
	dest := socks.Addr{Host: "example.com", Port: 53}
	srv.handle(peer, nativeUDPTestPacket(t, h, 0, 1, dest, "first"))
	first := nativeUDPTestReceive(t, events)
	if first.UserID != 4 || first.SourceIP != netip.MustParseAddr("198.51.100.4") || !first.AuthValid() {
		t.Fatalf("native UDP identity = %+v", first)
	}
	buf := make([]byte, 100)
	n, gotDest, err := first.Packets.ReadPacket(buf)
	if err != nil || gotDest != dest || string(buf[:n]) != "first" {
		t.Fatalf("native packet = %s %q %v", gotDest, buf[:n], err)
	}
	srv.handle(peer, nativeUDPTestPacket(t, h, 1, 1, dest, "second"))
	second := nativeUDPTestReceive(t, events)
	if second.UserID != 5 || second.Packets == first.Packets {
		t.Fatal("different authenticated users shared a packet stream")
	}
	_ = first.Packets.Close()
	if _, _, err := first.Packets.ReadPacket(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed packet read = %v", err)
	}
}
func TestNativeMieruUDPRejectsStaleCredentialSnapshot(t *testing.T) {
	old := nativeUDPTestHandler(t, []core.User{{ID: 4, UUID: "user:old"}})
	next := nativeUDPTestHandler(t, []core.User{{ID: 4, UUID: "user:new"}})
	current := old
	old.SetCurrent(func() *Handler { return current })
	events := make(chan *core.Session, 4)
	relay := func(ctx context.Context, sess *core.Session) error { events <- sess; <-ctx.Done(); return ctx.Err() }
	old.SetRelay(relay)
	next.SetRelay(relay)
	srv := &udpServer{pc: &nativeUDPTestConn{}, owner: old, ctx: context.Background(), peers: make(map[string]*udpPeer)}
	defer srv.closePeers()
	peer := &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 12345}
	dest := socks.Addr{Host: "example.com", Port: 53}
	srv.handle(peer, nativeUDPTestPacket(t, old, 0, 1, dest, "old"))
	previous := nativeUDPTestReceive(t, events)
	current = next
	srv.handle(peer, nativeUDPTestPacket(t, old, 0, 2, dest, "must reject"))
	if previous.AuthValid() {
		t.Fatal("old UDP admission proof remained valid")
	}
	select {
	case <-previous.Packets.(*udpPeer).done:
	default:
		t.Fatal("old UDP stream remained open")
	}
	srv.handle(peer, nativeUDPTestPacket(t, next, 0, 1, dest, "new"))
	accepted := nativeUDPTestReceive(t, events)
	if accepted.Packets == previous.Packets || !accepted.AuthValid() {
		t.Fatal("new UDP credential did not get a fresh admitted stream")
	}
	select {
	case <-events:
		t.Fatal("stale credentials reached relay")
	default:
	}
}

func TestNativeMieruUDPReplaySurvivesUserRefresh(t *testing.T) {
	users := []core.User{{ID: 4, UUID: "user:secret"}}
	old := nativeUDPTestHandler(t, users)
	next := nativeUDPTestHandler(t, users)
	next.InheritSecurityState(old)
	current := old
	old.SetCurrent(func() *Handler { return current })
	events := make(chan *core.Session, 4)
	relay := func(ctx context.Context, sess *core.Session) error { events <- sess; <-ctx.Done(); return ctx.Err() }
	old.SetRelay(relay)
	next.SetRelay(relay)
	srv := &udpServer{pc: &nativeUDPTestConn{}, owner: old, ctx: context.Background(), peers: make(map[string]*udpPeer)}
	defer srv.closePeers()
	peer := &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 12345}
	dest := socks.Addr{Host: "example.com", Port: 53}
	packet := nativeUDPTestPacket(t, old, 0, 1, dest, "first")
	srv.handle(peer, packet)
	_ = nativeUDPTestReceive(t, events)
	oldLater := nativeUDPTestPacket(t, old, 0, 3, dest, "old generation future sequence")
	srv.handle(peer, oldLater)
	current = next
	srv.handle(peer, packet)
	srv.handle(peer, nativeUDPTestPacket(t, next, 0, 2, dest, "fresh"))
	srv.handle(peer, oldLater)
	accepted := nativeUDPTestReceive(t, events)
	buf := make([]byte, 100)
	n, _, err := accepted.Packets.ReadPacket(buf)
	if err != nil || string(buf[:n]) != "fresh" {
		t.Fatalf("replayed native packet passed refreshed credentials: %q %v", buf[:n], err)
	}
	if len(accepted.Packets.(*udpPeer).ps.ready) != 0 {
		t.Fatal("old generation ciphertext was delivered into an existing new peer")
	}
	select {
	case <-events:
		t.Fatal("replayed native UDP packet opened another stream")
	default:
	}
}

type nativeUDPTestConn struct{ sent chan []byte }

func (*nativeUDPTestConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *nativeUDPTestConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.sent != nil {
		c.sent <- append([]byte(nil), p...)
	}
	return len(p), nil
}
func (*nativeUDPTestConn) Close() error                     { return nil }
func (*nativeUDPTestConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*nativeUDPTestConn) SetDeadline(time.Time) error      { return nil }
func (*nativeUDPTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*nativeUDPTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestNativeMieruUDPRetransmissionIsAcknowledgedOncePerAttempt(t *testing.T) {
	h := nativeUDPTestHandler(t, []core.User{{ID: 4, UUID: "user:secret"}})
	events := make(chan *core.Session, 4)
	h.SetRelay(func(ctx context.Context, sess *core.Session) error { events <- sess; <-ctx.Done(); return ctx.Err() })
	pc := &nativeUDPTestConn{sent: make(chan []byte, 4)}
	srv := &udpServer{owner: h, ctx: context.Background(), pc: pc, peers: make(map[string]*udpPeer)}
	defer srv.closePeers()
	peer := &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 12345}
	dest := socks.Addr{Host: "example.com", Port: 53}
	packet := nativeUDPTestPacket(t, h, 0, 1, dest, "payload")
	srv.handle(peer, packet)
	sess := nativeUDPTestReceive(t, events)
	srv.handle(peer, packet)
	for i := 0; i < 2; i++ {
		select {
		case raw := <-pc.sent:
			_, ack, _, err := h.identify(raw)
			if err != nil || ack.flags&flagAck == 0 || len(ack.payload) != 4 || binary.BigEndian.Uint32(ack.payload) != 1 {
				t.Fatalf("ACK %d = %+v %v", i, ack, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("retransmitted data was not acknowledged again")
		}
	}
	stream := sess.Packets.(*udpPeer)
	buf := make([]byte, 100)
	n, _, err := stream.ReadPacket(buf)
	if err != nil || string(buf[:n]) != "payload" {
		t.Fatalf("delivered payload = %q %v", buf[:n], err)
	}
	if len(stream.ps.ready) != 0 {
		t.Fatal("retransmission duplicated application delivery")
	}
	select {
	case <-events:
		t.Fatal("retransmission opened another relay stream")
	default:
	}
}
