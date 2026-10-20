package mieru

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

type v2CapturePacketConn struct {
	mu      sync.Mutex
	packets [][]byte
}

func (*v2CapturePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *v2CapturePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.packets) < 4096 {
		c.packets = append(c.packets, append([]byte(nil), b...))
	}
	return len(b), nil
}
func (c *v2CapturePacketConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.packets...)
}
func (*v2CapturePacketConn) Close() error                     { return nil }
func (*v2CapturePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{Port: 12345} }
func (*v2CapturePacketConn) SetDeadline(time.Time) error      { return nil }
func (*v2CapturePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*v2CapturePacketConn) SetWriteDeadline(time.Time) error { return nil }

func v2PacketTestKey(t *testing.T, h *Handler) *v2Key {
	t.Helper()
	u := h.keys[0]
	hash := v2HashedPassword(u.name, u.password)
	sec := time.Now().Round(2 * time.Minute).Unix()
	salt := v2TimeSalt(sec)
	key := v2Derive(hash[:], salt[:])
	aead, err := v2NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	return &v2Key{user: u, key: key, aead: aead, salt: salt, saltSec: sec}
}

func v2PacketTestFixture(t *testing.T) (*v2DatagramConn, *v2CapturePacketConn) {
	t.Helper()
	h := nativeUDPTestHandler(t, []core.User{{ID: 7, UUID: "interop:secret"}})
	pc := &v2CapturePacketConn{}
	srv := &udpServer{owner: h, ctx: t.Context(), pc: pc, peers: make(map[string]*udpPeer), v2Peers: make(map[string]*v2DatagramConn)}
	ctx, cancel := context.WithCancel(t.Context())
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 12345}
	now := time.Now()
	p := &v2DatagramConn{
		srv: srv, handler: h, key: v2PacketTestKey(t, h), client: addr, id: 41,
		peerKey: v2PacketKey(addr, 7, 41), ctx: ctx, cancel: cancel,
		done: make(chan struct{}), appDone: make(chan struct{}), notify: make(chan struct{}, 1),
		nextRecv: 1, nextSend: 1, window: v2PacketWindow,
		reorder: make(map[uint32]v2Datagram), pending: make(map[uint32]*v2Pending),
		lastRX: now, lastTX: now, created: now,
	}
	srv.v2Peers[p.peerKey] = p
	h.packetServer.Store(srv)
	t.Cleanup(func() { p.abort(nil) })
	return p, pc
}

func v2TestInput(id, seq, ack uint32, payload string) v2Datagram {
	return v2Datagram{meta: v2DataMeta(v2ProtoDataC2S, id, seq, ack, v2PacketWindow, 0, len(payload), 0, 0), payload: []byte(payload)}
}

func TestV2PacketReorderingDuplicatesAndWindowNeverRedeliverBusinessBytes(t *testing.T) {
	p, _ := v2PacketTestFixture(t)
	p.input(v2TestInput(p.id, 2, 0, "second"))
	p.input(v2TestInput(p.id, 2, 0, "second"))
	if len(p.ready) != 0 || len(p.reorder) != 1 {
		t.Fatal("out-of-order data escaped the receive window")
	}
	p.input(v2TestInput(p.id, 1, 0, "first"))
	p.input(v2TestInput(p.id, 1, 0, "first"))
	if p.nextRecv != 3 || len(p.reorder) != 0 || len(p.ready) != 2 {
		t.Fatal("receive cursor did not advance exactly once")
	}
	if err := p.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("firstsecond"))
	if _, err := io.ReadFull(p, got); err != nil || string(got) != "firstsecond" {
		t.Fatalf("application stream=%q err=%v", got, err)
	}
	p.input(v2TestInput(p.id, p.nextRecv+v2PacketWindow, 0, "outside"))
	p.input(v2TestInput(p.id, p.nextRecv, 0, string(make([]byte, v2ReceiveBudget+1))))
	diagnostic := p.handler.PacketDiagnostics()
	if diagnostic["duplicate_packets"] != 2 || diagnostic["dropped_packets"] != 2 || diagnostic["reassembly_bytes"] != 0 {
		t.Fatalf("bounded receive diagnostics=%v", diagnostic)
	}
	if len(diagnostic) != 6 {
		t.Fatal("diagnostic labels became unbounded")
	}
}

func TestV2PacketRetransmissionKeepsBusinessSequenceAndAckIsCumulative(t *testing.T) {
	p, pc := v2PacketTestFixture(t)
	if n, err := p.Write([]byte("once")); err != nil || n != 4 {
		t.Fatalf("write=%d err=%v", n, err)
	}
	if !p.step(time.Now().Add(300 * time.Millisecond)) {
		t.Fatal("session failed during first retry")
	}
	packets := pc.snapshot()
	if len(packets) != 2 || bytes.Equal(packets[0][:v2NonceLen], packets[1][:v2NonceLen]) {
		t.Fatal("retransmission did not use an independent explicit nonce")
	}
	for _, wire := range packets {
		meta, err := p.key.aead.Open(nil, wire[:v2NonceLen], wire[v2NonceLen:v2NonceLen+v2MetaLen+v2TagLen], nil)
		if err != nil || binary.BigEndian.Uint32(meta[10:14]) != 1 {
			t.Fatalf("retransmitted metadata=%x err=%v", meta, err)
		}
		plain, err := p.key.aead.Open(nil, wire[:v2NonceLen], wire[v2NonceLen+v2MetaLen+v2TagLen:], nil)
		if err != nil || string(plain) != "once" {
			t.Fatalf("retransmitted plaintext=%q err=%v", plain, err)
		}
	}
	// An impossible ACK must not erase the retained original data.
	p.input(v2Datagram{meta: v2DataMeta(v2ProtoAckC2S, p.id, 0, 3, 64, 0, 0, 0, 0)})
	if len(p.pending) != 1 {
		t.Fatal("ACK beyond the send cursor erased evidence")
	}
	p.input(v2Datagram{meta: v2DataMeta(v2ProtoAckC2S, p.id, 0, 2, 64, 0, 0, 0, 0)})
	if len(p.pending) != 0 || p.remoteAck != 2 || p.nextSend != 2 {
		t.Fatal("cumulative ACK did not advance the send window")
	}
	if p.handler.PacketDiagnostics()["retransmissions"] != 1 {
		t.Fatal("retransmission diagnostic was not bounded to the protocol layer")
	}
}

func TestV2PacketRetryBudgetClosesInsteadOfSilentlySkippingSequence(t *testing.T) {
	p, _ := v2PacketTestFixture(t)
	if _, err := p.Write([]byte("pending")); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.pending[1].tries = v2TransmissionLimit
	p.pending[1].last = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if p.step(time.Now()) {
		t.Fatal("exhausted reliable segment was silently skipped")
	}
	if !p.closed || len(p.pending) != 0 || p.handler.PacketDiagnostics()["dropped_packets"] != 1 {
		t.Fatal("retry exhaustion did not close and release its bounded state")
	}
}

func TestV2PacketReplayTombstoneSurvivesCredentialSnapshotReplacement(t *testing.T) {
	p, _ := v2PacketTestFixture(t)
	if !p.handler.reserveV2Session(p.key, p.id) {
		t.Fatal("first session identity rejected")
	}
	next := nativeUDPTestHandler(t, []core.User{{ID: 7, UUID: "interop:secret"}})
	next.InheritSecurityState(p.handler)
	if next.reserveV2Session(v2PacketTestKey(t, next), p.id) {
		t.Fatal("re-encrypted old session identity revived after snapshot replacement")
	}
	var current atomic.Pointer[Handler]
	current.Store(p.handler)
	p.handler.SetCurrent(func() *Handler { return current.Load() })
	current.Store(next)
	if _, err := p.Write([]byte("old")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("obsolete packet writer reopened: %v", err)
	}
	if _, err := p.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("obsolete packet reader reopened: %v", err)
	}
}

func TestV2PacketOpenPiggybackAndDelayedSOCKSRequestEnterCommonRelay(t *testing.T) {
	for _, piggyback := range []bool{true, false} {
		t.Run(map[bool]string{true: "piggyback", false: "delayed"}[piggyback], func(t *testing.T) {
			h := nativeUDPTestHandler(t, []core.User{{ID: 7, UUID: "interop:secret"}})
			key := v2PacketTestKey(t, h)
			pc := &v2CapturePacketConn{}
			srv := &udpServer{owner: h, ctx: t.Context(), pc: pc, peers: make(map[string]*udpPeer), v2Peers: make(map[string]*v2DatagramConn)}
			t.Cleanup(srv.closePeers)
			sessions := make(chan *core.Session, 2)
			h.SetRelay(func(ctx context.Context, sess *core.Session) error { sessions <- sess; <-ctx.Done(); return ctx.Err() })
			addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 23456}
			request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0x1f, 0x90}
			var nonce [v2NonceLen]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				t.Fatal(err)
			}
			v2HintNonce(nonce[:], "interop")
			payload := append(append([]byte(nil), request...), []byte("business")...)
			if !piggyback {
				payload = nil
			}
			meta := v2SessionMeta(v2ProtoOpenReq, 17, 0, 0, len(payload), 0)
			wire := append([]byte(nil), nonce[:]...)
			wire = key.aead.Seal(wire, nonce[:], meta, nil)
			if len(payload) > 0 {
				wire = key.aead.Seal(wire, nonce[:], payload, nil)
			}
			srv.handle(addr, wire)
			if !piggyback {
				data := append(append([]byte(nil), request...), []byte("business")...)
				dataMeta := v2DataMeta(v2ProtoDataC2S, 17, 1, 1, 64, 0, len(data), 0, 0)
				nonce[0] ^= 0x80
				flight := append([]byte(nil), nonce[:]...)
				flight = key.aead.Seal(flight, nonce[:], dataMeta, nil)
				flight = key.aead.Seal(flight, nonce[:], data, nil)
				srv.handle(addr, flight)
			}
			sess := nativeUDPTestReceive(t, sessions)
			if sess.Conn == nil || sess.Packets != nil || sess.UserID != 7 || sess.Dest.String() != "127.0.0.1:8080" || !sess.AuthValid() {
				t.Fatal("official UDP underlay bypassed the common stream session contract")
			}
			_ = sess.Conn.SetReadDeadline(time.Now().Add(time.Second))
			got := make([]byte, 8)
			if _, err := io.ReadFull(sess.Conn, got); err != nil || string(got) != "business" {
				t.Fatalf("piggyback remainder=%q err=%v", got, err)
			}
			srv.handle(addr, wire)
			select {
			case <-sessions:
				t.Fatal("duplicate open entered another relay session")
			default:
			}
		})
	}
}
