package tuic

import (
	"bytes"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Mihomo v1.19.32 transport/tuic/v5/protocol.go and sing-quic
// 75c3ac4fa12b/tuic/packet.go both put FRAG_TOTAL before FRAG_ID.
func TestPinnedTUICPacketWire(t *testing.T) {
	fixtures := [][]byte{
		{5, 2, 0x12, 0x34, 0x45, 0x67, 1, 0, 0, 3, 1, 127, 0, 0, 1, 0, 53, 'a', 'b', 'c'},
		{5, 2, 0x12, 0x34, 0x45, 0x67, 2, 1, 0, 3, 255, 'd', 'e', 'f'},
	}
	for _, wire := range fixtures {
		f, err := parsePacketBody(wire[2:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.marshal(), wire) {
			t.Fatalf("marshal=%x want=%x", f.marshal(), wire)
		}
		streamed, err := readFrameFromStream(bytes.NewReader(wire[2:]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(streamed.marshal(), wire) {
			t.Fatalf("stream marshal=%x want=%x", streamed.marshal(), wire)
		}
	}
	for _, bad := range [][]byte{{0, 1, 0, 1, 2, 2, 0, 0, 255}, {0, 1, 0, 1, 1, 1, 0, 0, 255}, {0, 1, 0, 1, 1, 0, 0, 0}, {0, 1, 0, 1, 1, 0, 0, 0, 255, 1}} {
		if _, err := parsePacketBody(bad); err == nil {
			t.Fatalf("malformed packet accepted: %x", bad)
		}
	}
}

func TestTUICInterleavedFragments(t *testing.T) {
	session := &udpSession{}
	addrA := socks.Addr{Host: "127.0.0.1", Port: 53}
	addrB := socks.Addr{Host: "127.0.0.1", Port: 5353}
	// Continuations may arrive before fragment zero; equal fragment counts do
	// not make packets interchangeable. Duplicate fragments do not add bytes.
	for _, f := range []*frame{
		{pktID: 10, fragTotal: 2, fragID: 1, payload: []byte("tail-a")},
		{pktID: 11, fragTotal: 2, fragID: 1, payload: []byte("tail-b")},
		{pktID: 10, fragTotal: 2, fragID: 1, payload: []byte("tail-a")},
	} {
		if payload, _ := session.reassemble(f); payload != nil {
			t.Fatal("incomplete datagram delivered")
		}
	}
	a := &frame{pktID: 10, fragTotal: 2, fragID: 0, hasAddr: true, addr: addrA, payload: []byte("head-a")}
	b := &frame{pktID: 11, fragTotal: 2, fragID: 0, hasAddr: true, addr: addrB, payload: []byte("head-b")}
	if payload, addr := session.reassemble(a); string(payload) != "head-atail-a" || addr != addrA {
		t.Fatalf("packet A=%q addr=%v", payload, addr)
	}
	if payload, addr := session.reassemble(b); string(payload) != "head-btail-b" || addr != addrB {
		t.Fatalf("packet B=%q addr=%v", payload, addr)
	}
	if payload, _ := session.reassemble(a); payload != nil {
		t.Fatal("completed packet replay delivered")
	}
	for id := uint16(100); id < 400; id++ {
		session.reassemble(&frame{pktID: id, fragTotal: 1, hasAddr: true, addr: addrA, payload: []byte("x")})
	}
	if len(session.recent) > 256 {
		t.Fatalf("completion history=%d", len(session.recent))
	}
	// The bounded history allows packet ID reuse after the recent window.
	if payload, _ := session.reassemble(a); payload != nil {
		t.Fatal("incomplete reused ID delivered")
	}
	if payload, _ := session.reassemble(&frame{pktID: 10, fragTotal: 2, fragID: 1, payload: []byte("new")}); string(payload) != "head-anew" {
		t.Fatalf("reused ID=%q", payload)
	}
}

func TestTUICFragmentBounds(t *testing.T) {
	session := &udpSession{}
	addr := socks.Addr{Host: "127.0.0.1", Port: 53}
	for id := uint16(0); id < 70; id++ {
		session.reassemble(&frame{pktID: id, fragTotal: 2, hasAddr: true, addr: addr, payload: []byte("x")})
	}
	if len(session.frags) != 64 {
		t.Fatalf("incomplete packets=%d", len(session.frags))
	}
	for _, set := range session.frags {
		set.created = time.Now().Add(-11 * time.Second)
	}
	session.reassemble(&frame{pktID: 80, fragTotal: 2, hasAddr: true, addr: addr, payload: []byte("x")})
	if len(session.frags) != 1 {
		t.Fatalf("expired packets retained=%d", len(session.frags))
	}
	large := &frame{pktID: 81, fragTotal: 2, hasAddr: true, addr: addr, payload: make([]byte, 65535)}
	session.reassemble(large)
	if payload, _ := session.reassemble(&frame{pktID: 81, fragTotal: 2, fragID: 1, payload: []byte("x")}); payload != nil {
		t.Fatal("oversized assembly accepted")
	}
	base := &frame{assocID: 1, pktID: 2, hasAddr: true, addr: addr}
	fragments := fragment(base, make([]byte, 4096), 1000)
	if len(fragments) != 5 || !fragments[0].hasAddr || fragments[1].hasAddr || fragments[0].fragTotal != 5 {
		t.Fatal("fragment count/address differs from pinned clients")
	}
	if got := fragment(base, make([]byte, 65535), 1); got != nil {
		t.Fatal("unrepresentable fragment count accepted")
	}
}
