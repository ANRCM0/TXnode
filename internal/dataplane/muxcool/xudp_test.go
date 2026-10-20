package muxcool

import (
	"encoding/hex"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// TestUDPFrameBodyIsDatagram covers the captured shape: the metadata carries the
// target and the frame body is the bare datagram.
func TestUDPFrameBodyIsDatagram(t *testing.T) {
	sess := newUDPSession(nil, 0, socks.Addr{Host: "127.0.0.1", Port: 61104})
	if err := sess.feed([]byte("capture-me")); err != nil {
		t.Fatalf("feed: %v", err)
	}
	buf := make([]byte, 64)
	n, dest, err := sess.ReadPacket(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "capture-me" {
		t.Fatalf("payload = %q", buf[:n])
	}
	if dest.Port != 61104 {
		t.Fatalf("dest = %v", dest)
	}
}

// TestUDPFrameBodyXUDPEnvelope covers a body that carries a full XUDP frame with
// its own destination instead of the session target.
func TestUDPFrameBodyXUDPEnvelope(t *testing.T) {
	body, _ := hex.DecodeString("00180000020102bc74017f000001000a636170747572652d6d65")
	if !looksLikeXUDP(body) {
		t.Fatal("captured XUDP frame not recognised")
	}
	sess := newUDPSession(nil, 0, socks.Addr{Host: "192.0.2.1", Port: 1})
	if err := sess.feed(body); err != nil {
		t.Fatalf("feed: %v", err)
	}
	buf := make([]byte, 64)
	n, dest, err := sess.ReadPacket(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "capture-me" {
		t.Fatalf("payload = %q", buf[:n])
	}
	if dest.String() != "127.0.0.1:48244" {
		t.Fatalf("dest = %v", dest)
	}
}
