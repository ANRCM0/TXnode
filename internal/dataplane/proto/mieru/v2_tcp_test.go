package mieru

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

func TestV2TCPUnderlayMultiplexesAfterDialFailureAndSessionClose(t *testing.T) {
	h, err := NewHandler(Options{Users: []core.User{{ID: 7, UUID: "interop:secret"}}, Heartbeat: -1})
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(chan *core.Session, 4)
	h.SetRelay(func(_ context.Context, sess *core.Session) error {
		sessions <- sess
		if !sess.AuthValid() {
			return errors.New("new TCP child lost its authenticated owner")
		}
		if sess.Packets != nil {
			buf := make([]byte, 64)
			for {
				n, dest, err := sess.Packets.ReadPacket(buf)
				if err != nil {
					return err
				}
				if err := sess.Packets.WritePacket(buf[:n], dest); err != nil {
					return err
				}
			}
		}
		reply := sess.Conn.(core.HandshakeReply)
		if sess.Dest.Port == 1 {
			return reply.HandshakeFailed(errors.New("connection refused"))
		}
		if err := reply.HandshakeSucceeded(nil); err != nil {
			return err
		}
		_, err := io.Copy(sess.Conn, sess.Conn)
		return err
	})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { _, err := h.Handle(t.Context(), server); done <- err }()
	tc := newV2TestClient(t, client, "interop", "secret")
	read := func(proto byte, sid uint32) []byte {
		t.Helper()
		meta, payload := tc.readSegment()
		if meta[0] != proto || binary.BigEndian.Uint32(meta[6:10]) != sid {
			t.Fatalf("metadata=%x want protocol=%d session=%d", meta, proto, sid)
		}
		return payload
	}
	request := func(command byte, port byte) []byte { return []byte{5, command, 0, 1, 127, 0, 0, 1, 0, port} }

	// The failed child must emit the explicit SOCKS5 REP05 and then close only
	// its session. A late close response still advances the underlay nonce.
	req := request(1, 1)
	tc.writeMeta(true, v2SessionMeta(v2ProtoOpenReq, 41, 0, 0, len(req), 0))
	tc.writePayload(req)
	read(v2ProtoOpenRsp, 41)
	if reply := read(v2ProtoDataS2C, 41); len(reply) != 10 || reply[0] != 5 || reply[1] != 5 {
		t.Fatalf("dial failure did not carry REP05: %x", reply)
	}
	read(v2ProtoCloseRq, 41)
	tc.writeMeta(false, v2SessionMeta(v2ProtoCloseRs, 41, 2, 0, 0, 0))

	// Empty-open is metadata only. Its later request and business bytes share
	// the new child's sequence space while the cipher cursor keeps advancing.
	tc.writeMeta(false, v2SessionMeta(v2ProtoOpenReq, 42, 0, 0, 0, 0))
	read(v2ProtoOpenRsp, 42)
	data := append(request(1, 2), []byte("ping")...)
	tc.writeMeta(false, v2DataMeta(v2ProtoDataC2S, 42, 1, 1, 64, 0, len(data), 0, 0))
	tc.writePayload(data)
	if reply := read(v2ProtoDataS2C, 42); len(reply) != 10 || reply[1] != 0 {
		t.Fatalf("positive control SOCKS5 reply=%x", reply)
	}
	if got := read(v2ProtoDataS2C, 42); string(got) != "ping" {
		t.Fatalf("positive control payload=%q", got)
	}
	tc.writeMeta(false, v2DataMeta(v2ProtoAckC2S, 42, 1, 3, 64, 0, 0, 0, 0))

	// A concurrent UDP ASSOCIATE uses another logical child of the same TCP
	// transport, with packet-over-stream framing below the common packet relay.
	req = request(3, 0)
	tc.writeMeta(false, v2SessionMeta(v2ProtoOpenReq, 43, 0, 0, len(req), 0))
	tc.writePayload(req)
	read(v2ProtoOpenRsp, 43)
	if reply := read(v2ProtoDataS2C, 43); len(reply) != 10 || reply[1] != 0 {
		t.Fatalf("UDP ASSOCIATE reply=%x", reply)
	}
	packet := []byte{0, 0, 14, 0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 'p', 'o', 'n', 'g', 0xff}
	tc.writeMeta(false, v2DataMeta(v2ProtoDataC2S, 43, 1, 1, 64, 0, len(packet), 0, 0))
	tc.writePayload(packet)
	if got := read(v2ProtoDataS2C, 43); string(got) != string(packet) {
		t.Fatalf("multiplexed packet-over-stream=%x", got)
	}
	tc.writeMeta(false, v2SessionMeta(v2ProtoCloseRq, 43, 2, 0, 0, 0))
	read(v2ProtoCloseRs, 43)

	// Closing the packet child must leave the earlier CONNECT child alive.
	tc.writeMeta(false, v2DataMeta(v2ProtoDataC2S, 42, 2, 2, 64, 0, 5, 0, 0))
	tc.writePayload([]byte("after"))
	if got := read(v2ProtoDataS2C, 42); string(got) != "after" {
		t.Fatalf("unrelated child closed with UDP ASSOCIATE: %q", got)
	}
	tc.writeMeta(false, v2SessionMeta(v2ProtoCloseRq, 42, 3, 0, 0, 0))
	read(v2ProtoCloseRs, 42)
	if len(sessions) != 3 {
		t.Fatalf("logical children bypassed the configured relay: %d", len(sessions))
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP underlay did not release child relays on transport close")
	}
}
