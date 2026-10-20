package mieru

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// A finite input stream models peer FIN without opening a local network socket.
// Writes remain available until Close, as on a TCP read half-close.
type v2FiniteTCPConn struct {
	r          *bytes.Reader
	allowEOF   <-chan struct{}
	closedDone chan struct{}
	closeOnce  sync.Once
	mu         sync.Mutex
	written    bytes.Buffer
	closed     bool
}

func (c *v2FiniteTCPConn) Read(p []byte) (int, error) {
	if c.r.Len() == 0 {
		select {
		case <-c.allowEOF:
		case <-c.closedDone:
			return 0, net.ErrClosed
		}
	}
	return c.r.Read(p)
}
func (c *v2FiniteTCPConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.written.Write(p)
}
func (c *v2FiniteTCPConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.closedDone)
	})
	return nil
}
func (*v2FiniteTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (*v2FiniteTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 23456}
}
func (*v2FiniteTCPConn) SetDeadline(time.Time) error      { return nil }
func (*v2FiniteTCPConn) SetReadDeadline(time.Time) error  { return nil }
func (*v2FiniteTCPConn) SetWriteDeadline(time.Time) error { return nil }

func TestV2TCPFrameBoundaryFINKeepsAuthenticatedTailButPartialRecordDoesNot(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "clean-frame-boundary"
		if partial {
			name = "partial-next-metadata"
		}
		t.Run(name, func(t *testing.T) {
			h := nativeUDPTestHandler(t, []core.User{{ID: 7, UUID: "interop:secret"}})
			key := v2PacketTestKey(t, h)
			nonce := make([]byte, v2NonceLen)
			var wire []byte
			appendRecord := func(meta, payload []byte) {
				if len(wire) == 0 {
					wire = append(wire, nonce...)
				}
				wire = key.aead.Seal(wire, nonce, meta, nil)
				v2IncreaseNonce(nonce)
				if len(payload) > 0 {
					wire = key.aead.Seal(wire, nonce, payload, nil)
					v2IncreaseNonce(nonce)
				}
			}
			req := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0x1f, 0x90}
			appendRecord(v2SessionMeta(v2ProtoOpenReq, 51, 0, 0, len(req), 0), req)
			for i, payload := range []string{"first", "second"} {
				appendRecord(v2DataMeta(v2ProtoDataC2S, 51, uint32(i+1), 1, 64, 0, len(payload), 0, 0), []byte(payload))
			}
			if partial {
				wire = append(wire, 0x42)
			}
			allowEOF := make(chan struct{})
			conn := &v2FiniteTCPConn{r: bytes.NewReader(wire), allowEOF: allowEOF, closedDone: make(chan struct{})}
			observed := make(chan error, 1)
			h.SetRelay(func(ctx context.Context, sess *core.Session) error {
				close(allowEOF)
				c := sess.Conn.(*v2Conn)
				if partial {
					<-ctx.Done()
					var one [1]byte
					n, err := c.Read(one[:])
					if n != 0 || !errors.Is(err, net.ErrClosed) {
						observed <- errors.New("partial metadata EOF released a buffered business tail")
					} else {
						observed <- nil
					}
					return nil
				}
				select {
				case <-c.transport.readDone:
				case <-ctx.Done():
					observed <- errors.New("clean FIN cancelled the relay before tail delivery")
					return nil
				}
				got := make([]byte, len("firstsecond"))
				if _, err := io.ReadFull(c, got); err != nil || string(got) != "firstsecond" {
					observed <- errors.New("clean FIN lost or reordered its authenticated queued tail")
					return nil
				}
				var one [1]byte
				if n, err := c.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
					observed <- errors.New("drained FIN did not end its logical read direction")
					return nil
				}
				if n, err := c.Write([]byte("reply-after-FIN")); n != 15 || err != nil {
					observed <- errors.New("clean FIN closed the reply direction before relay completion")
					return nil
				}
				observed <- nil
				return nil
			})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, _ = h.Handle(ctx, conn)
			select {
			case err := <-observed:
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("underlay did not await the authenticated child relay")
			}
		})
	}
}

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
