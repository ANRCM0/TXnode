package mieru

// Unit coverage for the mieru v2 session cipher state machine: nonce chaining
// per direction, sequence numbers, the SOCKS5 reply emitted by
// core.HandshakeReply and the ACK reply. The official-client interop test in
// internal/kernel/txnode is the wire-level authority; this test keeps the
// record layer covered without a third-party binary.

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// v2TestClient speaks the client half with the handler's derivation. It keeps
// explicit nonce cursors: the client cipher starts with a nonce it sends in its
// first record, and records from the server chain from the server's first nonce.
type v2TestClient struct {
	t      *testing.T
	conn   net.Conn
	aead   cipher.AEAD
	wNonce []byte
	rNonce []byte
}

func newV2TestClient(t *testing.T, conn net.Conn, user, password string) *v2TestClient {
	t.Helper()
	hashed := v2HashedPassword(user, []byte(password))
	// Mirror the reference rounding: time.Round to the 2-minute refresh
	// interval, not integer division (they disagree in each odd window).
	rounded := time.Now().Round(2 * time.Minute).Unix()
	salt := v2TimeSalt(rounded)
	aead, err := v2NewAEAD(v2Derive(hashed[:], salt[:]))
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, v2NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return &v2TestClient{t: t, conn: conn, aead: aead, wNonce: nonce}
}

// writeMeta writes the metadata record (the source connection's first record
// carries the nonce). The payload record is written separately by writePayload
// so the handler's Peek can authenticate before the client blocks.
func (c *v2TestClient) writeMeta(first bool, meta []byte) {
	c.t.Helper()
	nonce := append([]byte(nil), c.wNonce...)
	sealedMeta := c.aead.Seal(nil, nonce, meta, nil)
	v2IncreaseNonce(c.wNonce)
	var out []byte
	if first {
		out = append(out, nonce...)
	}
	out = append(out, sealedMeta...)
	if _, err := c.conn.Write(out); err != nil {
		c.t.Fatalf("write metadata: %v", err)
	}
}

// writePayload writes the payload record under the current nonce.
func (c *v2TestClient) writePayload(payload []byte) {
	c.t.Helper()
	sealed := c.aead.Seal(nil, c.wNonce, payload, nil)
	v2IncreaseNonce(c.wNonce)
	if _, err := c.conn.Write(sealed); err != nil {
		c.t.Fatalf("write payload: %v", err)
	}
}

func (c *v2TestClient) readSegment() (meta, payload []byte) {
	c.t.Helper()
	var buf []byte
	if c.rNonce == nil {
		buf = make([]byte, v2NonceLen+v2MetaLen+v2TagLen)
		if _, err := io.ReadFull(c.conn, buf); err != nil {
			c.t.Fatalf("read metadata: %v", err)
		}
		c.rNonce = append([]byte(nil), buf[:v2NonceLen]...)
	} else {
		buf = make([]byte, v2MetaLen+v2TagLen)
		if _, err := io.ReadFull(c.conn, buf); err != nil {
			c.t.Fatalf("read metadata: %v", err)
		}
	}
	meta, err := c.aead.Open(nil, c.rNonce, buf[len(buf)-(v2MetaLen+v2TagLen):], nil)
	if err != nil {
		c.t.Fatalf("open metadata: %v", err)
	}
	v2IncreaseNonce(c.rNonce)
	payloadLen := int(binary.BigEndian.Uint16(meta[22:24]))
	if payloadLen > 0 {
		body := make([]byte, payloadLen+v2TagLen)
		if _, err := io.ReadFull(c.conn, body); err != nil {
			c.t.Fatalf("read payload: %v", err)
		}
		payload, err = c.aead.Open(nil, c.rNonce, body, nil)
		if err != nil {
			c.t.Fatalf("open payload: %v", err)
		}
		v2IncreaseNonce(c.rNonce)
	}
	return meta, payload
}

func TestV2SessionRecordState(t *testing.T) {
	h, err := NewHandler(Options{
		Users:  []core.User{{ID: 1, UUID: "interop:secret"}},
		Logger: slog.New(slog.DiscardHandler),
		MTU:    1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A loopback socket has a real receive buffer, so the client can send its
	// whole first flight before the handler answers (net.Pipe would deadlock).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptedCh := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		acceptedCh <- accepted{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	acc := <-acceptedCh
	if acc.err != nil {
		t.Fatal(acc.err)
	}
	server := acc.conn
	defer server.Close()

	type result struct {
		sess *core.Session
		err  error
	}
	done := make(chan result, 1)
	go func() {
		sess, err := h.Handle(t.Context(), server)
		done <- result{sess, err}
	}()

	tc := newV2TestClient(t, client, "interop", "secret")
	req := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0x1f, 0x90}
	tc.writeMeta(true, v2SessionMeta(v2ProtoOpenReq, 42, 0, 0, len(req), 0))
	tc.writePayload(req)

	res := <-done
	if res.err != nil {
		t.Fatalf("handle: %v", res.err)
	}
	sess := res.sess
	if got, want := sess.Dest.String(), "127.0.0.1:8080"; got != want {
		t.Fatalf("dest = %s, want %s", got, want)
	}

	// openSessionResponse: metadata only, sequence 0, server nonce first.
	rspMeta, _ := tc.readSegment()
	if rspMeta[0] != v2ProtoOpenRsp || binary.BigEndian.Uint32(rspMeta[6:10]) != 42 {
		t.Fatalf("response meta = %x", rspMeta)
	}
	if binary.BigEndian.Uint32(rspMeta[10:14]) != 0 {
		t.Fatalf("response seq = %d, want 0", binary.BigEndian.Uint32(rspMeta[10:14]))
	}

	// The relay answers the inner SOCKS5 client through core.HandshakeReply.
	reply, ok := sess.Conn.(core.HandshakeReply)
	if !ok {
		t.Fatalf("session conn %T does not implement core.HandshakeReply", sess.Conn)
	}
	if err := reply.HandshakeSucceeded(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}); err != nil {
		t.Fatalf("handshake reply: %v", err)
	}
	dataMeta, data := tc.readSegment()
	if dataMeta[0] != v2ProtoDataS2C || binary.BigEndian.Uint32(dataMeta[10:14]) != 1 {
		t.Fatalf("socks reply meta = %x", dataMeta)
	}
	want := []byte{5, 0, 0, 1, 10, 0, 0, 1, 0x04, 0xd2}
	if string(data) != string(want) {
		t.Fatalf("socks reply = %x, want %x", data, want)
	}

	// Application data continues the server sequence.
	if _, err := sess.Conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	msgMeta, msg := tc.readSegment()
	if msgMeta[0] != v2ProtoDataS2C || binary.BigEndian.Uint32(msgMeta[10:14]) != 2 {
		t.Fatalf("data meta = %x", msgMeta)
	}
	if string(msg) != "hello" {
		t.Fatalf("data = %q", msg)
	}

	// A client data segment must reach the session; a following ACK must be
	// answered with a server ACK carrying the receive cursor.
	tc.writeMeta(false, v2DataMeta(v2ProtoDataC2S, 42, 1, 0, 65535, 0, 5, 0, 0))
	tc.writePayload([]byte("world"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(sess.Conn, buf); err != nil {
		t.Fatalf("session read: %v", err)
	}
	if string(buf) != "world" {
		t.Fatalf("session read = %q", buf)
	}
	tc.writeMeta(false, v2DataMeta(v2ProtoAckC2S, 42, 2, 2, 65535, 0, 0, 0, 0))
	ackMeta, _ := tc.readSegment()
	if ackMeta[0] != v2ProtoAckS2C || binary.BigEndian.Uint32(ackMeta[6:10]) != 42 {
		t.Fatalf("ack meta = %x", ackMeta)
	}
	if got := binary.BigEndian.Uint32(ackMeta[14:18]); got != 2 {
		t.Fatalf("ack unack = %d, want 2", got)
	}
}
