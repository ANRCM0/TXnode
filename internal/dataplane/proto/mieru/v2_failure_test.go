package mieru

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

type v2PartialFailureConn struct {
	net.Conn
	writes int
	closed bool
}

func (c *v2PartialFailureConn) Write(b []byte) (int, error) {
	c.writes++
	if c.writes == 2 {
		return 3, io.ErrUnexpectedEOF
	}
	return len(b), nil
}

func (c *v2PartialFailureConn) Close() error { c.closed = true; return nil }

func TestV2PartialRecordWritePermanentlyStopsImplicitNonceStream(t *testing.T) {
	wire := &v2PartialFailureConn{}
	aead, err := v2NewAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := &v2Conn{conn: wire, w: aead, wn: make([]byte, v2NonceLen), mtu: 4, wseq: 1, log: slog.New(slog.DiscardHandler)}
	if n, err := c.Write([]byte("12345678")); n != 4 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("accepted business bytes=%d err=%v", n, err)
	}
	if !wire.closed || !c.closed {
		t.Fatal("partially delivered record left its nonce stream reusable")
	}
	if n, err := c.Write([]byte("retry")); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("retry resumed a corrupted record stream: n=%d err=%v", n, err)
	}
	c.wmu.Lock()
	err = c.writeAckLocked()
	c.wmu.Unlock()
	if !errors.Is(err, io.ErrClosedPipe) || wire.writes != 2 {
		t.Fatal("ACK wrote beyond the failed record")
	}
}

func TestV2PacketAbortWaitsForSerializedSendBoundary(t *testing.T) {
	p, pc := v2PacketTestFixture(t)
	p.sendMu.Lock()
	started, finished := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		p.abort(net.ErrClosed)
		close(finished)
	}()
	<-started
	select {
	case <-finished:
		p.sendMu.Unlock()
		t.Fatal("abort returned before the serialized send boundary")
	case <-time.After(50 * time.Millisecond):
	}
	p.sendMu.Unlock()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("abort did not finish after the in-flight send released")
	}
	if err := p.ack(); !errors.Is(err, net.ErrClosed) || len(pc.snapshot()) != 0 {
		t.Fatal("closed session transmitted another packet", err)
	}
}
