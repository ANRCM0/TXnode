package yamux

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

type completionConn struct {
	mu       sync.Mutex
	wire     bytes.Buffer
	entered  chan struct{}
	release  chan struct{}
	closed   chan struct{}
	once     sync.Once
	accepted int
}

func (c *completionConn) Read([]byte) (int, error) { <-c.closed; return 0, io.EOF }
func (c *completionConn) Write(b []byte) (int, error) {
	n := len(b)
	gate := c.entered != nil && len(b) != headerSize
	if gate && c.accepted >= 0 {
		n = c.accepted
	}
	c.mu.Lock()
	_, _ = c.wire.Write(b[:n])
	c.mu.Unlock()
	if gate {
		close(c.entered)
		<-c.release
		return n, io.ErrClosedPipe
	}
	return n, nil
}
func (c *completionConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

func completionWait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("write completion did not finish")
		var zero T
		return zero
	}
}

func TestWriteCompletionSurvivesShutdown(t *testing.T) {
	for _, accepted := range []int{-1, 3, 0} {
		t.Run(map[int]string{-1: "full", 3: "partial", 0: "header-only"}[accepted], func(t *testing.T) {
			c := &completionConn{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), accepted: accepted}
			cfg := DefaultConfig()
			cfg.EnableKeepAlive = false
			cfg.ConnectionWriteTimeout = 2 * time.Second
			s := newSession(cfg, c, true)
			stream := newStream(s, 1, streamEstablished)
			result := make(chan writeResult, 1)
			go func() { n, err := stream.Write([]byte("payload")); result <- writeResult{n, err} }()
			completionWait(t, c.entered)
			closed := make(chan error, 1)
			go func() { closed <- s.Close() }()
			completionWait(t, c.closed)
			select {
			case value := <-result:
				t.Fatalf("returned before actual writer completion: %+v", value)
			default:
			}
			close(c.release)
			value := completionWait(t, result)
			_ = completionWait(t, closed)
			want := accepted
			if want < 0 {
				want = len("payload")
			}
			if value.n != want || !errors.Is(value.err, io.ErrClosedPipe) {
				t.Fatalf("result=%+v want n=%d with shutdown error", value, want)
			}
		})
	}
}

func TestQueuedWriteCancellationKeepsSibling(t *testing.T) {
	c := &completionConn{closed: make(chan struct{})}
	cfg := DefaultConfig()
	cfg.ConnectionWriteTimeout = time.Second
	s := &Session{conn: c, config: cfg, sendCh: make(chan *sendReady, 4), shutdownCh: make(chan struct{}), sendDoneCh: make(chan struct{}), logger: log.New(io.Discard, "", 0)}
	hdr := header(make([]byte, headerSize))
	body := []byte("cancelled")
	hdr.encode(typeData, 0, 1, uint32(len(body)))
	state := newWriteState()
	queued := &sendReady{Hdr: hdr, Body: body, state: state}
	// Cancel before dispatch directly; there is no scheduling or short timer
	// race determining whether the original request reached the send queue.
	if n, err := state.cancel(ErrConnectionWriteTimeout); n != 0 || !errors.Is(err, ErrConnectionWriteTimeout) {
		t.Fatalf("queued cancellation n=%d err=%v", n, err)
	}
	copy(body, "reused!!!")
	for i := range hdr {
		hdr[i] = 0
	}
	s.sendCh <- queued
	done := make(chan error, 1)
	go func() { done <- s.sendLoop() }()
	defer func() { close(s.shutdownCh); _ = c.Close(); _ = completionWait(t, done) }()
	other := newStream(s, 3, streamEstablished)
	if n, err := other.Write([]byte("sibling")); err != nil || n != len("sibling") {
		t.Fatalf("sibling n=%d err=%v", n, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.wire.Bytes(); len(got) != headerSize+len("sibling") || !bytes.Equal(got[headerSize:], []byte("sibling")) {
		t.Fatalf("cancelled data reached the wire: %q", got)
	}
}

func TestChildCloseKeepsSibling(t *testing.T) {
	a, b := net.Pipe()
	cfg := DefaultConfig()
	cfg.EnableKeepAlive = false
	client := newSession(cfg, a, true)
	server := newSession(cfg, b, false)
	defer client.Close()
	defer server.Close()
	first, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	_ = peer.Close()
	second, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	other, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = second.SetDeadline(time.Now().Add(2 * time.Second))
	_ = other.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() { _, err := second.Write([]byte("ok")); done <- err }()
	var got [2]byte
	if _, err := io.ReadFull(other, got[:]); err != nil || string(got[:]) != "ok" {
		t.Fatalf("sibling payload=%q err=%v", got, err)
	}
	if err := completionWait(t, done); err != nil || client.IsClosed() || server.IsClosed() {
		t.Fatalf("child close damaged parent: %v", err)
	}
}

type blockedClose struct{ entered, release chan struct{} }

func (c blockedClose) Close() error { close(c.entered); <-c.release; return nil }

func TestWriteSafetyTimerJoinsCallback(t *testing.T) {
	c := blockedClose{make(chan struct{}), make(chan struct{})}
	stop := writeSafetyTimer(c, time.Nanosecond)
	completionWait(t, c.entered)
	done := make(chan bool, 1)
	go func() { done <- stop() }()
	select {
	case <-done:
		t.Fatal("stop returned while Close callback was still running")
	default:
	}
	close(c.release)
	if !completionWait(t, done) {
		t.Fatal("fired callback was not joined")
	}
}
