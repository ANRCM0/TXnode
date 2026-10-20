package smux

import (
	"bytes"
	"errors"
	"io"
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
	if c.entered != nil {
		if c.accepted >= 0 {
			n = headerSize + c.accepted
		}
		c.mu.Lock()
		_, _ = c.wire.Write(b[:n])
		c.mu.Unlock()
		close(c.entered)
		<-c.release
		return n, io.ErrClosedPipe
	}
	c.mu.Lock()
	_, _ = c.wire.Write(b)
	c.mu.Unlock()
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
			cfg.KeepAliveDisabled = true
			s := newSession(cfg, c, true)
			defer s.Close()
			stream := newStream(1, cfg.MaxFrameSize, s)
			result := make(chan writeResult, 1)
			go func() { n, err := stream.Write([]byte("payload")); result <- writeResult{n, err} }()
			completionWait(t, c.entered)
			// Wire consumption precedes shutdown, while the real Write result
			// remains gated. Cancellation must join it instead of returning zero.
			_ = s.Close()
			select {
			case value := <-result:
				t.Fatalf("returned before actual writer completion: %+v", value)
			default:
			}
			close(c.release)
			value := completionWait(t, result)
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
	cfg.KeepAliveDisabled = true
	// Queue without running a sender, to make the cancellation order exact.
	s := &Session{conn: c, config: cfg, die: make(chan struct{}), shaper: make(chan writeRequest, 4), sq: NewShaperQueue(), chShaperPending: make(chan struct{}, 1), chShaperConsumed: make(chan struct{}, 1), chSocketWriteError: make(chan struct{})}
	defer s.Close()
	deadline := make(chan time.Time)
	frame := newFrame(1, cmdPSH, 1)
	frame.data = []byte("cancelled")
	result := make(chan writeResult, 1)
	go func() { n, err := s.writeFrameInternal(frame, deadline, CLSDATA); result <- writeResult{n, err} }()
	queued := completionWait(t, s.shaper)
	close(deadline)
	value := completionWait(t, result)
	if value.n != 0 || !errors.Is(value.err, ErrTimeout) {
		t.Fatalf("queued cancellation=%+v", value)
	}
	copy(frame.data, "reused!!!")
	s.shaper <- queued
	go s.shaperLoop()
	sendDone := make(chan struct{})
	go func() { defer close(sendDone); s.sendLoop() }()
	defer func() { _ = s.Close(); completionWait(t, sendDone) }()
	other := newFrame(1, cmdPSH, 3)
	other.data = []byte("sibling")
	if n, err := s.writeFrameInternal(other, nil, CLSDATA); err != nil || n != len(other.data) {
		t.Fatalf("sibling n=%d err=%v", n, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.wire.Bytes(); len(got) != headerSize+len(other.data) || !bytes.Equal(got[headerSize:], other.data) {
		t.Fatalf("cancelled data reached the wire: %q", got)
	}
}

func TestChildCloseKeepsSibling(t *testing.T) {
	a, b := net.Pipe()
	cfg := DefaultConfig()
	cfg.KeepAliveDisabled = true
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
