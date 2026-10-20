package core

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

type pauseTestConn struct {
	net.Conn
	read     func([]byte) (int, error)
	deadline time.Time
}

func TestReadPauseBareTCPResumesSameConnection(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	raw, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := NewReadPauseConn(raw)
	if tcpWriter(c) != raw {
		t.Fatal("unpaused bare TCP wrapper lost transparent splice")
	}
	original := time.Now().Add(3 * time.Second)
	if err := c.SetReadDeadline(original); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 8)); readDone <- err }()
	if err := c.PauseRead(); err != nil {
		t.Fatal(err)
	}
	if tcpWriter(c) != nil {
		t.Fatal("paused TCP wrapper allowed splice to bypass pause")
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, ErrReadPaused) {
			t.Fatalf("idle TCP read did not pause: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pause did not interrupt idle TCP read")
	}
	if err := c.ResumeRead(); err != nil || !c.ReadDeadline().Equal(original) {
		t.Fatalf("resume lost deadline: %v", err)
	}
	if tcpWriter(c) != raw {
		t.Fatal("resumed bare TCP wrapper lost transparent splice")
	}
	peer.SetWriteDeadline(original)
	if _, err := peer.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "payload" {
		t.Fatalf("same TCP stream failed after resume: %q %v", buf, err)
	}
}

func (c *pauseTestConn) Read(p []byte) (int, error)        { return c.read(p) }
func (c *pauseTestConn) SetReadDeadline(d time.Time) error { c.deadline = d; return nil }

func TestReadPauseRestoresDeadlineAndDoesNotRetryRealTimeout(t *testing.T) {
	underlying := &pauseTestConn{}
	c := &ReadPauseConn{Conn: underlying}
	original := time.Now().Add(time.Minute)
	c.SetReadDeadline(original)
	underlying.read = func([]byte) (int, error) {
		c.PauseRead()
		return 0, os.ErrDeadlineExceeded
	}
	if n, err := c.Read(make([]byte, 8)); n != 0 || !errors.Is(err, ErrReadPaused) {
		t.Fatalf("interrupted idle read = %d, %v", n, err)
	}
	if err := c.ResumeRead(); err != nil || !underlying.deadline.Equal(original) {
		t.Fatalf("deadline lost: %v, %v", underlying.deadline, err)
	}
	underlying.read = func([]byte) (int, error) { return 0, os.ErrDeadlineExceeded }
	if _, err := c.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrReadPaused) {
		t.Fatalf("real timeout retried: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(-time.Second))
	c.PauseRead()
	if _, err := c.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired original deadline treated as pause: %v", err)
	}
}

func TestReadPausePositiveTimeoutRemainsFailure(t *testing.T) {
	underlying := &pauseTestConn{}
	c := &ReadPauseConn{Conn: underlying}
	underlying.read = func(p []byte) (int, error) {
		c.PauseRead()
		p[0] = 'x'
		return 1, os.ErrDeadlineExceeded
	}
	if n, err := c.Read(make([]byte, 8)); n != 1 || !errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrReadPaused) {
		t.Fatalf("partial read converted to pause: %d %v", n, err)
	}
	if NewReadPauseConn(underlying) != nil {
		t.Fatal("opaque connection advertised safe pause")
	}
}

func TestEarlyPeekPauseRetainsBoundaryAndOriginalDeadline(t *testing.T) {
	underlying := &pauseTestConn{}
	c := &ReadPauseConn{Conn: underlying}
	original := time.Now().Add(time.Minute)
	c.SetReadDeadline(original)
	e := newEarlyConn(c)
	c.PauseRead()
	if head, err := e.peek(time.Second); len(head) != 0 || !errors.Is(err, ErrReadPaused) || e.done {
		t.Fatalf("peek consumed pause: %q %v done=%v", head, err, e.done)
	}
	firstBound := e.peekDeadline
	c.ResumeRead()
	underlying.read = func(p []byte) (int, error) { return copy(p, "payload"), nil }
	if head, err := e.peek(time.Hour); string(head) != "payload" || err != nil {
		t.Fatalf("peek after resume: %q %v", head, err)
	}
	if !firstBound.Equal(e.peekDeadline) || !c.ReadDeadline().Equal(original) || !underlying.deadline.Equal(original) {
		t.Fatal("peek reset timeout budget or lost original deadline")
	}
	buf := make([]byte, 7)
	if n, err := e.Read(buf); n != 7 || err != nil || string(buf) != "payload" {
		t.Fatalf("peek bytes lost: %q %d %v", buf, n, err)
	}
}

type pauseTestHook struct {
	beginPause bool
	begins     int
	completed  []Chunk
	tokens     []any
	waits      int
	onWait     func()
}

func (h *pauseTestHook) Begin(Chunk) (any, error) {
	if h.beginPause {
		h.beginPause = false
		return nil, ErrReadPaused
	}
	h.begins++
	return h.begins, nil
}
func (h *pauseTestHook) Complete(c Chunk, token any) {
	h.completed = append(h.completed, c)
	h.tokens = append(h.tokens, token)
}
func (*pauseTestHook) Close(Chunk)                              {}
func (*pauseTestHook) BindReadPause(ReadPauser) (func(), error) { return func() {}, nil }
func (h *pauseTestHook) WaitReady(ctx context.Context) error {
	h.waits++
	if h.onWait != nil {
		h.onWait()
	}
	return ctx.Err()
}

func TestCopyUploadPauseCompletesIssuingTokenBeforeWait(t *testing.T) {
	hook := &pauseTestHook{}
	reads := 0
	source := &pauseTestConn{read: func(p []byte) (int, error) {
		reads++
		switch reads {
		case 1:
			return 0, ErrReadPaused
		case 2:
			return copy(p, "abc"), nil
		default:
			return 0, io.EOF
		}
	}}
	hook.onWait = func() {
		if len(hook.completed) != 1 || hook.completed[0].N != 0 || hook.completed[0].Err != nil || hook.tokens[0] != 1 {
			t.Fatalf("wait before old token completed: %+v %+v", hook.completed, hook.tokens)
		}
	}
	var written []byte
	dst := accountingConn{write: func(p []byte) (int, error) { written = append(written, p...); return len(p), nil }}
	if err := copyDirection(context.Background(), dst, source, nil, nil, hook, Chunk{}, DirUpload); err != nil {
		t.Fatal(err)
	}
	if hook.waits != 1 || string(written) != "abc" || !reflect.DeepEqual(hook.tokens, []any{1, 2, 3}) || hook.completed[1].N != 3 {
		t.Fatalf("wrong retry ownership: %+v, %q", hook, written)
	}
}

func TestCopyDownloadWaitsBeforeIssuingWriteToken(t *testing.T) {
	hook := &pauseTestHook{beginPause: true}
	src := accountingConn{reader: &pausePayloadReader{}}
	dst := accountingConn{write: func(p []byte) (int, error) { return 2, os.ErrDeadlineExceeded }}
	err := copyDirection(context.Background(), dst, src, nil, nil, hook, Chunk{}, DirDownload)
	if !errors.Is(err, os.ErrDeadlineExceeded) || hook.waits != 1 || hook.begins != 1 || len(hook.completed) != 1 || hook.tokens[0] != 1 || hook.completed[0].N != 2 || !errors.Is(hook.completed[0].Err, os.ErrDeadlineExceeded) {
		t.Fatalf("partial write escaped issuing token: %v %+v", err, hook)
	}
}

type pausePayloadReader struct{}

func (*pausePayloadReader) Read(p []byte) (int, error) { return copy(p, "payload"), nil }

func TestCopyPausedWaitCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hook := &pauseTestHook{onWait: cancel}
	src := &pauseTestConn{read: func([]byte) (int, error) { return 0, ErrReadPaused }}
	err := copyDirection(ctx, nil, src, nil, nil, hook, Chunk{}, DirUpload)
	if !errors.Is(err, context.Canceled) || len(hook.completed) != 1 || hook.completed[0].N != 0 || hook.completed[0].Err != nil {
		t.Fatalf("cancellation lost completion: %v %+v", err, hook)
	}
}
