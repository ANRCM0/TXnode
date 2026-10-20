package core

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type accountingConn struct {
	net.Conn
	reader io.Reader
	write  func([]byte) (int, error)
}

func (c accountingConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c accountingConn) Write(p []byte) (int, error) { return c.write(p) }
func (c accountingConn) CloseWrite() error           { return nil }
func (c accountingConn) Close() error                { return nil }

type canceledWaiter struct{}

func (canceledWaiter) Wait(context.Context, int64) error { return context.Canceled }

func TestDownloadAccountsClientWrites(t *testing.T) {
	writeErr := errors.New("client write failed")
	for _, tc := range []struct {
		name    string
		n       int
		err     error
		wantErr error
	}{
		{"success", 5, nil, nil},
		{"short", 2, nil, io.ErrShortWrite},
		{"partial-error", 2, writeErr, writeErr},
		{"failed", 0, writeErr, writeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := &recordingHook{}
			dst := accountingConn{write: func([]byte) (int, error) { return tc.n, tc.err }}
			src := accountingConn{reader: strings.NewReader("hello")}
			err := copyDirection(context.Background(), dst, src, nil, nil, hook, Chunk{}, DirDownload)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want=%v", err, tc.wantErr)
			}
			if len(hook.begins) != 1 || len(hook.completes) != 1 {
				t.Fatalf("unexpected operation count: %+v", hook)
			}
			if hook.begins[0].N != 5 || hook.completes[0].N != int64(tc.n) || !errors.Is(hook.completes[0].Err, tc.wantErr) {
				t.Fatalf("write evidence: begin=%+v complete=%+v", hook.begins, hook.completes)
			}
		})
	}
}

func TestDownloadCanceledLimiterDoesNotEmitEvidence(t *testing.T) {
	hook := &recordingHook{}
	dst := accountingConn{write: func([]byte) (int, error) { t.Fatal("write after cancellation"); return 0, nil }}
	src := accountingConn{reader: strings.NewReader("hello")}
	err := copyDirection(context.Background(), dst, src, []waiter{canceledWaiter{}}, nil, hook, Chunk{}, DirDownload)
	if !errors.Is(err, context.Canceled) || len(hook.begins) != 0 || len(hook.completes) != 0 {
		t.Fatalf("canceled read produced write evidence: %v %+v", err, hook)
	}
}

type denyingChunkHook struct{ err error }

func (h denyingChunkHook) Begin(Chunk) (any, error) { return nil, h.err }
func (denyingChunkHook) Complete(Chunk, any)        {}
func (denyingChunkHook) Close(Chunk)                {}

func TestCopyPipeHookFailureInterruptsOtherDirection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	denied := errors.New("authorization denied")
	done := make(chan error, 1)
	go func() {
		done <- copyPipe(context.Background(), a, b, nil, nil, nil, nil, denyingChunkHook{err: denied}, Chunk{})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, denied) {
			t.Fatalf("copy error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("hook failure left other direction blocked")
	}
}
