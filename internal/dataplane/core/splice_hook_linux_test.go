//go:build linux

package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type spliceHookToken struct{ begin Chunk }

type spliceHookRecord struct {
	begin    Chunk
	complete Chunk
	finished bool
}

type spliceRecordingHook struct {
	mu            sync.Mutex
	allow         bool
	refuse        ChunkDirection
	refusal       error
	refused       []Chunk
	records       map[*spliceHookToken]*spliceHookRecord
	invalid       bool
	closed        int
	uploadStarted chan struct{}
	startOnce     sync.Once
}

func (h *spliceRecordingHook) AllowSplice() bool { return h.allow }

func (h *spliceRecordingHook) Begin(c Chunk) (any, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.refusal != nil && c.Dir == h.refuse {
		h.refused = append(h.refused, c)
		return nil, h.refusal
	}
	if h.records == nil {
		h.records = make(map[*spliceHookToken]*spliceHookRecord)
	}
	token := &spliceHookToken{c}
	h.records[token] = &spliceHookRecord{begin: c}
	if c.Dir == DirUpload && h.uploadStarted != nil {
		h.startOnce.Do(func() { close(h.uploadStarted) })
	}
	return token, nil
}

func (h *spliceRecordingHook) Complete(c Chunk, value any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	token, ok := value.(*spliceHookToken)
	if !ok || h.records[token] == nil || h.records[token].finished {
		h.invalid = true
		return
	}
	h.records[token].complete, h.records[token].finished = c, true
}

func (h *spliceRecordingHook) Close(Chunk) {
	h.mu.Lock()
	h.closed++
	h.mu.Unlock()
}

func (h *spliceRecordingHook) verify(t *testing.T, meta Chunk) (up, down int64, uploadEOF, uploadError bool) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.invalid || h.closed != 0 || len(h.records) == 0 {
		t.Fatalf("invalid hook ownership: invalid=%t closes=%d operations=%d", h.invalid, h.closed, len(h.records))
	}
	for token, record := range h.records {
		b, c := record.begin, record.complete
		if !record.finished || token.begin != b || c.ConnID != meta.ConnID || c.UserID != meta.UserID || c.Path != meta.Path || c.Dir != b.Dir ||
			b.ConnID != meta.ConnID || b.UserID != meta.UserID || b.Path != meta.Path || b.Err != nil || c.N < 0 || c.N > b.N {
			t.Fatalf("unpaired or retargeted operation: begin=%+v complete=%+v finished=%t", b, c, record.finished)
		}
		if c.Dir == DirUpload {
			if b.N != copyBuf {
				t.Fatalf("upload intent size=%d", b.N)
			}
			up += c.N
			uploadEOF = uploadEOF || c.N == 0 && errors.Is(c.Err, io.EOF)
			uploadError = uploadError || c.Err != nil && !errors.Is(c.Err, io.EOF)
		} else {
			if b.N <= 0 {
				t.Fatal("download intent did not follow a positive pipe read")
			}
			down += c.N
		}
	}
	return
}

type spliceObservedConn struct {
	net.Conn
	reads atomic.Int64
}

func (c *spliceObservedConn) Read(b []byte) (int, error) { c.reads.Add(1); return c.Conn.Read(b) }
func (c *spliceObservedConn) SpliceConn() net.Conn       { return c.Conn }
func (c *spliceObservedConn) CloseWrite() error          { return CloseWrite(c.Conn) }

type spliceTestWaiter struct{}

func (spliceTestWaiter) Wait(context.Context, int64) error { return nil }

func TestSpliceHookOptInPreservesFINAndOriginalOperations(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		allow   bool
		plain   bool
		limited bool
		splice  bool
	}{
		{name: "explicit", allow: true, splice: true},
		{name: "declined"},
		{name: "ordinary_chunk_hook", allow: true, plain: true},
		{name: "limited", allow: true, limited: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client, left := spliceTCPPair(t)
			origin, right := spliceTCPPair(t)
			a, b := &spliceObservedConn{Conn: left}, &spliceObservedConn{Conn: right}
			hook := &spliceRecordingHook{allow: scenario.allow}
			var installed ChunkHook = hook
			if scenario.plain {
				installed = struct{ ChunkHook }{hook}
			}
			var limits []waiter
			if scenario.limited {
				limits = []waiter{spliceTestWaiter{}}
			}
			meta := Chunk{ConnID: 301, UserID: 19, Path: "conn"}
			var countedUp, countedDown atomic.Int64
			done := make(chan error, 1)
			go func() {
				done <- pipeLimited(t.Context(), a, b, limits, nil, func(n int64) { countedUp.Add(n) }, func(n int64) { countedDown.Add(n) }, installed, meta)
			}()
			upload, download := bytes.Repeat([]byte("u"), copyBuf+137), bytes.Repeat([]byte("d"), copyBuf*2+31)
			originDone := make(chan error, 1)
			go func() {
				body, err := io.ReadAll(origin)
				if err == nil && !bytes.Equal(body, upload) {
					err = errors.New("upload bytes changed")
				}
				if err == nil {
					_, err = origin.Write(download)
				}
				if closeErr := origin.CloseWrite(); err == nil {
					err = closeErr
				}
				originDone <- err
			}()
			if n, err := client.Write(upload); err != nil || n != len(upload) {
				t.Fatalf("upload: n=%d err=%v", n, err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(client)
			if err != nil || !bytes.Equal(body, download) {
				t.Fatalf("download after FIN: n=%d err=%v", len(body), err)
			}
			if err := <-originDone; err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("hook relay did not finish after both FINs")
			}
			if scenario.splice {
				for _, conn := range []*net.TCPConn{left, right} {
					if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatalf("normal FIN relay closed its caller-owned socket: %v", err)
					}
				}
			}
			up, down, eof, _ := hook.verify(t, meta)
			if up != int64(len(upload)) || down != int64(len(download)) || !eof || countedUp.Load() != up || countedDown.Load() != down {
				t.Fatalf("actual byte/EOF evidence: up=%d down=%d eof=%t counts=%d/%d", up, down, eof, countedUp.Load(), countedDown.Load())
			}
			if used := a.reads.Load()+b.reads.Load() == 0; used != scenario.splice {
				t.Fatalf("splice=%t, want %t (wrapper reads=%d)", used, scenario.splice, a.reads.Load()+b.reads.Load())
			}
		})
	}
}

func TestSpliceHookRefusalAndCancellationCompleteOriginalRead(t *testing.T) {
	for _, refused := range []bool{false, true} {
		name := "cancellation"
		if refused {
			name = "download_refusal"
		}
		t.Run(name, func(t *testing.T) {
			_, left := spliceTCPPair(t)
			origin, right := spliceTCPPair(t)
			hook := &spliceRecordingHook{allow: true, uploadStarted: make(chan struct{})}
			failure := errors.New("synthetic download admission refusal")
			if refused {
				hook.refuse, hook.refusal = DirDownload, failure
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			meta := Chunk{ConnID: 307, UserID: 23, Path: "conn"}
			done := make(chan error, 1)
			go func() {
				used, err := splicePipeWithHook(ctx, left, right, nil, nil, hook, meta)
				if !used {
					err = errors.New("real TCP hook path did not splice")
				}
				done <- err
			}()
			select {
			case <-hook.uploadStarted:
			case <-time.After(2 * time.Second):
				t.Fatal("upload intent was not admitted")
			}
			if refused {
				if _, err := origin.Write([]byte("refused")); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if refused && !errors.Is(err, failure) {
					t.Fatalf("refusal lost: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocked sibling outlived refusal/cancellation")
			}
			up, down, _, readError := hook.verify(t, meta)
			if up != 0 || down != 0 || !readError {
				t.Fatalf("canceled original read: up=%d down=%d error=%t", up, down, readError)
			}
			hook.mu.Lock()
			refusals := len(hook.refused)
			hook.mu.Unlock()
			if refused && refusals != 1 {
				t.Fatalf("download refusal attempts=%d", refusals)
			}
		})
	}
}
