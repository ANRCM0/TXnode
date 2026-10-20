package core

import (
	"context"
	"errors"
	"net"
	"testing"
)

type recordingHook struct {
	begins    []Chunk
	completes []Chunk
	closed    []Chunk
	refuse    bool
}

func (h *recordingHook) Begin(c Chunk) (any, error) {
	h.begins = append(h.begins, c)
	if h.refuse {
		return nil, errors.New("refused")
	}
	return len(h.begins), nil
}

func (h *recordingHook) Complete(c Chunk, token any) { h.completes = append(h.completes, c) }

func (h *recordingHook) Close(c Chunk) { h.closed = append(h.closed, c) }

func TestCopyDirectionAccountsChunks(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	hook := &recordingHook{}
	meta := Chunk{ConnID: 9, UserID: 3, Path: "conn"}
	done := make(chan error, 1)
	go func() {
		done <- copyDirection(context.Background(), proxy, client, nil, nil, hook, meta, DirUpload)
	}()

	// net.Pipe is synchronous and crossed: writing proxy feeds the source
	// (client) that copyDirection reads, and the relayed bytes come back out of
	// client because proxy is the destination.
	if _, err := proxy.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = proxy.Close()
	<-done

	if len(hook.begins) == 0 || len(hook.completes) == 0 {
		t.Fatalf("hook not called: %+v", hook)
	}
	if hook.begins[0].N != copyBuf || hook.begins[0].Dir != DirUpload || hook.completes[0].N != 5 {
		t.Fatalf("chunk accounting: begin=%+v complete=%+v", hook.begins[0], hook.completes[0])
	}
}

func TestCopyDirectionAbortsWhenHookRefuses(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	hook := &recordingHook{refuse: true}
	err := copyDirection(context.Background(), proxy, client, nil, nil, hook, Chunk{ConnID: 1, UserID: 2}, DirUpload)
	if err == nil {
		t.Fatal("refused chunk did not abort the copy")
	}
}
