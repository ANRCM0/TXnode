package transport

import (
	"errors"
	"io"
	"testing"
)

type connectCloseBody struct {
	closed  bool
	failure error
}

func (b *connectCloseBody) Read([]byte) (int, error) { return 0, b.failure }
func (b *connectCloseBody) Close() error             { b.closed = true; return nil }

func TestConnectHalfCloseDoesNotResetResponse(t *testing.T) {
	failure := errors.New("body closed by handler")
	body := &connectCloseBody{failure: failure}
	stream := &connectStream{httpStream: &httpStream{body: body}}
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, failure) {
		t.Fatalf("remote read error changed before local half-close: %v", err)
	}
	if err := stream.CloseWrite(); err != nil || !body.closed {
		t.Fatalf("half-close: closed=%v err=%v", body.closed, err)
	}
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("local half-close must not cancel flushed response: %v", err)
	}
}
