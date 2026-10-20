package vless

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

type pauseResponseConn struct {
	net.Conn
	write func([]byte) (int, error)
}

func (c *pauseResponseConn) Write(p []byte) (int, error) { return c.write(p) }

func TestVLESSPartialResponseWritePreservesPayloadCount(t *testing.T) {
	failure := errors.New("write timeout")
	for _, tc := range []struct {
		name    string
		wire    int
		err     error
		payload int
		want    error
	}{
		{"partial-with-error", 5, failure, 3, failure},
		{"partial-without-error", 5, nil, 3, io.ErrShortWrite},
		{"header-only", 2, failure, 0, failure},
		{"partial-header", 1, nil, 0, io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &respConn{Conn: &pauseResponseConn{write: func([]byte) (int, error) { return tc.wire, tc.err }}}
			if n, err := c.Write([]byte("payload")); n != tc.payload || !errors.Is(err, tc.want) {
				t.Fatalf("partial payload count=%d err=%v", n, err)
			}
			if n, err := c.Write([]byte("retry")); n != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("partial frame allowed retry: %d %v", n, err)
			}
		})
	}
}

func TestVLESSOpaqueReadCannotPromisePause(t *testing.T) {
	c := &respConn{Conn: &pauseResponseConn{}}
	if c.ReadPauseSupported() {
		t.Fatal("opaque transport advertised safe pause")
	}
	if err := c.PauseRead(); !errors.Is(err, core.ErrReadPauseUnsupported) {
		t.Fatalf("opaque transport claims safe pause: %v", err)
	}
}
