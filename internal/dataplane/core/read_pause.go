package core

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// ErrReadPaused is retryable only at a protocol frame boundary with no bytes
// consumed. Complete the original chunk token before waiting for admission.
var ErrReadPaused = errors.New("relay read paused")

var ErrReadPauseUnsupported = errors.New("relay read pause unsupported")

type ReadPauser interface {
	PauseRead() error
	ResumeRead() error
}

// BindReadPause(nil) records an unsupported connection without rejecting normal
// traffic. Its presence must refuse a connection-preserving renewal.
type PausableChunkHook interface {
	ChunkHook
	BindReadPause(ReadPauser) (unbind func(), err error)
	WaitReady(context.Context) error
}

// ReadPauseConn owns deadlines after the protocol handshake. Only bare TCP is
// supported: TLS and other record layers can cache a timeout or consume hidden
// bytes, so their outer zero-byte timeout cannot prove a safe frame boundary.
type ReadPauseConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
	paused   bool
}

func NewReadPauseConn(conn net.Conn) *ReadPauseConn {
	if _, ok := conn.(*net.TCPConn); !ok {
		return nil
	}
	return &ReadPauseConn{Conn: conn}
}

func (c *ReadPauseConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	paused := c.paused
	expired := !c.deadline.IsZero() && !time.Now().Before(c.deadline)
	c.mu.Unlock()
	if paused {
		if expired {
			return 0, os.ErrDeadlineExceeded
		}
		return 0, ErrReadPaused
	}
	n, err := c.Conn.Read(p)
	var timeout net.Error
	if n == 0 && errors.As(err, &timeout) && timeout.Timeout() {
		c.mu.Lock()
		paused = c.paused && (c.deadline.IsZero() || time.Now().Before(c.deadline))
		c.mu.Unlock()
		if paused {
			return 0, ErrReadPaused
		}
	}
	return n, err
}

func (c *ReadPauseConn) ReadDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

func (c *ReadPauseConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	if c.paused && (t.IsZero() || time.Now().Before(t)) {
		t = time.Now()
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *ReadPauseConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *ReadPauseConn) PauseRead() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paused = true
	t := time.Now()
	if !c.deadline.IsZero() && c.deadline.Before(t) {
		t = c.deadline
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *ReadPauseConn) ResumeRead() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.Conn.SetReadDeadline(c.deadline); err != nil {
		return err
	}
	c.paused = false
	return nil
}

func (c *ReadPauseConn) CloseWrite() error { return CloseWrite(c.Conn) }

// Bounded accounting forbids splice through its hook. Ordinary/event-only
// traffic may unwrap this byte-transparent TCP wrapper while it is not paused.
func (c *ReadPauseConn) SpliceConn() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused {
		return nil
	}
	if _, ok := c.Conn.(*net.TCPConn); !ok {
		return nil
	}
	return c.Conn
}

func waitReadReady(ctx context.Context, hook ChunkHook, err error) error {
	if !errors.Is(err, ErrReadPaused) {
		return err
	}
	if pausable, ok := hook.(PausableChunkHook); ok {
		return pausable.WaitReady(ctx)
	}
	return err
}

func beginChunk(ctx context.Context, hook ChunkHook, c Chunk) (any, error) {
	for {
		token, err := hook.Begin(c)
		if !errors.Is(err, ErrReadPaused) {
			return token, err
		}
		if err := waitReadReady(ctx, hook, err); err != nil {
			return nil, err
		}
	}
}
