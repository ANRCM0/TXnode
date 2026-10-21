package core

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type pipeLifecycleConn struct {
	net.Conn
	reads           <-chan struct{}
	deadlineRelease <-chan struct{}
	retired         atomic.Bool
	deadlineCalls   atomic.Int32
	lateDeadlines   atomic.Int32
	closeCalls      atomic.Int32
}

func (c *pipeLifecycleConn) Read([]byte) (int, error)    { <-c.reads; return 0, io.EOF }
func (c *pipeLifecycleConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *pipeLifecycleConn) CloseWrite() error           { return nil }
func (c *pipeLifecycleConn) Close() error                { c.closeCalls.Add(1); return nil }
func (c *pipeLifecycleConn) SetDeadline(time.Time) error {
	c.deadlineCalls.Add(1)
	if c.deadlineRelease != nil {
		<-c.deadlineRelease
	}
	if c.retired.Load() {
		c.lateDeadlines.Add(1)
	}
	return nil
}

func TestCopyPipeJoinsCancellationBeforeStreamRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reads := make(chan struct{})
		deadlineRelease := make(chan struct{})
		a := &pipeLifecycleConn{reads: reads, deadlineRelease: deadlineRelease}
		b := &pipeLifecycleConn{reads: reads}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		returned := make(chan struct{})
		var pipeErr error
		go func() {
			pipeErr = copyPipe(ctx, a, b, nil, nil, nil, nil, nil, Chunk{})
			// Returning the HTTP handler retires its ResponseWriter in the same way.
			a.retired.Store(true)
			b.retired.Store(true)
			close(returned)
		}()
		synctest.Wait()
		if a.deadlineCalls.Load() != 1 {
			t.Fatal("cancellation watcher did not enter the blocked deadline operation")
		}
		close(reads)
		synctest.Wait()
		earlyReturn := false
		select {
		case <-returned:
			earlyReturn = true
		default:
		}
		close(deadlineRelease)
		synctest.Wait()
		<-returned
		if earlyReturn || a.lateDeadlines.Load() != 0 || b.lateDeadlines.Load() != 0 {
			t.Fatal("relay returned and retired its streams before cancellation cleanup finished")
		}
		if pipeErr != nil {
			t.Fatalf("graceful copies returned %v", pipeErr)
		}
		if a.deadlineCalls.Load() != 1 || b.deadlineCalls.Load() != 1 || a.closeCalls.Load() != 1 || b.closeCalls.Load() != 1 {
			t.Fatal("cancellation did not finish both deadline and close operations")
		}
	})
}
