package yamux

import (
	"errors"
	"io"
	"sync"
	"time"
)

type writeResult struct {
	n   int
	err error
}

// Cancellation can discard a queued frame, but must join an active writer's
// real result before the caller reuses its bytes or completes accounting.
type writeState struct {
	mu        sync.Mutex
	started   bool
	cancelled bool
	result    chan writeResult
}

func newWriteState() *writeState { return &writeState{result: make(chan writeResult, 1)} }

func (w *writeState) start() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancelled {
		return false
	}
	w.started = true
	return true
}

func (w *writeState) cancel(err error) (int, error) {
	w.mu.Lock()
	if !w.started {
		w.cancelled = true
		w.mu.Unlock()
		return 0, err
	}
	w.mu.Unlock()
	result := <-w.result
	return result.n, errors.Join(result.err, err)
}

func writeSafetyTimer(conn io.Closer, timeout time.Duration) func() bool {
	done := make(chan struct{})
	timer := time.AfterFunc(timeout, func() { _ = conn.Close(); close(done) })
	return func() bool {
		if timer.Stop() {
			return false
		}
		<-done
		return true
	}
}
