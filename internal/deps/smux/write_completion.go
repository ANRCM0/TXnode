package smux

import (
	"errors"
	"io"
	"sync"
	"time"
)

// A queued frame still belongs to the caller. Cancellation must win ownership
// before the sender can read it; an active sender retains it until real IO ends.
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

// Only the sender owns this parent safety valve. Joining a fired callback
// prevents a delayed Close from affecting another request after this one ends.
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
