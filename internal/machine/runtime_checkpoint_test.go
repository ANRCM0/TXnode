package machine

import (
	"context"
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"testing"
	"time"
)

func TestRuntimeCheckpointStopAllPreservesParentCauseAndCollectsChildFailure(t *testing.T) {
	o := newTestOrchestrator()
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan struct{})
	result := make(chan error, 1)
	child, stop := context.WithCancelCause(ctx)
	o.nodes[1] = &nodeHandle{cancelCause: stop, done: done, result: result}
	failure := errors.New("durable checkpoint refused")
	go func() {
		defer close(done)
		<-child.Done()
		if !controlerror.IsRuntimeCheckpoint(context.Cause(child)) {
			result <- errors.New("parent cause lost")
			return
		}
		result <- failure
	}()
	cancel(controlerror.RuntimeCheckpoint)
	completed := make(chan error, 1)
	go func() { completed <- o.stopAll() }()
	select {
	case err := <-completed:
		if !errors.Is(err, failure) {
			t.Fatal("child persistence failure swallowed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("checkpoint join blocked")
	}
}
