package machine

import (
	"context"
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"sync/atomic"
	"testing"
	"time"
)

func TestMachineAuthorityDenialSignalStopsTwoChildrenWithoutSelfJoin(t *testing.T) {
	o := newTestOrchestrator()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	o.runCtx = ctx
	o.runCancel = cancel
	o.terminal = make(chan error, 1)
	var stopped atomic.Int32
	for _, id := range []int{1, 2} {
		child, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		o.nodes[id] = &nodeHandle{cancel: stop, done: done}
		go func() {
			defer close(done)
			<-child.Done()
			if _, ok := controlerror.AsAuthorityDenial(context.Cause(child)); ok {
				stopped.Add(1)
			}
		}()
	}
	denial := &controlerror.AuthorityDenial{Scope: controlerror.MachineScope, MachineID: 16, Code: "NODE_UNAUTHORIZED", HTTPStatus: 401}
	signalDone := make(chan struct{})
	go func() { o.signalAuthorityDenial(denial); close(signalDone) }()
	select {
	case <-signalDone:
	case <-time.After(time.Second):
		t.Fatal("rejecting child blocked on own join")
	}
	select {
	case e := <-o.terminal:
		if e != denial {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("machine main loop not signalled")
	}
	joined := make(chan struct{})
	go func() { o.stopAll(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("machine deadlocked joining children")
	}
	if stopped.Load() != 2 {
		t.Fatal("typed machine cause not propagated to both children")
	}
	o.signalAuthorityDenial(denial)
	select {
	case <-o.terminal:
		t.Fatal("duplicate terminal signal")
	default:
	}
}
func TestNodeAuthority404AndOrdinaryErrorDoNotCancelMachine(t *testing.T) {
	o := newTestOrchestrator()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	o.runCancel = cancel
	o.terminal = make(chan error, 1)
	for _, err := range []error{errors.New("network failure"), &controlerror.AuthorityDenial{Scope: controlerror.NodeScope, NodeID: 1, MachineID: 16, Code: "NODE_NOT_FOUND", HTTPStatus: 404}} {
		if o.signalAuthorityDenial(err) {
			t.Fatal("node or network error stopped machine")
		}
	}
	if ctx.Err() != nil || o.terminalErr != nil {
		t.Fatal("machine context cancelled")
	}
}
