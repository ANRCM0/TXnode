package nodesync

import (
	"context"
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"testing"
	"time"
)

func TestAuthorityDenialIsDeliveredAndStickyInsteadOfBackoff(t *testing.T) {
	denial := &controlerror.AuthorityDenial{Scope: controlerror.NodeScope, NodeID: 42, Code: "NODE_NOT_FOUND", HTTPStatus: 404}
	source := &fakeSource{supportsPoll: true, pollErr: denial}
	c := New(source)
	if !c.Poll(context.Background(), "", false) {
		t.Fatal("poll refused")
	}
	select {
	case result := <-c.Results():
		if result.Terminal != denial || result.Users != nil || result.Config != nil {
			t.Fatal("denial converted to snapshot")
		}
	case <-time.After(time.Second):
		t.Fatal("denial lost")
	}
	if c.Terminal() != denial || c.Poll(context.Background(), "", false) {
		t.Fatal("terminal denial not sticky")
	}
}
func TestOrdinaryFailureKeepsPollRetryPolicy(t *testing.T) {
	source := &fakeSource{supportsPoll: true, pollErr: errors.New("network or server failure")}
	c := New(source)
	c.Poll(context.Background(), "", false)
	deadline := time.Now().Add(time.Second)
	for c.pullActive.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Terminal() != nil {
		t.Fatal("network inferred denial")
	}
	select {
	case <-c.Results():
		t.Fatal("ordinary error published terminal")
	default:
	}
	source.mu.Lock()
	source.pollErr = nil
	source.mu.Unlock()
	if c.Poll(context.Background(), "", false) {
		t.Fatal("lost old backoff")
	}
	if !c.Poll(context.Background(), "", false) {
		t.Fatal("retry denied")
	}
	select {
	case result := <-c.Results():
		if result.Terminal != nil {
			t.Fatal("retry terminal")
		}
	case <-time.After(time.Second):
		t.Fatal("retry missing")
	}
}
