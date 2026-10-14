package nodesync

import (
	"context"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"testing"
	"time"
)

func TestPollAtCarriesCapturedGenerationIncludingAuthorityDenial(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		source := &fakeSource{supportsPoll: true}
		if terminal {
			source.pollErr = &controlerror.AuthorityDenial{Scope: controlerror.NodeScope, NodeID: 42, HTTPStatus: 404, Code: "NODE_NOT_FOUND"}
		}
		c := New(source)
		if !c.PollAt(context.Background(), "", false, 9) {
			t.Fatal("poll")
		}
		select {
		case r := <-c.Results():
			if !r.HasGeneration || r.Generation != 9 || (terminal && r.Terminal == nil) {
				t.Fatal("generation/terminal discarded", r)
			}
		case <-time.After(time.Second):
			t.Fatal("result")
		}
	}
}
func TestOldPollWrapperDoesNotInventGeneration(t *testing.T) {
	c := New(&fakeSource{supportsPoll: true})
	c.Poll(context.Background(), "", false)
	select {
	case r := <-c.Results():
		if r.HasGeneration {
			t.Fatal("old wrapper has unexpected generation")
		}
	case <-time.After(time.Second):
		t.Fatal("result")
	}
}
