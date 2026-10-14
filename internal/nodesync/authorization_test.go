package nodesync

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSignedSnapshotRefusalIsStickyTerminalWhileConnectivityIsNot(t *testing.T) {
	for _, fatal := range []bool{true, false} {
		t.Run(map[bool]string{true: "signed_refusal", false: "network"}[fatal], func(t *testing.T) {
			err := errors.New("network failure")
			if fatal {
				err = errors.New("NODE_AUTHORIZATION_ROLLBACK")
			}
			source := &fakeSource{supportsPoll: true, pollErr: err}
			c := New(source)
			if !c.Poll(context.Background(), "", false) {
				t.Fatal("poll not started")
			}
			deadline := time.Now().Add(time.Second)
			for c.pullActive.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if fatal {
				select {
				case result := <-c.Results():
					if result.Terminal != err || c.Terminal() != err {
						t.Fatal("signed refusal not terminal")
					}
				case <-time.After(time.Second):
					t.Fatal("terminal missing")
				}
				if c.Poll(context.Background(), "", false) {
					t.Fatal("terminal refusal retried")
				}
			} else if c.Terminal() != nil {
				t.Fatal("network error fabricated authority denial")
			}
		})
	}
}
