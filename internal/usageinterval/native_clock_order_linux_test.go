//go:build linux

package usageinterval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func nativeLockedClock(t *testing.T, collector *NativeCollector, fixed time.Time) func() time.Time {
	t.Helper()
	return func() time.Time {
		if collector.mu.TryLock() {
			collector.mu.Unlock()
			t.Fatal("completion sampled clocks outside the collector lock")
		}
		return fixed
	}
}

func TestNativeCompletionClockObservationIsSerialized(t *testing.T) {
	store, _, session := nativeFixture(t)
	collector := newNative(t, store, session, "1")
	upload := collector.BeginIO(7, "upload", 19)
	download := collector.BeginIO(7, "download", 7)
	if upload == nil || download == nil {
		t.Fatal("durable intents missing")
	}
	fixed := time.Now()
	clock := nativeLockedClock(t, collector, fixed)
	if err := collector.completeIOWithClock(upload, "upload", 13, true, clock); err != nil {
		t.Fatal(err)
	}
	if err := collector.completeIOWithClock(download, "download", 7, false, clock); err != nil {
		t.Fatal(err)
	}
	state := nativeStateOnDisk(t, collector)
	want := stamp{fixed.UnixNano(), int64(fixed.Sub(collector.origin))}
	if collector.Unknown() || collector.inflight.Load() != 0 || len(state.Events) != 2 {
		t.Fatal("serialized completions lost authority or durable evidence")
	}
	for i, event := range state.Events {
		if !event.Done || !event.Eligible || event.Completed != want {
			t.Fatalf("completion %d did not retain its serialized observation: %+v", i, event)
		}
	}
	if state.Events[0].Bytes != 13 || !state.Events[0].IOError || state.Events[1].Bytes != 7 {
		t.Fatal("serialized observations changed actual I/O bytes or error state")
	}
}

func TestNativeSerializedCompletionKeepsUncertainEvidenceIneligible(t *testing.T) {
	for _, reason := range []string{"wall_rollback", "monotonic_deadline", "retired"} {
		t.Run(reason, func(t *testing.T) {
			store, spool, session := nativeFixture(t)
			collector := newNative(t, store, session, "1")
			op := collector.BeginIO(7, "upload", 19)
			if op == nil {
				t.Fatal("durable intent missing")
			}
			fixed := time.Now()
			switch reason {
			case "wall_rollback":
				collector.mu.Lock()
				collector.last = stamp{fixed.UnixNano() + 1, int64(fixed.Sub(collector.origin))}
				collector.mu.Unlock()
			case "monotonic_deadline":
				collector.deadline = fixed
			case "retired":
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				if err := collector.Drain(cancelled); err != nil {
					t.Fatal(err)
				}
			}
			if err := collector.completeIOWithClock(op, "upload", 13, true, nativeLockedClock(t, collector, fixed)); err != nil {
				t.Fatal("uncertain actual I/O was not retained", err)
			}
			if !collector.Unknown() || collector.inflight.Load() != 0 {
				t.Fatal("uncertain completion retained authority or an active intent")
			}
			if err := collector.Drain(context.Background()); err != nil {
				t.Fatal(err)
			}
			state := nativeStateOnDisk(t, collector)
			if len(state.Events) != 1 || !state.Events[0].Done || state.Events[0].Eligible ||
				state.Events[0].Bytes != 13 || state.Events[0].Requested != 19 || !state.Events[0].IOError ||
				state.Events[0].Completed != (stamp{fixed.UnixNano(), int64(fixed.Sub(collector.origin))}) {
				t.Fatal("uncertain evidence was discarded, relabeled or made eligible")
			}
			records, err := spool.Records()
			if err != nil || len(records) != 0 || state.Pending != nil {
				t.Fatal("uncertain completion produced submittable usage", err)
			}
		})
	}
}

func TestNativeSerializedCompletionRejectsForeignAndDuplicateTokens(t *testing.T) {
	store, _, session := nativeFixture(t)
	original := newNative(t, store, session, "1")
	op := original.BeginIO(7, "upload", 19)
	if op == nil {
		t.Fatal("durable intent missing")
	}
	replacement := newNative(t, store, session, "2")
	if err := replacement.completeIOWithClock(op, "upload", 13, true, func() time.Time {
		t.Fatal("foreign token reached completion clock observation")
		return time.Time{}
	}); !errors.Is(err, ErrUnknown) {
		t.Fatal("foreign token was accepted", err)
	}
	if len(nativeStateOnDisk(t, replacement).Events) != 0 || !replacement.Unknown() {
		t.Fatal("foreign token changed replacement evidence or retained authority")
	}
	fixed := time.Now()
	clock := nativeLockedClock(t, original, fixed)
	if err := original.completeIOWithClock(op, "upload", 13, true, clock); err != nil {
		t.Fatal("original owner lost its pending operation", err)
	}
	before := nativeStateOnDisk(t, original)
	if err := original.completeIOWithClock(op, "upload", 19, false, clock); !errors.Is(err, ErrUnknown) {
		t.Fatal("duplicate completion was accepted", err)
	}
	after := nativeStateOnDisk(t, original)
	if !original.Unknown() || original.inflight.Load() != 0 || len(before.Events) != 1 || len(after.Events) != 1 ||
		after.Events[0] != before.Events[0] {
		t.Fatal("duplicate completion rewrote original evidence or changed inflight ownership")
	}
}
