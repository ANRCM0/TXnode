//go:build linux

package usageinterval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNativeStrictRetirementRefusesUnresolvedIntent(t *testing.T) {
	store, spool, session := nativeFixture(t)
	collector := newNative(t, store, session, "1")
	op := collector.BeginIO(7, "upload", 19)
	if op == nil {
		t.Fatal("missing original intent")
	}
	if _, err := collector.RetireQuiescent(context.Background()); !errors.Is(err, ErrPending) {
		t.Fatalf("unresolved intent certified: %v", err)
	}
	if collector.BeginIO(7, "upload", 1) != nil {
		t.Fatal("retirement reopened admission")
	}
	records, err := spool.Records()
	if err != nil || len(records) != 0 {
		t.Fatalf("unresolved operation exported: records=%d err=%v", len(records), err)
	}
	if err := collector.CompleteIO(op, "upload", 11, false); err != nil {
		t.Fatal(err)
	}
	if err := collector.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err = spool.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("original tail missing after terminal drain: records=%d err=%v", len(records), err)
	}
}

func TestNativeStrictRetirementKeepsOriginalSessionAndMarker(t *testing.T) {
	store, spool, session := nativeFixture(t)
	collector := newNative(t, store, session, "1")
	op := collector.BeginIO(7, "upload", 19)
	if op == nil || collector.CompleteIO(op, "upload", 11, false) != nil {
		t.Fatal("original operation missing")
	}
	boundary, err := collector.RetireQuiescent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	records, err := spool.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("original batch missing: %v", err)
	}
	record := records[0]
	if record.Session.Grants[0].AuthSnapshotID != session.Grants[0].AuthSnapshotID || record.Submission.Payload.EndedAt != boundary.Unix() || boundary.Unix() != store.marker.LastEnd {
		t.Fatal("renewal rewrote the original grant or durable boundary")
	}
	next := newNative(t, store, session, "2")
	if !collector.RenewalSuccessor(next, boundary) || next.ReadyAt().Before(boundary) {
		t.Fatal("next collector overlaps the original whole-second interval")
	}
}

func TestNativeStrictRetirementHonorsCancelledLockWait(t *testing.T) {
	store, _, session := nativeFixture(t)
	collector := newNative(t, store, session, "1")
	collector.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := collector.RetireQuiescent(ctx); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("retirement wait error=%v", err)
		}
	case <-time.After(time.Second):
		collector.mu.Unlock()
		t.Fatal("retirement waited for a blocked persistence owner beyond its deadline")
	}
	collector.mu.Unlock()
	if !collector.Unknown() || collector.state.Retired {
		t.Fatal("cancelled retirement certified a boundary or reopened admission")
	}
}

func TestNativeStrictRetirementRejectsAlreadyFailedOwner(t *testing.T) {
	store, _, session := nativeFixture(t)
	collector := newNative(t, store, session, "1")
	collector.Fail()
	if _, err := collector.RetireQuiescent(context.Background()); !errors.Is(err, ErrUnknown) {
		t.Fatalf("failed collector certified: %v", err)
	}
}
