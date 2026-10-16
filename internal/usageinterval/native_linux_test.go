//go:build linux

package usageinterval

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

const nativeTestUUID = "00112233-4455-4677-8899-aabbccddeeff"

func nativeSession() usagev2.Session {
	now := time.Now().Unix()
	session := fixtureSession()
	session.IssuedAt = now - 5
	session.Grants[0].IssuedAt, session.Grants[0].LeaseExpiresAt = session.IssuedAt, now+60
	return session
}

func nativeWindow(session usagev2.Session, revision string) NativeWindow {
	expires := session.IssuedAt + 60
	if len(session.Grants) > 0 {
		expires = session.Grants[0].LeaseExpiresAt
	}
	return NativeWindow{Revision: revision, Digest: strings.Repeat("a", 64), IssuedAt: session.IssuedAt, ExpiresAt: expires}
}

func nativeFixture(t *testing.T) (*NativeStore, *usagev2.Spool, usagev2.Session) {
	t.Helper()
	root := t.TempDir()
	spool, err := usagev2.OpenSpool(filepath.Join(root, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	session := nativeSession()
	store, err := OpenNativeStore(filepath.Join(root, "native"), session, spool)
	if err != nil {
		spool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close(); spool.Close() })
	return store, spool, session
}

func newNative(t *testing.T, store *NativeStore, session usagev2.Session, revision string) *NativeCollector {
	t.Helper()
	users := map[string]int{nativeTestUUID: 7}
	if len(session.Grants) == 0 {
		users = map[string]int{}
	}
	collector, err := store.NewCollector(session, nativeWindow(session, revision), users)
	if err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(collector.ReadyAt()); delay > 0 {
		time.Sleep(delay)
	}
	return collector
}

func nativeStateOnDisk(t *testing.T, collector *NativeCollector) nativeState {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(collector.store.dir, collector.state.Collector+".native"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), nativeTestUUID) {
		t.Fatal("UUID material entered usage evidence")
	}
	var state nativeState
	if decodeNative(raw, &state) != nil || validateNativeState(state) != nil {
		t.Fatal("invalid durable native evidence")
	}
	return state
}

func TestNativeIntentPrecedesIOAndCompletedTailKeepsOriginalPeriod(t *testing.T) {
	store, spool, session := nativeFixture(t)
	first := newNative(t, store, session, "1")
	operation := first.BeginIO(7, "upload", 17)
	if operation == nil {
		t.Fatal("I/O admission missing")
	}
	durable := nativeStateOnDisk(t, first)
	if len(durable.Events) != 1 || durable.Events[0].Done || durable.Events[0].Requested != 17 {
		t.Fatal("I/O escaped without a durable intent")
	}
	if first.CompleteIO(operation, "upload", 17, true) != nil {
		t.Fatal("partial-positive I/O was lost")
	}
	down := first.BeginIO(7, "download", 11)
	if down == nil || first.CompleteIO(down, "download", 11, false) != nil {
		t.Fatal("download evidence missing")
	}
	if first.Drain(context.Background()) != nil {
		t.Fatal("tail failed to seal")
	}
	before, err := spool.Records()
	if err != nil || len(before) != 1 {
		t.Fatal("original batch missing", err)
	}
	entry := before[0].Submission.Payload.Entries[0]
	if entry.RawUpBytes != "17" || entry.RawDownBytes != "11" || entry.UsagePeriodID != session.Grants[0].UsagePeriodID {
		t.Fatal("tail bytes or original period changed", entry)
	}
	next := session
	next.Grants = append([]usagev2.Grant{}, session.Grants...)
	next.Grants[0].TermsID, next.Grants[0].UsagePeriodID, next.Grants[0].AuthSnapshotID = "23", "24", "25"
	second := newNative(t, store, next, "2")
	op := second.BeginIO(7, "upload", 3)
	if op == nil || second.CompleteIO(op, "upload", 3, false) != nil || second.Drain(context.Background()) != nil {
		t.Fatal("new interval failed")
	}
	records, err := spool.Records()
	if err != nil || len(records) != 2 || records[0].Submission.PayloadDigest != before[0].Submission.PayloadDigest ||
		records[1].Submission.Payload.Entries[0].UsagePeriodID != "24" ||
		records[1].Submission.Payload.StartedAt < records[0].Submission.Payload.EndedAt {
		t.Fatal("handoff relabeled/overlapped an original batch", err)
	}
}

func TestNativeCrashRecoveryExportsCompletedEvidenceAndQuarantinesPendingIntent(t *testing.T) {
	store, spool, session := nativeFixture(t)
	first := newNative(t, store, session, "1")
	completed := first.BeginIO(7, "upload", 19)
	if completed == nil || first.CompleteIO(completed, "upload", 19, false) != nil {
		t.Fatal("completed evidence failed")
	}
	if first.BeginIO(7, "download", 31) == nil {
		t.Fatal("pending intent failed")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenNativeStore(store.dir, session, spool)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	records, err := spool.Records()
	if err != nil || len(records) != 1 || records[0].Submission.Payload.Entries[0].RawUpBytes != "19" {
		t.Fatal("crash discarded completed tail", err)
	}
	if recovered.QuarantinedCollectors() != 1 {
		t.Fatal("uncertain I/O disappeared from recovery state")
	}
	if _, err := recovered.NewCollector(session, nativeWindow(session, "1"), map[string]int{nativeTestUUID: 7}); err == nil {
		t.Fatal("old signed revision resumed a crashed timeline")
	}
	original := records[0].Submission
	second := newNative(t, recovered, session, "2")
	if err := second.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	again, _ := spool.Records()
	if len(again) != 1 || again[0].Submission.Payload.BatchID != original.Payload.BatchID || again[0].Submission.PayloadDigest != original.PayloadDigest {
		t.Fatal("recovery invented a new batch for the same bytes")
	}
}

func TestNativeLateCompletionStaysWithRetiredCollector(t *testing.T) {
	store, spool, session := nativeFixture(t)
	first := newNative(t, store, session, "1")
	op := first.BeginIO(7, "upload", 13)
	if op == nil {
		t.Fatal("intent failed")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := first.Drain(cancelled); err != nil {
		t.Fatal(err)
	}
	second := newNative(t, store, session, "2")
	if err := first.CompleteIO(op, "upload", 7, true); err != nil {
		t.Fatal("late known bytes not retained", err)
	}
	state := nativeStateOnDisk(t, first)
	if !state.Retired || len(state.Events) != 1 || state.Events[0].Bytes != 7 || state.Events[0].Eligible {
		t.Fatal("late callback moved into new authority")
	}
	records, err := spool.Records()
	if err != nil || len(records) != 0 {
		t.Fatal("unknown late I/O was fabricated into billable usage", err)
	}
	if second.CheckCurrent() != nil {
		t.Fatal("retired callbacks modified the new timeline")
	}
}

func TestNativeCleanRefreshReclaimsJournalAndRefusesClosedOwner(t *testing.T) {
	store, _, session := nativeFixture(t)
	session.Grants = []usagev2.Grant{}
	for revision := 1; revision <= 140; revision++ {
		collector := newNative(t, store, session, strconv.Itoa(revision))
		if err := collector.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.ReadDir(store.dir)
	if err != nil || len(files) != 2 {
		t.Fatal("clean refresh retained every collector journal", len(files), err)
	}
	withUsers := nativeSession()
	collector := newNative(t, store, withUsers, "141")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if collector.BeginIO(7, "upload", 8) != nil {
		t.Fatal("closed durable owner admitted I/O")
	}
}

func TestNativeSealedPayloadMustAgreeWithExactDurableEvidence(t *testing.T) {
	store, _, session := nativeFixture(t)
	collector := newNative(t, store, session, "1")
	op := collector.BeginIO(7, "upload", 9)
	if op == nil || collector.CompleteIO(op, "upload", 9, false) != nil {
		t.Fatal("evidence failed")
	}
	state := nativeStateOnDisk(t, collector)
	end := state.Events[0].Completed.Wall/int64(time.Second) + 1
	batch, err := session.Build(state.StartedAt, end, map[int][2]int64{7: {99, 0}})
	if err != nil {
		t.Fatal(err)
	}
	state.Pending = &usagev2.Record{SchemaVersion: 1, Session: session, Submission: batch}
	state.PendingSequences, state.PendingEnd = []uint64{state.Events[0].Sequence}, end
	if validateNativeState(state) == nil {
		t.Fatal("sealed bytes no longer matched durable I/O evidence")
	}
}

func TestNativePendingReadKeepsCompletedWritesBoundedUntilOriginalSessionDrain(t *testing.T) {
	store, spool, session := nativeFixture(t)
	collector := newNative(t, store, session, "1")
	pending := collector.BeginIO(7, "download", 8192)
	if pending == nil {
		t.Fatal("pending read was not durably admitted")
	}
	const writes = MaxOperations + 16
	for i := 0; i < writes; i++ {
		op := collector.BeginIO(7, "upload", 3)
		if op == nil || collector.CompleteIO(op, "upload", 3, false) != nil {
			t.Fatalf("completed operations exhausted the bounded journal at %d", i)
		}
	}
	state := nativeStateOnDisk(t, collector)
	if len(state.Events) != 2 || state.Events[0].Done || state.Events[1].Operations != writes ||
		state.Events[1].Bytes != 3*writes || state.Events[1].Requested != 3*writes {
		t.Fatal("completed I/O aggregation changed bytes or lost the pending intent")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := collector.Drain(cancelled); err != nil {
		t.Fatal(err)
	}
	records, err := spool.Records()
	if err != nil || len(records) != 1 || records[0].Submission.Payload.Entries[0].RawUpBytes != strconv.Itoa(3*writes) {
		t.Fatal("bounded aggregation did not seal exact original bytes", err)
	}
	next := newNative(t, store, session, "2")
	if err := collector.CompleteIO(pending, "download", 7, true); err != nil {
		t.Fatal(err)
	}
	remaining := nativeStateOnDisk(t, collector)
	if len(remaining.Events) != 1 || remaining.Events[0].Bytes != 7 || remaining.Events[0].Eligible ||
		next.CheckCurrent() != nil {
		t.Fatal("late original read was relabeled into the replacement Session")
	}
}

func TestNativeClockRollbackAndOfflineExpiryPreserveUncertainEvidence(t *testing.T) {
	for _, reason := range []string{"clock_rollback", "offline_expiry"} {
		t.Run(reason, func(t *testing.T) {
			store, spool, session := nativeFixture(t)
			collector := newNative(t, store, session, "1")
			op := collector.BeginIO(7, "upload", 19)
			if op == nil {
				t.Fatal("intent missing")
			}
			if reason == "clock_rollback" {
				collector.last.Wall = time.Now().Add(time.Minute).UnixNano()
				collector.last.Elapsed = 0
			} else {
				collector.deadline = time.Now().Add(-time.Second)
			}
			if err := collector.CompleteIO(op, "upload", 13, true); err != nil {
				t.Fatal("uncertain completion was not retained", err)
			}
			if collector.CheckCurrent() == nil || collector.BeginIO(7, "upload", 1) != nil {
				t.Fatal("uncertain authority admitted more I/O")
			}
			if err := collector.Drain(context.Background()); err != nil {
				t.Fatal(err)
			}
			state := nativeStateOnDisk(t, collector)
			records, err := spool.Records()
			if err != nil || len(records) != 0 || len(state.Events) != 1 || state.Events[0].Bytes != 13 || state.Events[0].Eligible {
				t.Fatal("uncertain completion became a successful usage acknowledgement", err)
			}
		})
	}
}
