package usageinterval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

type testClock struct {
	mu sync.Mutex
	at stamp
}

func (c *testClock) read() stamp { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *testClock) set(wall int64, nanos int64, elapsed time.Duration) {
	c.mu.Lock()
	c.at = stamp{wall*int64(time.Second) + nanos, int64(elapsed)}
	c.mu.Unlock()
}
func fixtureSession() usagev2.Session {
	return usagev2.Session{ProtocolVersion: 2, CoreInstanceID: "core-synthetic-1", NodeID: "3", SourceEpoch: "5", ReceiptGeneration: "1", RetentionSeconds: 86400, MaxLateReportSeconds: 3600, ReceiptRetentionSeconds: 86400, IssuedAt: 900, Grants: []usagev2.Grant{{UserID: "7", AccessSubjectID: "9007199254740993", AuthSnapshotID: "11", TariffRevisionID: "12", TermsID: "13", UsagePeriodID: "14", IssuedAt: 900, LeaseExpiresAt: 2000, RevocationVersion: "0"}}}
}
func fixture(t *testing.T) (*Collector, *Journal, *usagev2.Spool, *testClock) {
	t.Helper()
	dir := t.TempDir()
	spool, err := usagev2.OpenSpool(filepath.Join(dir, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(filepath.Join(dir, "interval"), fixtureSession(), spool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close(); spool.Close() })
	clock := &testClock{}
	clock.set(1000, 100000000, 0)
	c, err := newCollector(fixtureSession(), map[string]int{"private-runtime-user": 7}, j, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	return c, j, spool, clock
}
func op(c *Collector, n int64, dir string) { o := c.Begin(7); c.Complete(o, dir, n, false) }
func batches(t *testing.T, spool *usagev2.Spool) []usagev2.Record {
	t.Helper()
	r, err := spool.Records()
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestIntegerPartitionKeepsActualPhysicalDirectionsAndImmutableGrants(t *testing.T) {
	c, _, spool, clock := fixture(t)
	op(c, 11, "upload")
	clock.set(1001, 100000000, time.Second)
	op(c, 7, "download")
	s, err := c.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if s.Payload.StartedAt != 1000 || s.Payload.EndedAt != 1001 || s.Payload.Entries[0].RawUpBytes != "11" || s.Payload.Entries[0].RawDownBytes != "0" || s.Payload.Entries[0].AccessSubjectID != "9007199254740993" {
		t.Fatal("incorrect physical binding")
	}
	clock.set(1002, 100000000, 2*time.Second)
	next, err := c.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if next.Payload.StartedAt != s.Payload.EndedAt || next.Payload.EndedAt != 1002 || next.Payload.Entries[0].RawUpBytes != "0" || next.Payload.Entries[0].RawDownBytes != "7" || next.Payload.BatchID == s.Payload.BatchID {
		t.Fatal("adjacent intervals overlap or lose counters")
	}
	if len(batches(t, spool)) != 2 {
		t.Fatal("expected two immutable batches")
	}
	if _, err := c.Flush(); err != ErrPending {
		t.Fatal("repeated flush invented batch")
	}
}
func TestInflightAndCrossingOperationsDeferWithoutLosingOrMovingBytes(t *testing.T) {
	c, _, spool, clock := fixture(t)
	operation := c.Begin(7)
	clock.set(1001, 100000000, time.Second)
	if _, err := c.Flush(); err != ErrPending {
		t.Fatal("inflight accepted")
	}
	c.Complete(operation, "upload", 19, true)
	if _, err := c.Flush(); err != ErrPending {
		t.Fatal("crossing operation split")
	}
	if len(batches(t, spool)) != 0 || len(c.completed) != 1 {
		t.Fatal("pending counters dropped")
	}
	clock.set(1002, 0, 2*time.Second)
	s, err := c.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if s.Payload.StartedAt != 1000 || s.Payload.EndedAt != 1002 || s.Payload.Entries[0].RawUpBytes != "19" {
		t.Fatal("deferred range was reassigned")
	}
}
func TestFlushFsyncDoesNotLoseNewConcurrentIO(t *testing.T) {
	c, j, spool, clock := fixture(t)
	op(c, 3, "upload")
	clock.set(1001, 0, time.Second)
	entered, release := make(chan struct{}), make(chan struct{})
	once := sync.Once{}
	j.fault = func(stage string) error {
		if stage == "after_file_sync" {
			once.Do(func() { close(entered); <-release })
		}
		return nil
	}
	finished := make(chan error, 1)
	go func() { _, err := c.Flush(); finished <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("flush did not reach fsync")
	}
	clock.set(1001, 500000000, 1500*time.Millisecond)
	op(c, 23, "download")
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	clock.set(1002, 0, 2*time.Second)
	s, err := c.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if s.Payload.StartedAt != 1001 || s.Payload.Entries[0].RawDownBytes != "23" || len(batches(t, spool)) != 2 {
		t.Fatal("I/O during Flush lost")
	}
}
func TestBoundedJournalFsyncFaultsRetainOriginalBatchIdentity(t *testing.T) {
	for _, stage := range []string{"before_file_sync", "after_file_sync", "after_publish", "after_dir_sync", "before_spool", "after_spool", "file_syscall", "directory_syscall"} {
		t.Run(stage, func(t *testing.T) {
			c, j, spool, clock := fixture(t)
			op(c, 29, "upload")
			clock.set(1001, 0, time.Second)
			fileSync, dirSync := j.syncFile, j.syncDir
			j.fault = func(at string) error {
				if at == stage {
					return errors.New("synthetic sync fault")
				}
				return nil
			}
			if stage == "file_syscall" {
				j.syncFile = func(*os.File) error { return errors.New("synthetic file fsync") }
			}
			if stage == "directory_syscall" {
				j.syncDir = func(string) error { return errors.New("synthetic directory fsync") }
			}
			if s, err := c.Flush(); err == nil || s != nil || c.pending == nil {
				t.Fatal("fault returned durable batch")
			}
			frozen := c.pending.Record.Submission
			j.fault = nil
			j.syncFile = fileSync
			j.syncDir = dirSync
			s, err := c.Flush()
			if err != nil {
				t.Fatal(err)
			}
			if s.Payload.BatchID != frozen.Payload.BatchID || s.PayloadDigest != frozen.PayloadDigest || len(batches(t, spool)) != 1 {
				t.Fatal("retry generated second batch")
			}
			if err := j.Recover(); err != nil {
				t.Fatal(err)
			}
			if len(batches(t, spool)) != 1 {
				t.Fatal("recovery duplicated batch")
			}
		})
	}
}
func TestUnknownClockLeaseIdentityDuplicateCompletionAndCapacityFailClosed(t *testing.T) {
	for _, reason := range []string{"wall_rollback", "monotonic_rollback", "lease_expiry", "monotonic_lease_expiry", "no_grant", "duplicate_completion", "negative", "overflow", "changed_user_map", "close", "capacity"} {
		t.Run(reason, func(t *testing.T) {
			c, _, spool, clock := fixture(t)
			operation := c.Begin(7)
			switch reason {
			case "wall_rollback":
				clock.set(1000, 99999999, time.Second)
			case "monotonic_rollback":
				clock.set(1000, 200000000, -time.Nanosecond)
			case "lease_expiry":
				clock.set(2000, 0, 1000*time.Second)
			case "monotonic_lease_expiry":
				clock.set(1001, 0, 1000*time.Second)
			case "no_grant":
				c.Begin(8)
			case "duplicate_completion":
				c.Complete(operation, "upload", 1, false)
			case "changed_user_map":
				c.CheckUsers(map[string]int{"changed": 7})
			case "close":
				c.Close()
			case "capacity":
				for i := 0; i < MaxOperations; i++ {
					c.Begin(7)
				}
			}
			n := int64(1)
			if reason == "negative" {
				n = -1
			}
			if reason == "overflow" {
				n = int64(usagev2.MaxRawBytes) + 1
			}
			c.Complete(operation, "upload", n, false)
			if !c.Unknown() {
				t.Fatal("invalid producer did not fail-stop immediately")
			}
			clock.set(1002, 0, 2*time.Second)
			if s, err := c.Flush(); err != ErrUnknown || s != nil || len(batches(t, spool)) != 0 {
				t.Fatal("unknown evidence accepted")
			}
		})
	}
}
func TestCollectorCannotResumeAnOldSourceOrMutateCallerGrant(t *testing.T) {
	c, j, spool, clock := fixture(t)
	op(c, 5, "upload")
	clock.set(1001, 0, time.Second)
	first, err := c.Flush()
	if err != nil {
		t.Fatal(err)
	}
	session := fixtureSession()
	if _, err := newCollector(session, map[string]int{"private-runtime-user": 7}, j, clock.read); err != ErrUnknown {
		t.Fatal("source epoch resumed")
	}
	j.Close()
	reopened, err := OpenJournal(j.dir, session, spool)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := newCollector(session, map[string]int{"private-runtime-user": 7}, reopened, clock.read); err != ErrUnknown {
		t.Fatal("restart resumed old live timeline")
	}
	session.SourceEpoch = "6"
	reopened.Close()
	next, err := OpenJournal(j.dir, session, spool)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	collector, err := newCollector(session, map[string]int{"private-runtime-user": 7}, next, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	session.Grants[0].AccessSubjectID = "999"
	op(collector, 9, "download")
	clock.set(1002, 0, 2*time.Second)
	second, err := collector.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if second.Payload.SourceEpoch != "6" || second.Payload.Entries[0].AccessSubjectID != "9007199254740993" || first.Payload.SourceEpoch != "5" || len(batches(t, spool)) != 2 {
		t.Fatal("frozen binding changed")
	}
}
func TestConstructionRejectsMissingDuplicateOutOfRangeOrUnknownGrants(t *testing.T) {
	for _, reason := range []string{"nil", "unknown_user", "oversized_id", "duplicate_user", "duplicate_subject", "expired", "too_many"} {
		t.Run(reason, func(t *testing.T) {
			_, j, _, clock := fixture(t)
			session := fixtureSession()
			users := map[string]int{"private-runtime-user": 7}
			switch reason {
			case "nil":
				session.Grants = nil
			case "unknown_user":
				users = map[string]int{"private-runtime-user": 8}
			case "oversized_id":
				users = map[string]int{"private-runtime-user": 2147483648}
			case "duplicate_user":
				session.Grants = append(session.Grants, session.Grants[0])
			case "duplicate_subject":
				g := session.Grants[0]
				g.UserID = "8"
				session.Grants = append(session.Grants, g)
				users["other"] = 8
			case "expired":
				session.Grants[0].LeaseExpiresAt = 999
			case "too_many":
				users = map[string]int{}
				for i := 0; i < MaxGrants+1; i++ {
					session.Grants = append(session.Grants, session.Grants[0])
				}
			}
			if _, err := newCollector(session, users, j, clock.read); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
}

type transport struct {
	session       usagev2.Session
	stored        *usagev2.Receipt
	submits, gets int
	lost          bool
}

func (f *transport) Get(context.Context, usagev2.Query) (usagev2.Receipt, bool, error) {
	f.gets++
	if f.stored == nil {
		return usagev2.Receipt{}, false, nil
	}
	return *f.stored, true, nil
}
func (f *transport) Submit(_ context.Context, s usagev2.Submission) (usagev2.Receipt, error) {
	f.submits++
	r := usagev2.Receipt{ProtocolVersion: 2, CoreInstanceID: f.session.CoreInstanceID, ReceiptGeneration: f.session.ReceiptGeneration, NodeID: s.Payload.NodeID, SourceEpoch: s.Payload.SourceEpoch, BatchID: s.Payload.BatchID, PayloadDigest: s.PayloadDigest, ReceiptStatus: "persisted", SettlementStatus: "pending", AcceptedAt: s.Payload.EndedAt, ReceiptID: "receipt-synthetic-1"}
	f.stored = &r
	if f.lost {
		return usagev2.Receipt{}, errors.New("synthetic response loss")
	}
	return r, nil
}
func TestJournalRecoveryPreservesCoreReceiptsAndReporterQueryBeforeReplay(t *testing.T) {
	c, j, spool, clock := fixture(t)
	op(c, 17, "upload")
	clock.set(1001, 0, time.Second)
	original, err := c.Flush()
	if err != nil {
		t.Fatal(err)
	}
	f := &transport{session: fixtureSession(), lost: true}
	reporter, err := usagev2.NewReporter(f.session, spool, f)
	if err != nil {
		t.Fatal(err)
	}
	if reporter.Deliver(context.Background()) == nil {
		t.Fatal("response loss hidden")
	}
	if err := reporter.Deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.submits != 1 || f.gets != 2 {
		t.Fatal("did not query original batch before replay")
	}
	if err := j.Recover(); err != nil {
		t.Fatal(err)
	}
	records := batches(t, spool)
	if len(records) != 1 || records[0].Receipt == nil || records[0].Submission.Payload.BatchID != original.Payload.BatchID {
		t.Fatal("journal overwrote Core ACK")
	}
	f.stored = nil
	if err := reporter.Deliver(context.Background()); err != usagev2.ErrRecoveryRequired {
		t.Fatal("confirmed missing Core receipt accepted")
	}
}

func TestJournalIdentityDriftCorruptEvidenceAndExclusiveLockAreClosed(t *testing.T) {
	for _, kind := range []string{"Core", "Node", "generation", "bytes", "sequence", "extra", "ownership", "closed_spool"} {
		t.Run(kind, func(t *testing.T) {
			c, j, spool, clock := fixture(t)
			op(c, 13, "upload")
			clock.set(1001, 0, time.Second)
			if _, err := c.Flush(); err != nil {
				t.Fatal(err)
			}
			if kind == "closed_spool" {
				spool.Close()
				if err := j.Recover(); err == nil {
					t.Fatal("closed spool accepted")
				}
				return
			}
			files, _ := os.ReadDir(j.dir)
			var path string
			for _, f := range files {
				if journalName.MatchString(f.Name()) {
					path = filepath.Join(j.dir, f.Name())
				}
			}
			raw, _ := os.ReadFile(path)
			var env envelope
			if json.Unmarshal(raw, &env) != nil {
				t.Fatal("fixture record unavailable")
			}
			switch kind {
			case "Core":
				env.Record.Session.CoreInstanceID = "core-other-instance"
			case "Node":
				env.Record.Session.NodeID = "99"
			case "generation":
				env.Record.Session.ReceiptGeneration = "2"
			case "bytes":
				env.Record.Evidence[0].Bytes++
			case "sequence":
				env.Record.Evidence[0].Sequence = 0
			case "ownership":
				env.Record.Evidence[0].UserID = "8"
			case "extra":
				raw = append(raw, ' ')
			}
			if kind != "extra" {
				raw, _ = json.Marshal(env)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := j.Recover(); err == nil {
				t.Fatal("corrupt journal accepted")
			}
		})
	}
	_, j, spool, _ := fixture(t)
	if other, err := OpenJournal(j.dir, fixtureSession(), spool); err == nil {
		other.Close()
		t.Fatal("parallel journal owner accepted")
	}
}
func TestJournalFilesArePrivateAndDoNotPersistRuntimeUUIDOrCredentials(t *testing.T) {
	c, j, _, clock := fixture(t)
	op(c, 37, "download")
	clock.set(1001, 0, time.Second)
	if _, err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(j.dir)
	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatal("journal readable by other OS users")
		}
		raw, err := os.ReadFile(filepath.Join(j.dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("private-runtime-user")) || bytes.Contains(raw, []byte("password")) || bytes.Contains(raw, []byte("uuid")) {
			t.Fatal("runtime credential label persisted")
		}
	}
}

func TestJournalFutureSourceEpochAndRehashedSequenceReplayCannotExport(t *testing.T) {
	c, j, spool, clock := fixture(t)
	op(c, 43, "upload")
	clock.set(1001, 0, time.Second)
	if _, err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	j.current.SourceEpoch = "4"
	if err := j.Recover(); err != ErrUnknown {
		t.Fatal("future source epoch exported under rollback")
	}
	j.current.SourceEpoch = "5"
	files, _ := os.ReadDir(j.dir)
	var path string
	for _, f := range files {
		if journalName.MatchString(f.Name()) {
			path = filepath.Join(j.dir, f.Name())
		}
	}
	raw, _ := os.ReadFile(path)
	original, err := decodeClaim(raw)
	if err != nil {
		t.Fatal(err)
	}
	record := original.Record
	record.Interval = 2
	next, err := makeClaim(record.Collector, record.Interval, record.Session, record.Submission, record.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(j.path(next), next.encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.Recover(); err != ErrUnknown {
		t.Fatal("rehashed interval/operation replay accepted")
	}
	if len(batches(t, spool)) != 1 {
		t.Fatal("replay exported another batch")
	}
}
