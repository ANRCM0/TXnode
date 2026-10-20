//go:build linux

package txnode

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

type renewalReadProbe struct{ pauses, resumes int }

func (p *renewalReadProbe) PauseRead() error  { p.pauses++; return nil }
func (p *renewalReadProbe) ResumeRead() error { p.resumes++; return nil }

func renewalMeterFixture(t *testing.T) (*Kernel, *nativeMeter, *usageinterval.NativeStore, *usagev2.Spool, usagev2.Session, map[string]int) {
	t.Helper()
	now := time.Now().Unix()
	session := usagev2.Session{ProtocolVersion: 2, CoreInstanceID: "txnode-renewal", NodeID: "3", SourceEpoch: "5", ReceiptGeneration: "1", RetentionSeconds: 86400, MaxLateReportSeconds: 3600, ReceiptRetentionSeconds: 86400, IssuedAt: now - 1,
		Grants: []usagev2.Grant{{UserID: "7", AccessSubjectID: "8", AuthSnapshotID: "11", TariffRevisionID: "12", TermsID: "13", UsagePeriodID: "14", IssuedAt: now - 1, LeaseExpiresAt: now + 60, RevocationVersion: "0"}}}
	dir := t.TempDir()
	spool, err := usagev2.OpenSpool(filepath.Join(dir, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	store, err := usageinterval.OpenNativeStore(filepath.Join(dir, "native"), session, spool)
	if err != nil {
		spool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close(); spool.Close() })
	users := map[string]int{"renewal-secret": 7}
	collector, err := store.NewCollector(session, usageinterval.NativeWindow{Revision: "1", Digest: strings.Repeat("a", 64), IssuedAt: now - 1, ExpiresAt: now + 60}, users)
	if err != nil {
		t.Fatal(err)
	}
	m := &nativeMeter{collector: collector, users: users}
	if !m.EnableEnforcingBounded() {
		t.Fatal("collector refused admission")
	}
	k := New(RuntimeConfig{})
	k.meter = m
	return k, m, store, spool, session, users
}

func renewalNext(t *testing.T, store *usageinterval.NativeStore, session usagev2.Session, users map[string]int) *usageinterval.NativeCollector {
	t.Helper()
	collector, err := store.NewCollector(session, usageinterval.NativeWindow{Revision: "2", Digest: strings.Repeat("b", 64), IssuedAt: session.IssuedAt, ExpiresAt: session.Grants[0].LeaseExpiresAt}, users)
	if err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(collector.ReadyAt()); delay > 0 {
		time.Sleep(delay)
	}
	return collector
}

func TestNativeRenewalPausesUntilOriginalTokensCompleteAndPublicationResumes(t *testing.T) {
	k, m, store, spool, session, users := renewalMeterFixture(t)
	probe := &renewalReadProbe{}
	unbind, err := m.BindReadPause(probe)
	if err != nil {
		t.Fatal(err)
	}
	defer unbind()
	chunk := core.Chunk{UserID: 7, Dir: core.DirUpload, N: 31}
	token, err := m.Begin(chunk)
	if err != nil {
		t.Fatal(err)
	}
	old := m.collector
	ticket, err := k.PauseNativeRenewal(m)
	if err != nil {
		t.Fatal(err)
	}
	defer ticket.Abort()
	if probe.pauses != 1 {
		t.Fatal("old upload read was not interrupted")
	}
	if _, err := m.Begin(chunk); !errors.Is(err, core.ErrReadPaused) {
		t.Fatalf("pause admitted chunk: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := ticket.WaitQuiescent(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("live token certified: %v", err)
	}
	cancel()
	chunk.N = 17
	m.Complete(chunk, token)
	if err := ticket.WaitQuiescent(context.Background()); err != nil {
		t.Fatal(err)
	}
	boundary, err := ticket.Retire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	records, err := spool.Records()
	if err != nil || len(records) != 1 || records[0].Session.Grants[0].AuthSnapshotID != session.Grants[0].AuthSnapshotID || records[0].Submission.Payload.EndedAt != boundary.Unix() {
		t.Fatal("original grant or terminal batch changed")
	}
	next := renewalNext(t, store, session, users)
	if err := ticket.Commit(next); err != nil {
		t.Fatal(err)
	}
	if m.collector != next || m.collector == old {
		t.Fatal("collector publication missing")
	}
	if _, err := m.Begin(chunk); !errors.Is(err, core.ErrReadPaused) {
		t.Fatal("Commit reopened before deadline publication")
	}
	if err := ticket.Resume(); err != nil {
		t.Fatal(err)
	}
	if probe.resumes != 1 || m.paused || m.stopped.Load() {
		t.Fatal("same hook failed to resume")
	}
	fresh, err := m.Begin(chunk)
	if err != nil {
		t.Fatal(err)
	}
	m.Complete(chunk, fresh)
	m.StopBoundedUsageTraffic()
}

func TestNativeRenewalUnsupportedDoesNotChangeAdmission(t *testing.T) {
	k, m, _, _, _, _ := renewalMeterFixture(t)
	unbind, err := m.BindReadPause(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unbind()
	if _, err := k.PauseNativeRenewal(m); !errors.Is(err, usageinterval.ErrNativeRenewalUnsupported) {
		t.Fatalf("unsupported error=%v", err)
	}
	if m.paused || m.stopped.Load() || m.collector.Unknown() || m.renewal != nil {
		t.Fatal("unsupported probe changed admission")
	}
	m.StopBoundedUsageTraffic()
}

func TestNativeRenewalTerminalLatchSurvivesPausedAndCommittedStates(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "paused", true: "committed"}[commit], func(t *testing.T) {
			k, m, store, _, session, users := renewalMeterFixture(t)
			ticket, err := k.PauseNativeRenewal(m)
			if err != nil {
				t.Fatal(err)
			}
			if commit {
				if _, err := ticket.Retire(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := ticket.Commit(renewalNext(t, store, session, users)); err != nil {
					t.Fatal(err)
				}
			}
			m.StopBoundedUsageTraffic()
			if err := ticket.Resume(); !errors.Is(err, usageinterval.ErrUnknown) {
				t.Fatalf("terminal owner resumed: %v", err)
			}
			ticket.Abort()
			if _, err := m.Begin(core.Chunk{UserID: 7, Dir: core.DirUpload, N: 1}); !errors.Is(err, usageinterval.ErrUnknown) {
				t.Fatal("terminal owner admitted")
			}
		})
	}
}

func TestNativeChunkTokenRejectsForeignAndDuplicateCompletion(t *testing.T) {
	_, issuer, _, _, _, _ := renewalMeterFixture(t)
	_, foreign, _, _, _, _ := renewalMeterFixture(t)
	chunk := core.Chunk{UserID: 7, Dir: core.DirUpload, N: 19}
	token, err := issuer.Begin(chunk)
	if err != nil {
		t.Fatal(err)
	}
	foreign.Complete(chunk, token)
	if !foreign.stopped.Load() || foreign.inflight.Load() != 0 || issuer.inflight.Load() != 1 || token.(*chunkTokens).completed.Load() {
		t.Fatal("foreign completion consumed issuer permit")
	}
	issuer.Complete(chunk, token)
	if issuer.inflight.Load() != 0 {
		t.Fatal("original owner failed to release permit")
	}
	issuer.Complete(chunk, token)
	if !issuer.stopped.Load() || issuer.inflight.Load() != 0 {
		t.Fatal("duplicate completion reopened or underflowed owner")
	}
}

func TestNativeTokenKeepsIssuingCollectorAcrossPublication(t *testing.T) {
	_, m, store, spool, session, users := renewalMeterFixture(t)
	old := m.collector
	chunk := core.Chunk{UserID: 7, Dir: core.DirUpload, N: 23}
	token, err := m.Begin(chunk)
	if err != nil {
		t.Fatal(err)
	}
	next := renewalNext(t, store, session, users)
	// Exercise token provenance independently from the stricter ticket, which
	// normally forbids publication until every original operation has completed.
	m.gateMu.Lock()
	m.collector = next
	m.gateMu.Unlock()
	chunk.N = 13
	m.Complete(chunk, token)
	if next.Unknown() || old.Unknown() || m.inflight.Load() != 0 {
		t.Fatal("completion was routed to the current collector instead of its issuer")
	}
	if err := old.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := spool.Records()
	if err != nil || len(records) != 1 || len(records[0].Submission.Payload.Entries) != 1 || records[0].Submission.Payload.Entries[0].RawUpBytes != "13" {
		t.Fatalf("original completion evidence missing: records=%+v err=%v", records, err)
	}
	m.StopBoundedUsageTraffic()
}

func TestNativeRenewalCommitRejectsDifferentStore(t *testing.T) {
	k, m, _, _, _, _ := renewalMeterFixture(t)
	_, foreign, _, _, _, _ := renewalMeterFixture(t)
	ticket, err := k.PauseNativeRenewal(m)
	if err != nil {
		t.Fatal(err)
	}
	defer ticket.Abort()
	if _, err := ticket.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ticket.Commit(foreign.collector); !errors.Is(err, usageinterval.ErrUnknown) {
		t.Fatalf("foreign durable owner accepted: %v", err)
	}
	if m.collector == foreign.collector || !m.paused {
		t.Fatal("rejected commit changed publication or admission")
	}
	foreign.StopBoundedUsageTraffic()
}
