//go:build linux

package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

type nativeStartupTransport struct {
	mu          sync.Mutex
	session     usagev2.Session
	gets        int
	submissions []usagev2.Submission
	preAck      bool
	mismatch    bool
	cutoff      bool
	localOnly   bool
	failure     error
	blockAt     int
	entered     chan struct{}
	release     chan struct{}
}

func (p *nativeStartupTransport) receipt(q usagev2.Query) usagev2.Receipt {
	r := usagev2.Receipt{ProtocolVersion: 2, CoreInstanceID: p.session.CoreInstanceID,
		ReceiptGeneration: p.session.ReceiptGeneration, NodeID: q.NodeID, SourceEpoch: q.SourceEpoch,
		BatchID: q.BatchID, PayloadDigest: q.PayloadDigest, ReceiptStatus: "persisted",
		SettlementStatus: "pending", AcceptedAt: time.Now().Unix(), ReceiptID: "native-startup-receipt"}
	if p.cutoff {
		r.SettlementStatus, r.ReasonCode = "quarantined", usagev2.NativeCutoffCode
	}
	if p.mismatch {
		r.PayloadDigest = "sha256:" + strings.Repeat("f", 64)
	}
	return r
}

func (p *nativeStartupTransport) Get(ctx context.Context, q usagev2.Query) (usagev2.Receipt, bool, error) {
	p.mu.Lock()
	p.gets++
	block := p.gets == p.blockAt
	p.mu.Unlock()
	if block {
		close(p.entered)
		select {
		case <-ctx.Done():
			return usagev2.Receipt{}, false, ctx.Err()
		case <-p.release:
		}
	}
	if p.failure != nil {
		return usagev2.Receipt{}, false, p.failure
	}
	if p.preAck {
		return p.receipt(q), true, nil
	}
	return usagev2.Receipt{}, false, nil
}

func (p *nativeStartupTransport) Submit(_ context.Context, submission usagev2.Submission) (usagev2.Receipt, error) {
	p.mu.Lock()
	p.submissions = append(p.submissions, submission)
	p.mu.Unlock()
	if p.localOnly {
		return usagev2.Receipt{}, &usagev2.HTTPError{Status: 422, Code: usagev2.NativeCutoffCode}
	}
	return p.receipt(submission.Query()), nil
}

func nativeStartupFixture(t *testing.T, empty bool) (*Service, *nativeStartupTransport) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	base := &authorityTestPlane{bootstrap: controlplane.Bootstrap{Config: &model.NodeSpec{
		Protocol: "vless", Network: "tcp", ListenIP: "127.0.0.1", ServerPort: authorityPort(t)}}}
	plane := &nativeBillingPlane{authorityTestPlane: base, key: key, revision: 1, period: "14", empty: empty}
	plane.trust = authorization.Trust{ProtocolVersion: 1, CoreInstanceID: "1b32d316-8cb8-4b46-8d49-e281c28d5169",
		KeyID: "native-startup", KeyEpoch: "1", Algorithm: "Ed25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	cfg := authorityService(t, base).cfg
	cfg.Panel.URL = "https://127.0.0.1:18443"
	root := t.TempDir()
	cfg.Authorization = config.AuthorizationConfig{Enabled: true, StateDir: filepath.Join(root, "authority"),
		CoreInstanceID: plane.trust.CoreInstanceID, KeyID: plane.trust.KeyID, KeyEpoch: "1",
		PublicKey: plane.trust.PublicKey, PolicyVersion: config.NativeProviderUsagePolicyVersion,
		RefreshInterval: 30, MaxClockSkew: 5, Provider: config.AuthorizationProviderConfig{
			Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1",
			CAFile: filepath.Join(root, "ca.pem"), ClientCert: filepath.Join(root, "node.pem"), ClientKey: filepath.Join(root, "node.key")}}
	cfg.UsageV2 = config.UsageV2Config{Enabled: true, Directory: filepath.Join(root, "usage")}
	s := NewWithControlPlane(cfg, plane)
	if err := s.preflightNativeUsage(); err != nil {
		t.Fatal(err)
	}
	if err := s.initAuthorization(); err != nil {
		t.Fatal(err)
	}
	snapshot := plane.snapshot(t)
	var payload credentialdelivery.Payload
	if err := json.Unmarshal(snapshot.Authorization.PayloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	payload.UsageV2.SourceEpoch = "2"
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope := authorization.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
	verified, err := plane.manager.Verify(envelope, snapshot.Authorization.Users, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	transport := &nativeStartupTransport{session: *verified.Payload.UsageV2}
	plane.bootstrap.Authorization, plane.bootstrap.Users = verified, snapshot.Users
	plane.bootstrap.UsageV2Session = verified.Payload.UsageV2
	plane.bootstrap.UsageV2Transport, plane.bootstrap.UsageV2NativeHTTP = transport, true
	t.Cleanup(func() { s.stopNativeUsageIO(); s.kernel.Stop(); s.closeNativeUsage(); s.closeAuthorization() })
	return s, transport
}

// The sealed spool and unsealed completed native intent use an older source
// epoch and grant. Opening NativeStore must export that intent before replay.
func nativeStartupSeed(t *testing.T, s *Service, count int, completedIntent, currentGrant bool) []usagev2.Record {
	t.Helper()
	session := *s.source.(*nativeBillingPlane).bootstrap.Authorization.Payload.UsageV2
	session.Grants = append([]usagev2.Grant{}, session.Grants...)
	if !currentGrant {
		session.SourceEpoch, session.IssuedAt = "1", session.IssuedAt-60
		session.Grants = []usagev2.Grant{{UserID: "7", AccessSubjectID: "10", AuthSnapshotID: "100",
			TariffRevisionID: "5", TermsID: "12", UsagePeriodID: "13", IssuedAt: session.IssuedAt,
			LeaseExpiresAt: session.IssuedAt + 120, RevocationVersion: "0"}}
	}
	directory := filepath.Join(s.cfg.UsageV2.Directory, "node-42")
	spool, err := usagev2.OpenSpool(filepath.Join(directory, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	var original []usagev2.Record
	for i := 0; i < count; i++ {
		started := session.IssuedAt + int64(i)
		submission, err := session.Build(started, started+1, map[int][2]int64{7: {int64(i + 1), 3}})
		if err != nil {
			t.Fatal(err)
		}
		record := usagev2.Record{SchemaVersion: 1, Session: session, Submission: submission}
		if err := spool.Save(record); err != nil {
			t.Fatal(err)
		}
		original = append(original, record)
	}
	if completedIntent {
		store, err := usageinterval.OpenNativeStore(filepath.Join(directory, "native"), session, spool)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		collector, err := store.NewCollector(session, usageinterval.NativeWindow{Revision: "1", Digest: strings.Repeat("d", 64),
			IssuedAt: session.IssuedAt, ExpiresAt: session.Grants[0].LeaseExpiresAt}, map[string]int{"synthetic-old": 7})
		if err != nil {
			t.Fatal(err)
		}
		op := collector.BeginIO(7, "upload", 11)
		if op == nil || collector.CompleteIO(op, "upload", 11, false) != nil {
			t.Fatal("could not retain completed native intent")
		}
	}
	return original
}

func nativeStartupListening(s *Service) bool {
	port := s.source.(*nativeBillingPlane).bootstrap.Config.ServerPort
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 30*time.Millisecond)
	if err == nil {
		conn.Close()
	}
	return err == nil
}

func nativeStartupRecords(t *testing.T, s *Service) []usagev2.Record {
	t.Helper()
	if s.nativeUsage != nil {
		records, err := s.nativeUsage.spool.Records()
		if err != nil {
			t.Fatal(err)
		}
		return records
	}
	spool, err := usagev2.OpenSpool(filepath.Join(s.cfg.UsageV2.Directory, "node-42", "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	records, err := spool.Records()
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func TestNativeStartupRecoveryAcknowledgesAllPagesBeforeRealListener(t *testing.T) {
	s, transport := nativeStartupFixture(t, false)
	original := nativeStartupSeed(t, s, 17, true, false)
	transport.blockAt, transport.entered, transport.release = 17, make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.initialSetup(ctx) }()
	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("second recovery page not reached")
	}
	if nativeStartupListening(s) || s.nativeUsage.collector.Load() != nil {
		t.Fatal("listener or collector installed before all recovery pages were acknowledged")
	}
	close(transport.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup recovery did not complete")
	}
	if !nativeStartupListening(s) || !s.kernel.IsRunning() {
		t.Fatal("real native listener did not open after durable acknowledgements")
	}
	records := nativeStartupRecords(t, s)
	if len(records) != 18 || len(transport.submissions) != 18 || transport.gets != 18 {
		t.Fatalf("recovery omitted a page or unsealed intent: records=%d submits=%d gets=%d", len(records), len(transport.submissions), transport.gets)
	}
	for i, record := range records {
		if record.Receipt == nil || record.Receipt.SettlementStatus != "pending" ||
			record.Receipt.Validate(record.Session, record.Submission) != nil || record.Session.SourceEpoch != "1" ||
			record.Submission.Payload.Entries[0].UsagePeriodID != "13" {
			t.Fatal("recovery lost durable custody or original billing authority")
		}
		if i < len(original) && (!reflect.DeepEqual(record.Session, original[i].Session) ||
			!reflect.DeepEqual(record.Submission, original[i].Submission)) {
			t.Fatal("recovery rewrote an original session or payload")
		}
	}
}

func TestNativeStartupRecoveryQueriesLostAcknowledgementWithoutRepost(t *testing.T) {
	s, transport := nativeStartupFixture(t, false)
	nativeStartupSeed(t, s, 1, false, false)
	transport.preAck = true
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !nativeStartupListening(s) || len(transport.submissions) != 0 || transport.gets != 1 {
		t.Fatal("lost acknowledgement was reposted or listener was not admitted")
	}
}

func TestNativeStartupRecoveryFailuresKeepRealListenerClosed(t *testing.T) {
	for _, mode := range []string{"transport", "receipt-mismatch", "current-cutoff", "known-current-cutoff", "known-receipt-mismatch", "local-marker", "cancel", "page-timeout"} {
		t.Run(mode, func(t *testing.T) {
			s, transport := nativeStartupFixture(t, false)
			original := nativeStartupSeed(t, s, 1, false, mode == "current-cutoff" || mode == "known-current-cutoff")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "transport":
				transport.failure = usagev2.ErrTransportUnavailable
			case "receipt-mismatch":
				transport.mismatch = true
			case "current-cutoff":
				transport.cutoff = true
			case "known-current-cutoff", "known-receipt-mismatch":
				transport.cutoff = mode == "known-current-cutoff"
				spool, err := usagev2.OpenSpool(filepath.Join(s.cfg.UsageV2.Directory, "node-42", "spool"), 0)
				if err != nil {
					t.Fatal(err)
				}
				record := original[0]
				receipt := transport.receipt(record.Submission.Query())
				record.Receipt = &receipt
				if err := spool.Save(record); err != nil {
					t.Fatal(err)
				}
				spool.Close()
				if mode == "known-receipt-mismatch" {
					// Simulate a corrupt persisted receipt, not a sanctioned Save.
					record.Receipt.PayloadDigest = "sha256:" + strings.Repeat("f", 64)
					raw, err := json.Marshal(record)
					if err != nil {
						t.Fatal(err)
					}
					files, err := filepath.Glob(filepath.Join(s.cfg.UsageV2.Directory, "node-42", "spool", "*.usage.json"))
					if err != nil || len(files) != 1 {
						t.Fatal("original capture not found", err)
					}
					if err := os.WriteFile(files[0], raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "local-marker":
				transport.localOnly = true
			case "cancel", "page-timeout":
				transport.blockAt, transport.entered, transport.release = 1, make(chan struct{}), make(chan struct{})
			}
			done := make(chan error, 1)
			go func() { done <- s.initialSetup(ctx) }()
			if transport.entered != nil {
				select {
				case <-transport.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("recovery transport not reached")
				}
				if nativeStartupListening(s) || s.nativeUsage.collector.Load() != nil {
					t.Fatal("blocked recovery installed a listener or collector")
				}
				if mode == "cancel" {
					cancel()
				}
			}
			select {
			case err := <-done:
				if err == nil || mode == "cancel" && !errors.Is(err, context.Canceled) ||
					mode == "page-timeout" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("startup accepted failed recovery: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("failed startup recovery did not terminate")
			}
			if nativeStartupListening(s) || s.kernel.IsRunning() || s.nativeUsage != nil {
				t.Fatal("failed recovery installed a runtime or listener")
			}
			if mode == "known-current-cutoff" || mode == "known-receipt-mismatch" {
				if transport.gets != 0 || len(transport.submissions) != 0 {
					t.Fatal("known receipt triggered recovery HTTP")
				}
				if mode == "known-receipt-mismatch" {
					return // The corrupt spool is intentionally unreadable.
				}
			}
			records := nativeStartupRecords(t, s)
			if len(records) != 1 || !reflect.DeepEqual(records[0].Session, original[0].Session) ||
				!reflect.DeepEqual(records[0].Submission, original[0].Submission) {
				t.Fatal("failed recovery relabeled or lost original evidence")
			}
			if mode == "local-marker" && (records[0].LocalQuarantine == nil || records[0].Receipt != nil) {
				t.Fatal("local refusal was treated as a Core acknowledgement")
			}
		})
	}
}

func TestNativeStartupRecoveryHistoricalCutoffAndEmptyBootstrap(t *testing.T) {
	for _, empty := range []bool{false, true} {
		for _, known := range []bool{false, true} {
			t.Run(fmt.Sprintf("empty=%t/known=%t", empty, known), func(t *testing.T) {
				s, transport := nativeStartupFixture(t, empty)
				original := nativeStartupSeed(t, s, 1, false, false)
				transport.cutoff = true
				if known {
					spool, err := usagev2.OpenSpool(filepath.Join(s.cfg.UsageV2.Directory, "node-42", "spool"), 0)
					if err != nil {
						t.Fatal(err)
					}
					record := original[0]
					receipt := transport.receipt(record.Submission.Query())
					record.Receipt = &receipt
					if err := spool.Save(record); err != nil {
						t.Fatal(err)
					}
					spool.Close()
				}
				if err := s.initialSetup(context.Background()); err != nil {
					t.Fatal(err)
				}
				records := nativeStartupRecords(t, s)
				if len(records) != 1 || records[0].Receipt == nil || records[0].Receipt.SettlementStatus != "quarantined" ||
					s.nativeUsage.refreshNeeded.Load() || nativeStartupListening(s) == empty {
					t.Fatal("historical durable cutoff affected current grant or empty bootstrap skipped recovery")
				}
				if known && transport.gets != 0 {
					t.Fatal("known historical cutoff was queried instead of acknowledged locally")
				}
			})
		}
	}
}

func nativeStartupBudgetRecords(t *testing.T, s *Service, transport *nativeStartupTransport, acknowledged bool) int {
	t.Helper()
	count := nativeStartupRecoveryPages*nativeStartupRecoveryPageSize + 1
	session := transport.session
	session.SourceEpoch, session.IssuedAt = "1", session.IssuedAt-60
	session.Grants = append([]usagev2.Grant{}, session.Grants...)
	for i := range session.Grants {
		session.Grants[i].IssuedAt = session.IssuedAt
		session.Grants[i].AuthSnapshotID, session.Grants[i].UsagePeriodID = "100", "13"
	}
	spool, err := usagev2.OpenSpool(filepath.Join(s.cfg.UsageV2.Directory, "node-42", "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	for i := 0; i < count; i++ {
		submission, err := session.Build(session.IssuedAt, session.IssuedAt+1, map[int][2]int64{7: {int64(i + 1), 0}})
		if err != nil {
			t.Fatal(err)
		}
		record := usagev2.Record{SchemaVersion: 1, Session: session, Submission: submission}
		if acknowledged {
			receipt := transport.receipt(submission.Query())
			record.Receipt = &receipt
		}
		if err := spool.Save(record); err != nil {
			t.Fatal(err)
		}
	}
	return count
}

func TestNativeStartupRecoveryWorkBudget(t *testing.T) {
	if nativeStartupRecoveryPageSize != 16 || nativeStartupRecoveryPages != 16 ||
		nativeStartupRecoveryTimeout > 30*time.Second || nativeStartupRecoveryPageWait > 2*time.Second {
		t.Fatal("startup recovery work or timeout budget changed")
	}
	s, transport := nativeStartupFixture(t, false)
	// Valid overlapping captures are retained by the spool; startup must reject
	// work above its own budget before making any recovery HTTP request.
	count := nativeStartupBudgetRecords(t, s, transport, false)
	if err := s.initialSetup(context.Background()); err == nil || transport.gets != 0 ||
		nativeStartupListening(s) || len(nativeStartupRecords(t, s)) != count {
		t.Fatal("over-budget startup admitted traffic, attempted HTTP or discarded captures")
	}
}

func TestNativeStartupRecoveryRetainedAcknowledgementsDoNotConsumeNetworkBudget(t *testing.T) {
	s, transport := nativeStartupFixture(t, false)
	count := nativeStartupBudgetRecords(t, s, transport, true)
	transport.failure = usagev2.ErrTransportUnavailable
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatal("already acknowledged history blocked startup", err)
	}
	if !nativeStartupListening(s) || transport.gets != 0 || len(transport.submissions) != 0 ||
		len(nativeStartupRecords(t, s)) != count {
		t.Fatal("retained durable acknowledgements consumed recovery budget or HTTP")
	}
}
