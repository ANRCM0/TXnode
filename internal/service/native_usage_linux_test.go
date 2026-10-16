//go:build linux

package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/kernel/singbox"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/panel"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

type nativeBillingKernel struct {
	*fakeKernel
	prepared *singbox.ConnTracker
}

func (k *nativeBillingKernel) SetNativeUsageTracker(tracker *singbox.ConnTracker) bool {
	if k.running || tracker == nil {
		return false
	}
	k.prepared = tracker
	return true
}
func (k *nativeBillingKernel) Protocols() []string { return []string{"vless", "vmess"} }

type nativeBillingPlane struct {
	*authorityTestPlane
	manager   *authorization.Manager
	key       ed25519.PrivateKey
	trust     authorization.Trust
	revision  int
	period    string
	empty     bool
	uuid      string
	transport *modeTransport
}

func (p *nativeBillingPlane) PrepareNativeUsageV2(string) error { return nil }
func (p *nativeBillingPlane) RefreshAuthorization(context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{Users: p.bootstrap.Users, Authorization: p.bootstrap.Authorization}, nil
}
func (p *nativeBillingPlane) ConfigureAuthorization(manager *authorization.Manager) error {
	p.manager = manager
	return manager.SetTrust(p.trust)
}
func (p *nativeBillingPlane) snapshot(t *testing.T) controlplane.Snapshot {
	t.Helper()
	p.revision++
	now := time.Now().Unix()
	uuid := p.uuid
	if uuid == "" {
		uuid = "00112233-4455-4677-8899-aabbccddeeff"
	}
	sum := sha256.Sum256([]byte(uuid))
	users := []panel.User{{ID: 7, UUID: uuid}}
	commitments := []panel.User{{ID: 7, UUID: "sha256:" + hex.EncodeToString(sum[:])}}
	subjects := []credentialdelivery.Subject{{UserID: 7, AccessSubjectID: "10", SubscriptionID: "11", TermsID: "12",
		ProviderSubjectRef: "subject_" + strings.Repeat("a", 32), CredentialRef: "credential_" + strings.Repeat("b", 32), CredentialGeneration: "1", CredentialExpiresAt: now + 3600}}
	session := usagev2.Session{ProtocolVersion: 2, CoreInstanceID: p.trust.CoreInstanceID, NodeID: "42", SourceEpoch: "1", ReceiptGeneration: "1",
		RetentionSeconds: 86400, MaxLateReportSeconds: 3600, ReceiptRetentionSeconds: 86400, IssuedAt: now,
		Grants: []usagev2.Grant{{UserID: "7", AccessSubjectID: "10", AuthSnapshotID: strconv.Itoa(100 + p.revision),
			TariffRevisionID: "5", TermsID: "12", UsagePeriodID: p.period, IssuedAt: now, LeaseExpiresAt: now + 60, RevocationVersion: "0"}}}
	if p.empty {
		users, commitments, subjects, session.Grants = []panel.User{}, []panel.User{}, []credentialdelivery.Subject{}, []usagev2.Grant{}
	}
	payload := credentialdelivery.Payload{ProtocolVersion: 1, Audience: credentialdelivery.Audience, PolicyVersion: credentialdelivery.PolicyVersionV2,
		CoreInstanceID: p.trust.CoreInstanceID, NodeID: 42, Revision: strconv.Itoa(p.revision), KeyID: p.trust.KeyID, KeyEpoch: "1",
		IssuedAt: now, NotBefore: now - 5, ExpiresAt: now + 60, Complete: true, Users: commitments, UsageV2: &session,
		Provider: credentialdelivery.ProviderBinding{InstallationID: p.trust.CoreInstanceID, ProviderID: "primary-provider", ProviderInstanceEpoch: "1",
			RecipientSHA256: strings.Repeat("c", 64), CredentialProfileID: "vless-uuid/v1", Subjects: subjects}}
	raw, _ := json.Marshal(payload)
	envelope := authorization.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(p.key, raw))}
	snapshot, err := p.manager.Verify(envelope, users, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return controlplane.Snapshot{Config: p.bootstrap.Config, Users: model.UserSpecsFromPanel(users), Authorization: snapshot}
}

func nativeBillingService(t *testing.T) (*Service, *nativeBillingKernel, *nativeBillingPlane) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	base := &authorityTestPlane{bootstrap: controlplane.Bootstrap{Config: &model.NodeSpec{Protocol: "vless", Network: "tcp", ListenIP: "127.0.0.1", ServerPort: 12345}}}
	plane := &nativeBillingPlane{authorityTestPlane: base, key: key, period: "14"}
	plane.trust = authorization.Trust{ProtocolVersion: 1, CoreInstanceID: "1b32d316-8cb8-4b46-8d49-e281c28d5169", KeyID: "native-billing", KeyEpoch: "1",
		Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	original := authorityService(t, base)
	original.cfg.Panel.URL = "https://127.0.0.1:18443"
	root := t.TempDir()
	original.cfg.Authorization = config.AuthorizationConfig{Enabled: true, StateDir: filepath.Join(root, "authority"), CoreInstanceID: plane.trust.CoreInstanceID,
		KeyID: plane.trust.KeyID, KeyEpoch: "1", PublicKey: plane.trust.PublicKey, PolicyVersion: config.NativeProviderUsagePolicyVersion, RefreshInterval: 30, MaxClockSkew: 5,
		Provider: config.AuthorizationProviderConfig{Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1",
			CAFile: filepath.Join(root, "ca.pem"), ClientCert: filepath.Join(root, "node.pem"), ClientKey: filepath.Join(root, "node.key")}}
	original.cfg.UsageV2 = config.UsageV2Config{Enabled: true, Directory: filepath.Join(root, "usage")}
	s := NewWithControlPlane(original.cfg, plane)
	kernel := &nativeBillingKernel{fakeKernel: &fakeKernel{}}
	s.kernel, s.kernelLife = kernel, kernellifecycle.New(kernel)
	if err := s.preflightUsageV2(); err != nil {
		t.Fatal(err)
	}
	if err := s.initAuthorization(); err != nil {
		t.Fatal(err)
	}
	snapshot := plane.snapshot(t)
	plane.transport = &modeTransport{session: *snapshot.Authorization.Payload.UsageV2, receipts: map[string]usagev2.Receipt{}}
	plane.bootstrap.Authorization, plane.bootstrap.Users = snapshot.Authorization, snapshot.Users
	plane.bootstrap.UsageV2Session, plane.bootstrap.UsageV2Transport, plane.bootstrap.UsageV2NativeHTTP = snapshot.Authorization.Payload.UsageV2, plane.transport, true
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.stopNativeUsageIO(); s.kernel.Stop(); s.closeNativeUsage(); s.closeAuthorization() })
	return s, kernel, plane
}

func TestNativeBillingRefreshResetAndEmptyRevocationPreserveOriginalSessions(t *testing.T) {
	s, kernel, plane := nativeBillingService(t)
	if !kernel.running || kernel.startCalls != 1 || !s.nativeUsageMode() {
		t.Fatal("native billing did not start")
	}
	first := s.nativeUsage.collector.Load()
	op := first.BeginIO(7, "upload", 17)
	if op == nil || first.CompleteIO(op, "upload", 17, false) != nil {
		t.Fatal("first period capture failed")
	}
	refreshed := plane.snapshot(t)
	refreshed.Config = nil
	if err := s.applyNativeAuthorization(context.Background(), refreshed, false); err != nil {
		t.Fatal(err)
	}
	if !kernel.running || kernel.startCalls != 2 {
		t.Fatal("ordinary lease refresh did not restart a metered session")
	}
	second := s.nativeUsage.collector.Load()
	op = second.BeginIO(7, "download", 11)
	if op == nil || second.CompleteIO(op, "download", 11, false) != nil {
		t.Fatal("renewed period capture failed")
	}
	plane.period = "24"
	if err := s.applyNativeAuthorization(context.Background(), plane.snapshot(t), false); err != nil {
		t.Fatal(err)
	}
	third := s.nativeUsage.collector.Load()
	op = third.BeginIO(7, "upload", 3)
	if op == nil || third.CompleteIO(op, "upload", 3, false) != nil {
		t.Fatal("reset period capture failed")
	}
	plane.empty = true
	empty := plane.snapshot(t)
	empty.Config = nil
	if err := s.applyNativeAuthorization(context.Background(), empty, false); err != nil {
		t.Fatal(err)
	}
	if kernel.running || s.users.Count() != 0 {
		t.Fatal("empty revocation left native users active")
	}
	records, err := s.nativeUsage.spool.Records()
	if err != nil || len(records) != 3 {
		t.Fatal("tail records missing", err)
	}
	for i, record := range records {
		want := "14"
		if i == 2 {
			want = "24"
		}
		if record.Submission.Payload.Entries[0].UsagePeriodID != want ||
			i > 0 && record.Submission.Payload.StartedAt < records[i-1].Submission.Payload.EndedAt {
			t.Fatal("reset relabeled or overlapped previous period")
		}
	}
	report := s.prepareReportBatch()
	if len(report.Payload.Traffic) != 0 || len(report.Payload.TrafficSegments) != 0 || s.tracker.HasTraffic() {
		t.Fatal("native usage was also queued into legacy billing")
	}
	if err := s.nativeUsage.reporter.DeliverPage(context.Background(), 16); err != nil {
		t.Fatal(err)
	}
	if len(plane.transport.snapshot()) != 3 {
		t.Fatal("original-session batches were not delivered")
	}
}

func TestNativeBillingReverifiesExportedUsageSessionBeforeHandoff(t *testing.T) {
	s, kernel, plane := nativeBillingService(t)
	next := plane.snapshot(t)
	originalPeriod := next.Authorization.Payload.UsageV2.Grants[0].UsagePeriodID
	next.Authorization.Payload.UsageV2.Grants[0].UsagePeriodID = "999"
	if err := s.applyNativeAuthorization(context.Background(), next, false); err != nil {
		t.Fatal(err)
	}
	if !kernel.running || s.authorization.Current().Payload.UsageV2.Grants[0].UsagePeriodID != originalPeriod {
		t.Fatal("exported Session mutated signed billing authority")
	}
}

func TestNativeBillingRotationAndShutdownSealPriorCredentialEvidence(t *testing.T) {
	s, kernel, plane := nativeBillingService(t)
	old := s.nativeUsage.collector.Load()
	op := old.BeginIO(7, "upload", 23)
	if op == nil || old.CompleteIO(op, "upload", 23, false) != nil {
		t.Fatal("old credential evidence missing")
	}
	plane.uuid = "11223344-5566-4788-99aa-bbccddeeff00"
	if err := s.applyNativeAuthorization(context.Background(), plane.snapshot(t), false); err != nil {
		t.Fatal(err)
	}
	if !kernel.running || kernel.startCalls != 2 || s.users.Users()[0].UUID != plane.uuid || old.CheckCurrent() == nil {
		t.Fatal("credential rotation reused old kernel admission")
	}
	current := s.nativeUsage.collector.Load()
	op = current.BeginIO(7, "download", 29)
	if op == nil || current.CompleteIO(op, "download", 29, false) != nil {
		t.Fatal("replacement credential evidence missing")
	}
	if err := s.drainNativeUsage(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := s.nativeUsage.spool.Records()
	if err != nil || len(records) != 2 || records[0].Submission.Payload.Entries[0].RawUpBytes != "23" ||
		records[1].Submission.Payload.Entries[0].RawDownBytes != "29" ||
		records[0].Session.Grants[0].AuthSnapshotID == records[1].Session.Grants[0].AuthSnapshotID {
		t.Fatal("rotation or shutdown merged prior credential sessions", err)
	}
}

type nativeRefusalTransport struct {
	submits int
	session usagev2.Session
	receipt *usagev2.Receipt
}

func (t *nativeRefusalTransport) Get(context.Context, usagev2.Query) (usagev2.Receipt, bool, error) {
	if t.receipt != nil {
		return *t.receipt, true, nil
	}
	return usagev2.Receipt{}, false, nil
}
func (t *nativeRefusalTransport) Submit(_ context.Context, submission usagev2.Submission) (usagev2.Receipt, error) {
	t.submits++
	if t.session.NodeID != "" {
		t.receipt = &usagev2.Receipt{
			ProtocolVersion: 2, CoreInstanceID: t.session.CoreInstanceID, ReceiptGeneration: t.session.ReceiptGeneration,
			NodeID: submission.Payload.NodeID, SourceEpoch: submission.Payload.SourceEpoch,
			BatchID: submission.Payload.BatchID, PayloadDigest: submission.PayloadDigest, ReceiptID: "native-cutoff-receipt",
			ReceiptStatus: "persisted", SettlementStatus: "quarantined", ReasonCode: usagev2.NativeCutoffCode,
			AcceptedAt: time.Now().Unix(),
		}
		return *t.receipt, nil
	}
	return usagev2.Receipt{}, &usagev2.HTTPError{Status: 422, Code: usagev2.NativeCutoffCode}
}

func TestNativeCutoffClosesAffectedAdmissionAndHigherRevisionRecoversWithoutReposting(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		name := "legacy422"
		if persisted {
			name = "persisted receipt"
		}
		t.Run(name, func(t *testing.T) {
			s, kernel, plane := nativeBillingService(t)
			current := s.authorization.Current()
			session := *current.Payload.UsageV2
			submission, err := session.Build(session.IssuedAt, session.IssuedAt+1, map[int][2]int64{7: {13, 17}})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.nativeUsage.spool.Save(usagev2.Record{SchemaVersion: 1, Session: session, Submission: submission}); err != nil {
				t.Fatal(err)
			}
			transport := &nativeRefusalTransport{}
			if persisted {
				transport.session = session
			}
			s.nativeUsage.reporter, err = usagev2.NewReporter(session, s.nativeUsage.spool, transport)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.nativeUsage.reporter.DeliverNativePage(context.Background(), 16, s.quarantineNativeUsage); err != nil {
				t.Fatal(err)
			}
			if !s.nativeUsage.refreshNeeded.Load() || s.nativeUsage.failed.Load() ||
				s.nativeUsage.collector.Load().BeginIO(7, "upload", 1) != nil {
				t.Fatal("current rejected authority remained usable or permanently poisoned Service")
			}
			select {
			case <-s.nativeUsageRefreshChannel():
			default:
				t.Fatal("cutoff failed to request fresh signed authority")
			}
			replay := controlplane.Snapshot{Users: model.UserSpecsFromPanel(current.Users), Authorization: current}
			if err := s.applyNativeAuthorization(context.Background(), replay, false); err != nil {
				t.Fatal(err)
			}
			if !s.nativeUsage.refreshNeeded.Load() || s.startKernel(s.lastConfig, s.users.Users()) {
				t.Fatal("same signed revision reopened rejected admission")
			}
			if err := s.applyNativeAuthorization(context.Background(), plane.snapshot(t), false); err != nil {
				t.Fatal(err)
			}
			if !kernel.running || kernel.startCalls != 2 || s.nativeUsage.refreshNeeded.Load() {
				t.Fatal("higher signed revision could not recover legal admission")
			}
			if err := s.nativeUsage.reporter.DeliverNativePage(context.Background(), 16, s.quarantineNativeUsage); err != nil {
				t.Fatal(err)
			}
			if transport.submits != 1 || s.nativeUsage.refreshNeeded.Load() || s.nativeUsage.collector.Load().CheckCurrent() != nil {
				t.Fatal("old quarantined history blocked or was relabeled into the new grant")
			}
			records, err := s.nativeUsage.spool.Records()
			if err != nil || len(records) != 1 || records[0].Submission.PayloadDigest != submission.PayloadDigest ||
				!bytes.Equal(mustNativeC2JSON(t, records[0].Session), mustNativeC2JSON(t, session)) ||
				(persisted && (records[0].Receipt == nil || records[0].LocalQuarantine != nil ||
					records[0].Receipt.SettlementStatus != "quarantined" ||
					records[0].Receipt.ReasonCode != usagev2.NativeCutoffCode)) ||
				(!persisted && (records[0].Receipt != nil || records[0].LocalQuarantine == nil)) ||
				s.nativeUsage.reporter.NativeQuarantinedCount() != 1 {
				t.Fatal("cutoff recovery changed original capture or confused Core receipt with local refusal", err)
			}
		})
	}
}
