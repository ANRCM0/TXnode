//go:build linux

package service

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/outbound"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

func TestNativeRenewalEligibilityPreservesAuthorityAndAccountingIdentity(t *testing.T) {
	origin := nativeConfigOrigin(t)
	_, initial := nativeConfigPanel(t, authorityPort(t), origin)
	s, plane := nativeConfigService(t, initial, "http://127.0.0.1:1")
	current := s.authorization.Current()
	next := plane.snapshot(t).Authorization
	if !nativeRenewalEquivalent(current, next) {
		t.Fatal("a verified ordinary snapshot renewal was not eligible")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*authorization.Snapshot)
	}{
		{"credential-generation", func(v *authorization.Snapshot) { v.Payload.Provider.Subjects[0].CredentialGeneration = "2" }},
		{"credential-reference", func(v *authorization.Snapshot) { v.Payload.Provider.Subjects[0].CredentialRef += "x" }},
		{"material", func(v *authorization.Snapshot) { v.Users[0].UUID = "ffeeddcc-bbaa-4988-8877-665544332211" }},
		{"user-limit", func(v *authorization.Snapshot) { v.Users[0].DeviceLimit++ }},
		{"terms", func(v *authorization.Snapshot) { v.Payload.UsageV2.Grants[0].TermsID = "99" }},
		{"tariff", func(v *authorization.Snapshot) { v.Payload.UsageV2.Grants[0].TariffRevisionID = "99" }},
		{"period", func(v *authorization.Snapshot) { v.Payload.UsageV2.Grants[0].UsagePeriodID = "99" }},
		{"revocation", func(v *authorization.Snapshot) { v.Payload.UsageV2.Grants[0].RevocationVersion = "1" }},
		{"source-epoch", func(v *authorization.Snapshot) { v.Payload.UsageV2.SourceEpoch = "2" }},
		{"receipt-generation", func(v *authorization.Snapshot) { v.Payload.UsageV2.ReceiptGeneration = "2" }},
		{"provider-epoch", func(v *authorization.Snapshot) { v.Payload.Provider.ProviderInstanceEpoch = "2" }},
		{"recipient", func(v *authorization.Snapshot) { v.Payload.Provider.RecipientSHA256 += "0" }},
		{"shorter-envelope", func(v *authorization.Snapshot) { v.Payload.ExpiresAt = current.Payload.ExpiresAt - 1 }},
		{"shorter-credential", func(v *authorization.Snapshot) {
			v.Payload.Provider.Subjects[0].CredentialExpiresAt = current.Payload.Provider.Subjects[0].CredentialExpiresAt - 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(next)
			var changed authorization.Snapshot
			if err != nil || json.Unmarshal(raw, &changed) != nil {
				t.Fatal("snapshot fixture could not be cloned", err)
			}
			tc.mutate(&changed)
			if nativeRenewalEquivalent(current, &changed) {
				t.Fatal("changed authority was treated as a connection-preserving renewal")
			}
		})
	}
	if !nativeRenewalEquivalent(current, next) {
		t.Fatal("eligibility checking mutated the original verified snapshots")
	}
}

func TestNativeRenewalKeepsIdleEstablishedFlowAndOriginalGrantBatches(t *testing.T) {
	testNativeRenewalKeepsIdleEstablishedFlowAndOriginalGrantBatches(t, "vless")
}

func TestNativeVMessRenewalKeepsIdleEstablishedFlowAndOriginalGrantBatches(t *testing.T) {
	testNativeRenewalKeepsIdleEstablishedFlowAndOriginalGrantBatches(t, "vmess")
}

func testNativeRenewalKeepsIdleEstablishedFlowAndOriginalGrantBatches(t *testing.T, protocol string) {
	t.Helper()
	origin := nativeConfigOrigin(t)
	_, initial := nativeConfigPanel(t, authorityPort(t), origin)
	initial.Protocol = protocol
	s, plane := nativeConfigService(t, initial, "http://127.0.0.1:1")
	var stream net.Conn
	switch protocol {
	case "vless":
		_, stream = nativeC2VLESSDial(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(initial.ServerPort)), plane.uuidOrDefault(), origin.Addr())
	case "vmess":
		// Match machineCoreDial's same-repository client and plain TCP server.
		// Independent third-party interoperability remains a separate gate.
		client, err := outbound.New("vmess", opt.Opt{
			"server": "127.0.0.1", "port": initial.ServerPort, "uuid": plane.uuidOrDefault(),
			"method": "aes-128-gcm", "network": "tcp",
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		stream, err = client.DialTCP(ctx, socks.FromNetAddr(origin.Addr()))
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unsupported renewal test protocol", protocol)
	}
	defer stream.Close()
	meter := s.nativeUsage.active.Load()
	grants := map[string]string{}
	expected := map[string]int64{}
	currentGrant := ""
	remember := func(snapshot *authorization.Snapshot) {
		grant := snapshot.Payload.UsageV2.Grants[0]
		grants[grant.AuthSnapshotID] = grant.UsagePeriodID
		currentGrant = grant.AuthSnapshotID
	}
	remember(s.authorization.Current())
	var bytes int64
	for i := 0; i < 3; i++ {
		body := "before-renewal-" + strconv.Itoa(i)
		nativeConfigEcho(t, stream, body)
		bytes += int64(len(body))
		expected[currentGrant] += int64(len(body))
		old := s.nativeUsage.collector.Load()
		next := plane.snapshot(t)
		next.Config = nil
		remember(next.Authorization)
		if err := s.applyNativeAuthorization(context.Background(), next, false); err != nil {
			t.Fatal("ordinary renewal closed a proven plain "+protocol+" flow", err)
		}
		if s.nativeUsage.active.Load() != meter || s.nativeUsage.collector.Load() == old || !old.Unknown() ||
			s.authorization.Current().Digest != next.Authorization.Digest || !s.kernel.IsRunning() {
			t.Fatal("renewal replaced the hook or failed to retire the old grant")
		}
		body = "after-renewal-" + strconv.Itoa(i)
		nativeConfigEcho(t, stream, body)
		bytes += int64(len(body))
		expected[currentGrant] += int64(len(body))
	}
	if err := s.drainNativeUsage(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := s.nativeUsage.spool.Records()
	if err != nil || len(records) != 4 {
		t.Fatal("renewed grants did not retain their separate original batches", len(records), err)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Submission.Payload.StartedAt < records[j].Submission.Payload.StartedAt
	})
	var totals [2]int64
	seen := map[string]bool{}
	for i, record := range records {
		payload := record.Submission.Payload
		if record.Submission.Validate() != nil || i > 0 && payload.StartedAt < records[i-1].Submission.Payload.EndedAt {
			t.Fatal("renewal produced invalid or overlapping original intervals")
		}
		if len(payload.Entries) != 1 {
			t.Fatal("renewal batch lost its unique original grant")
		}
		for _, entry := range payload.Entries {
			if seen[entry.AuthSnapshotID] || grants[entry.AuthSnapshotID] != entry.UsagePeriodID || entry.UsagePeriodID != "14" {
				t.Fatal("renewal relabeled the original snapshot or usage period")
			}
			seen[entry.AuthSnapshotID] = true
			up, upErr := strconv.ParseInt(entry.RawUpBytes, 10, 64)
			down, downErr := strconv.ParseInt(entry.RawDownBytes, 10, 64)
			if upErr != nil || downErr != nil {
				t.Fatal("invalid original byte evidence")
			}
			if up != expected[entry.AuthSnapshotID] || down != expected[entry.AuthSnapshotID] {
				t.Fatalf("renewal moved actual bytes between original grants: snapshot=%s got=%d/%d want=%d each", entry.AuthSnapshotID, up, down, expected[entry.AuthSnapshotID])
			}
			totals[0] += up
			totals[1] += down
		}
	}
	if len(grants) != 4 || len(seen) != len(grants) {
		t.Fatal("renewal did not preserve all four distinct signed grants")
	}
	if totals != [2]int64{bytes, bytes} {
		t.Fatalf("renewal lost or duplicated actual stream bytes: got=%v want=%d each", totals, bytes)
	}
}

type nativeRenewalBlockingKernel struct {
	kernel.Kernel
	entered chan struct{}
	release chan struct{}
}

type nativeRenewalUnsupportedKernel struct {
	kernel.Kernel
	nativeUsageKernel
}

func (*nativeRenewalUnsupportedKernel) PauseNativeRenewal(usageinterval.Meter) (usageinterval.RenewalTicket, error) {
	return nil, usageinterval.ErrNativeRenewalUnsupported
}

func TestNativeRenewalUnsupportedPauseKeepsOriginalRestartPath(t *testing.T) {
	origin := nativeConfigOrigin(t)
	_, initial := nativeConfigPanel(t, authorityPort(t), origin)
	s, plane := nativeConfigService(t, initial, "http://127.0.0.1:1")
	old := s.nativeUsage.collector.Load()
	meter := s.nativeUsage.active.Load()
	s.kernel = &nativeRenewalUnsupportedKernel{Kernel: s.kernel, nativeUsageKernel: s.kernel.(nativeUsageKernel)}
	next := plane.snapshot(t)
	if err := s.applyNativeAuthorization(context.Background(), next, false); err != nil {
		t.Fatal("unsupported safe pause changed the existing restart contract", err)
	}
	if !old.Unknown() || s.nativeUsage.collector.Load() == old || s.nativeUsage.active.Load() == meter ||
		s.authorization.Current().Digest != next.Authorization.Digest || !s.kernel.IsRunning() {
		t.Fatal("unsupported pause failed to rebuild a fresh original metered runtime")
	}
	_, fresh := nativeC2VLESSDial(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(initial.ServerPort)), plane.uuidOrDefault(), origin.Addr())
	defer fresh.Close()
	nativeConfigEcho(t, fresh, "restarted-with-fresh-signed-grant")
}

func (k *nativeRenewalBlockingKernel) PauseNativeRenewal(meter usageinterval.Meter) (usageinterval.RenewalTicket, error) {
	ticket, err := k.Kernel.(nativeRenewalKernel).PauseNativeRenewal(meter)
	if err != nil {
		return nil, err
	}
	return &nativeRenewalBlockingTicket{RenewalTicket: ticket, entered: k.entered, release: k.release}, nil
}

type nativeRenewalBlockingTicket struct {
	usageinterval.RenewalTicket
	entered chan struct{}
	release chan struct{}
}

func (t *nativeRenewalBlockingTicket) WaitQuiescent(ctx context.Context) error {
	if err := t.RenewalTicket.WaitQuiescent(ctx); err != nil {
		return err
	}
	close(t.entered)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.release:
		return nil
	}
}

func TestNativeRenewalCurrentCutoffCannotResumePausedOwner(t *testing.T) {
	origin := nativeConfigOrigin(t)
	_, initial := nativeConfigPanel(t, authorityPort(t), origin)
	s, plane := nativeConfigService(t, initial, "http://127.0.0.1:1")
	_, stream := nativeC2VLESSDial(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(initial.ServerPort)), plane.uuidOrDefault(), origin.Addr())
	defer stream.Close()
	nativeConfigEcho(t, stream, "before-current-cutoff")
	old := s.authorization.Current()
	collector := s.nativeUsage.collector.Load()
	blocking := &nativeRenewalBlockingKernel{Kernel: s.kernel, entered: make(chan struct{}), release: make(chan struct{})}
	s.kernel = blocking
	next := plane.snapshot(t)
	next.Config = nil
	result := make(chan error, 1)
	go func() { result <- s.applyNativeAuthorization(context.Background(), next, false) }()
	select {
	case <-blocking.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("renewal did not reach a quiescent paused owner")
	}
	s.quarantineNativeUsage(usagev2.Record{Session: *old.Payload.UsageV2,
		Submission: usagev2.Submission{Payload: usagev2.Payload{Entries: []usagev2.Entry{{AuthSnapshotID: old.Payload.UsageV2.Grants[0].AuthSnapshotID}}}}})
	close(blocking.release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("matching current cutoff resumed a renewed owner")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cutoff could not terminate renewal")
	}
	if !s.nativeUsage.refreshNeeded.Load() || s.nativeUsage.collector.Load() != collector ||
		s.authorization.Current().Digest != old.Digest || !collector.Unknown() {
		t.Fatal("cutoff advanced authority or replaced the original collector")
	}
	stream.SetDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := stream.Read(one[:]); err == nil {
		t.Fatal("quarantined paused stream remained usable")
	}
}
