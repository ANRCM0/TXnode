//go:build linux

package txnode

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

func TestNativeMeterAuthorizationGenerations(t *testing.T) {
	now := time.Now().Unix()
	session := usagev2.Session{ProtocolVersion: 2, CoreInstanceID: "txnode-generation", NodeID: "3", SourceEpoch: "5", ReceiptGeneration: "1", RetentionSeconds: 86400, MaxLateReportSeconds: 3600, ReceiptRetentionSeconds: 86400, IssuedAt: now - 1,
		Grants: []usagev2.Grant{{UserID: "7", AccessSubjectID: "8", AuthSnapshotID: "11", TariffRevisionID: "12", TermsID: "13", UsagePeriodID: "14", IssuedAt: now - 1, LeaseExpiresAt: now + 60, RevocationVersion: "0"}}}
	root := t.TempDir()
	spool, err := usagev2.OpenSpool(filepath.Join(root, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	store, err := usageinterval.OpenNativeStore(filepath.Join(root, "native"), session, spool)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	k := New(RuntimeConfig{TrustedProxies: "private", MaxFresh: 64, HandshakeTimeout: time.Second})
	defer k.Stop()
	users := map[string]int{"secret-pass": 7}
	var previous *nativeMeter
	for generation := 1; generation <= 2; generation++ {
		collector, err := store.NewCollector(session, usageinterval.NativeWindow{Revision: strconv.Itoa(generation), Digest: strings.Repeat("a", 64), IssuedAt: now - 1, ExpiresAt: now + 60}, users)
		if err != nil {
			t.Fatal(err)
		}
		if delay := time.Until(collector.ReadyAt()); delay > 0 {
			time.Sleep(delay)
		}
		meter, ok := k.NewNativeMeter(collector, users)
		if !ok || !k.SetNativeUsageTracker(meter) {
			t.Fatalf("generation %d meter installation refused", generation)
		}
		nm := meter.(*nativeMeter)
		if nm == previous {
			t.Fatal("collector generation reused mutable meter")
		}
		if err := k.Start(&model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePortTB(t)}, []model.UserSpec{{ID: 7, UUID: "secret-pass"}}, kernel.TLSCert{}); err != nil {
			t.Fatal(err)
		}
		chunk := core.Chunk{ConnID: uint64(generation), UserID: 7, Dir: core.DirDownload, Path: "conn", N: 64}
		token, err := k.chunkHook().Begin(chunk)
		if err != nil {
			t.Fatal(err)
		}
		meter.StopBoundedUsageTraffic()
		k.Stop()
		if _, err := nm.Begin(chunk); !errors.Is(err, usageinterval.ErrUnknown) {
			t.Fatalf("old generation admitted: %v", err)
		}
		// A token admitted before stop still belongs to its original collector.
		chunk.N = 11
		nm.Complete(chunk, token)
		if err := collector.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		if previous != nil && !previous.collector.Unknown() {
			t.Fatal("previous collector reopened")
		}
		previous = nm
	}
	records, err := spool.Records()
	if err != nil || len(records) != 2 {
		t.Fatalf("generation submissions=%d err=%v", len(records), err)
	}
}
