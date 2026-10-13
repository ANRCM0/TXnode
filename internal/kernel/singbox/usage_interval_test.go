package singbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"net"
)

func intervalSession() usagev2.Session {
	now := time.Now().Unix()
	return usagev2.Session{ProtocolVersion: 2, CoreInstanceID: "core-synthetic-tracker", NodeID: "3", SourceEpoch: "1", ReceiptGeneration: "1", RetentionSeconds: 86400, MaxLateReportSeconds: 3600, ReceiptRetentionSeconds: 86400, IssuedAt: now, Grants: []usagev2.Grant{{UserID: "7", AccessSubjectID: "9007199254740993", AuthSnapshotID: "21", TariffRevisionID: "22", TermsID: "23", UsagePeriodID: "24", IssuedAt: now - 2, LeaseExpiresAt: now + 60, RevocationVersion: "0"}}}
}
func boundedTracker(t *testing.T) (*ConnTracker, *usagev2.Spool, *usageinterval.Journal) {
	t.Helper()
	dir := t.TempDir()
	spool, err := usagev2.OpenSpool(filepath.Join(dir, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	session := intervalSession()
	journal, err := usageinterval.OpenJournal(filepath.Join(dir, "interval"), session, spool)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := NewConnTrackerWithBoundedUsage(session, map[string]int{"user": 7}, journal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tracker.CloseBoundedUsage(); journal.Close(); spool.Close() })
	return tracker, spool, journal
}
func sealTCP(t *testing.T, tracker *ConnTracker) *usagev2.Submission {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s, err := tracker.FlushBoundedUsage()
		if err == nil {
			return s
		}
		if err != usageinterval.ErrPending {
			t.Fatal(err)
		}
		timer := time.NewTimer(20 * time.Millisecond)
		<-timer.C
	}
	t.Fatal("bounded TCP interval did not seal")
	return nil
}
func TestBoundedTrackerActualTCPPhysicalDirectionsExtendedWriterAndSpool(t *testing.T) {
	tracker, spool, journal := boundedTracker(t)
	connection, peer := lifecycleTCP(t, tracker, "user")
	done := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("upload-11!!")); done <- err }()
	if _, err := io.ReadFull(connection, make([]byte, 11)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := io.ReadFull(peer, make([]byte, 7)); done <- err }()
	if err := bufio.NewExtendedWriter(connection).WriteBuffer(buf.As([]byte("down-07"))); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertV1(t, tracker, [2]int64{11, 7})
	submission := sealTCP(t, tracker)
	entry := submission.Payload.Entries[0]
	if entry.RawUpBytes != "11" || entry.RawDownBytes != "7" || entry.AccessSubjectID != "9007199254740993" || entry.AuthSnapshotID != "21" || entry.TermsID != "23" || entry.UsagePeriodID != "24" {
		t.Fatal("physical bytes or frozen grant wrong")
	}
	if err := journal.Recover(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Recover(); err != nil {
		t.Fatal(err)
	}
	records, err := spool.Records()
	if err != nil || len(records) != 1 || records[0].Submission.Payload.BatchID != submission.Payload.BatchID || records[0].Receipt != nil {
		t.Fatal("journal replay duplicated batch or invented Core ACK")
	}
	transport := &intervalTransport{session: records[0].Session, lost: true}
	reporter, err := usagev2.NewReporter(records[0].Session, spool, transport)
	if err != nil {
		t.Fatal(err)
	}
	if reporter.Deliver(context.Background()) == nil {
		t.Fatal("simulated persisted-ACK response loss hidden")
	}
	if err := reporter.Deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.submits != 1 || transport.gets != 2 {
		t.Fatal("actual TCP batch replayed without querying receipt")
	}
	if err := journal.Recover(); err != nil {
		t.Fatal(err)
	}
	confirmed, err := spool.Records()
	if err != nil || len(confirmed) != 1 || confirmed[0].Receipt == nil || confirmed[0].Submission.Payload.BatchID != submission.Payload.BatchID {
		t.Fatal("journal discarded original Core receipt")
	}

}
func TestBoundedTrackerPinnedSingCopyAndUnwrapCannotBypassDirectRanges(t *testing.T) {
	for _, direction := range []string{"read", "write", "explicit_unwrap_read", "explicit_unwrap_write"} {
		t.Run(direction, func(t *testing.T) {
			tracker, _, _ := boundedTracker(t)
			connection, peer := lifecycleTCP(t, tracker, "user")
			view := connection.(*boundedTCPView)
			wrapped := view.base
			if view.ReaderReplaceable() || view.WriterReplaceable() || wrapped.Upstream() != nil {
				t.Fatal("raw upstream exposed")
			}
			reader, reads := wrapped.UnwrapReader()
			writer, writes := wrapped.UnwrapWriter()
			if _, bypass := connection.(interface {
				UnwrapReader() (io.Reader, []N.CountFunc)
			}); bypass {
				t.Fatal("counter-bearing view exposed")
			}
			if _, bypass := connection.(interface{ Upstream() any }); bypass {
				t.Fatal("Upstream view exposed")
			}
			if _, bypass := connection.(interface {
				UnwrapWriter() (io.Writer, []N.CountFunc)
			}); bypass {
				t.Fatal("writer counter view exposed")
			}
			if reader.(*boundedTCPView).base != wrapped || writer.(*boundedTCPView).base != wrapped || len(reads) != 0 || len(writes) != 0 {
				t.Fatal("count callback bypass exposed")
			}
			const payload = "asymmetric-13"
			done := make(chan error, 1)
			upload := direction == "read" || direction == "explicit_unwrap_read"
			if upload {
				go func() { _, err := peer.Write([]byte(payload)); peer.Close(); done <- err }()
				var destination bytes.Buffer
				if direction == "read" {
					n, err := bufio.Copy(&destination, connection)
					if err != nil || n != int64(len(payload)) {
						t.Fatal("pinned Copy failed")
					}
				} else {
					if _, err := io.Copy(&destination, reader); err != nil {
						t.Fatal(err)
					}
				}
				if destination.String() != payload {
					t.Fatal("copy changed bytes")
				}
			} else {
				go func() { _, err := io.ReadFull(peer, make([]byte, len(payload))); done <- err }()
				if direction == "write" {
					n, err := bufio.Copy(connection, strings.NewReader(payload))
					if err != nil || n != int64(len(payload)) {
						t.Fatal("pinned Copy failed")
					}
				} else {
					if _, err := io.Copy(writer, strings.NewReader(payload)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			s := sealTCP(t, tracker)
			e := s.Payload.Entries[0]
			if upload {
				if e.RawUpBytes != "13" || e.RawDownBytes != "0" {
					t.Fatal("read copy bypassed range")
				}
			} else {
				if e.RawUpBytes != "0" || e.RawDownBytes != "13" {
					t.Fatal("write copy bypassed range")
				}
			}
		})
	}
}
func TestBoundedTrackerPartialErrorCountsActualBytesWithoutDroppingErrorRange(t *testing.T) {
	tracker, _, _ := boundedTracker(t)
	// The existing deterministic partial-I/O fixture exercises the same actual
	// wrapper; its positive n with EOF/ErrClosedPipe remains known byte evidence.
	connection, peer := lifecycleTCP(t, tracker, "user")
	view := connection.(*boundedTCPView)
	wrapped := view.base
	wrapped.Conn = &errorAfterIO{wrapped.Conn}
	done := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("read-05")); done <- err }()
	n, err := wrapped.Read(make([]byte, 7))
	if n != 7 || err != io.EOF {
		t.Fatal("partial read fixture changed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := io.ReadFull(peer, make([]byte, 2)); done <- err }()
	n, err = wrapped.Write([]byte("write-partial"))
	if n != 2 || err != io.ErrClosedPipe {
		t.Fatal("partial write fixture changed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertV1(t, tracker, [2]int64{7, 2})
	s := sealTCP(t, tracker)
	if s.Payload.Entries[0].RawUpBytes != "7" || s.Payload.Entries[0].RawDownBytes != "2" {
		t.Fatal("partial error lost counters")
	}
}
func TestBoundedTrackerInflightRealTCPMergesAfterDeferredFlush(t *testing.T) {
	tracker, spool, _ := boundedTracker(t)
	connection, peer := lifecycleTCP(t, tracker, "user")
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { close(started); _, err := io.ReadFull(connection, make([]byte, 9)); done <- err }()
	<-started
	// Wait one boundary while a real Read is blocked. No synthetic counter table.
	timer := time.NewTimer(time.Until(time.Unix(time.Now().Unix()+1, 0)) + 20*time.Millisecond)
	<-timer.C
	if s, err := tracker.FlushBoundedUsage(); err != usageinterval.ErrPending || s != nil {
		t.Fatal("in-flight read sealed")
	}
	records, _ := spool.Records()
	if len(records) != 0 {
		t.Fatal("uncompleted bytes spooled")
	}
	if _, err := peer.Write([]byte("merge-009")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s := sealTCP(t, tracker)
	if s.Payload.Entries[0].RawUpBytes != "9" || s.Payload.EndedAt-s.Payload.StartedAt < 2 {
		t.Fatal("cross-boundary I/O lost or split")
	}
}
func TestBoundedTrackerUnknownUDPChangedIdentityAndLateAfterCloseStayV1(t *testing.T) {
	for _, reason := range []string{"udp", "identity", "late", "unknown"} {
		t.Run(reason, func(t *testing.T) {
			tracker, spool, _ := boundedTracker(t)
			connection, _ := lifecycleTCP(t, tracker, "user")
			switch reason {
			case "udp":
				lifecyclePacket(t, tracker, "user")
			case "identity":
				tracker.SetUserMap(map[string]int{"rotated": 7})
			case "late":
				connection.Close()
				_, _ = connection.Read(make([]byte, 1))
			case "unknown":
				lifecycleTCP(t, tracker, "no-grant")
			}
			if s, err := tracker.FlushBoundedUsage(); err != usageinterval.ErrUnknown || s != nil {
				t.Fatal("unknown producer accepted")
			}
			records, _ := spool.Records()
			if len(records) != 0 {
				t.Fatal("unknown traffic became empty successful batch")
			}
		})
	}
	defaultTracker := NewConnTracker(0)
	if defaultTracker.boundedUsage != nil {
		t.Fatal("default collector enabled")
	}
	if _, err := defaultTracker.FlushBoundedUsage(); err != usageinterval.ErrUnknown {
		t.Fatal("default path constructed evidence")
	}
}

type intervalTransport struct {
	session       usagev2.Session
	stored        *usagev2.Receipt
	submits, gets int
	lost          bool
}

func (f *intervalTransport) Get(_ context.Context, q usagev2.Query) (usagev2.Receipt, bool, error) {
	f.gets++
	if f.stored == nil {
		return usagev2.Receipt{}, false, nil
	}
	if f.stored.BatchID != q.BatchID || f.stored.PayloadDigest != q.PayloadDigest {
		return usagev2.Receipt{}, false, usagev2.ErrReceiptMismatch
	}
	return *f.stored, true, nil
}
func (f *intervalTransport) Submit(_ context.Context, s usagev2.Submission) (usagev2.Receipt, error) {
	f.submits++
	r := usagev2.Receipt{ProtocolVersion: 2, CoreInstanceID: f.session.CoreInstanceID, ReceiptGeneration: f.session.ReceiptGeneration, NodeID: s.Payload.NodeID, SourceEpoch: s.Payload.SourceEpoch, BatchID: s.Payload.BatchID, PayloadDigest: s.PayloadDigest, ReceiptStatus: "persisted", SettlementStatus: "pending", AcceptedAt: s.Payload.EndedAt, ReceiptID: "receipt-synthetic-tcp"}
	f.stored = &r
	if f.lost {
		return usagev2.Receipt{}, errors.New("synthetic persisted ACK response loss")
	}
	return r, nil
}

func TestEnforcingBoundedTrackerRefusesActualIOAfterUnknownOrExpiry(t *testing.T) {
	tracker, _, _ := boundedTracker(t)
	if !tracker.EnableEnforcingBounded() {
		t.Fatal("mode enforcement refused before listener")
	}
	conn, peer := lifecycleTCP(t, tracker, "user")
	tracker.StopBoundedUsageTraffic()
	if n, err := conn.Write([]byte("refused-after-unknown")); n != 0 || err == nil {
		t.Fatal("unknown mode performed write")
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("unknown mode performed read")
	}
	peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("unknown mode peer received bytes")
	}
}
func TestSingBoxPreparedUsageTrackerInstalledBeforeFirstStartAndCannotRestart(t *testing.T) {
	dir := t.TempDir()
	spool, err := usagev2.OpenSpool(filepath.Join(dir, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	session := intervalSession()
	journal, err := usageinterval.OpenJournal(filepath.Join(dir, "journal"), session, spool)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	const uuid = "00112233-4455-6677-8899-aabbccddeeff"
	tracker, err := NewConnTrackerWithBoundedUsage(session, map[string]int{uuid: 7}, journal)
	if err != nil {
		t.Fatal(err)
	}
	if !tracker.EnableEnforcingBounded() {
		t.Fatal("enforcement refused")
	}
	runtime := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"})
	if !runtime.SetBoundedUsageTracker(tracker) {
		t.Fatal("prepared tracker attachment refused")
	}
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenPort := port.Addr().(*net.TCPAddr).Port
	port.Close()
	users := []model.UserSpec{{ID: 7, UUID: uuid}}
	spec := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: listenPort}
	if err := runtime.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	if runtime.connTrackerSafe() != tracker || !runtime.trackerRegistered {
		t.Fatal("listener did not own prepared bounded producer")
	}
	if err := runtime.Start(spec, users, kernel.TLSCert{}); err == nil {
		t.Fatal("frozen source allowed full tracker restart")
	}
}
