package usagev2

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type nativeCutoffTransport struct {
	reject   map[string]error
	submits  map[string]int
	receipts map[string]Receipt
	reply    *Receipt
}

func (t *nativeCutoffTransport) Get(_ context.Context, query Query) (Receipt, bool, error) {
	receipt, exists := t.receipts[query.BatchID]
	return receipt, exists, nil
}
func (t *nativeCutoffTransport) Submit(_ context.Context, submission Submission) (Receipt, error) {
	id := submission.Payload.BatchID
	t.submits[id]++
	if err := t.reject[id]; err != nil {
		return Receipt{}, err
	}
	receipt := receiptFor(submission, "pending")
	if t.reply != nil {
		receipt = *t.reply
	}
	t.receipts[id] = receipt
	return receipt, nil
}

func TestNativePersistedCutoffReceiptIsDurableBeforeRefusalAndSurvivesRestart(t *testing.T) {
	for _, queried := range []bool{false, true} {
		name := "submit"
		if queried {
			name = "query"
		}
		t.Run(name, func(t *testing.T) {
			spool := linuxSpool(t)
			s := session()
			submission, err := s.Build(s.IssuedAt, s.IssuedAt+1, map[int][2]int64{7: {13, 17}})
			if err != nil {
				t.Fatal(err)
			}
			original := Record{SchemaVersion: 1, Session: s, Submission: submission}
			if err := spool.Save(original); err != nil {
				t.Fatal(err)
			}
			receipt := receiptFor(submission, "quarantined")
			receipt.ReasonCode = NativeCutoffCode
			transport := &nativeCutoffTransport{
				submits: map[string]int{}, receipts: map[string]Receipt{}, reply: &receipt,
			}
			if queried {
				transport.receipts[submission.Payload.BatchID] = receipt
			}
			reporter, err := NewReporter(s, spool, transport)
			if err != nil {
				t.Fatal(err)
			}
			refusals := 0
			refused := func(record Record) {
				refusals++
				durable, err := spool.Records()
				if err != nil || len(durable) != 1 || durable[0].Receipt == nil ||
					*durable[0].Receipt != receipt || record.Receipt == nil || *record.Receipt != receipt ||
					record.LocalQuarantine != nil || durable[0].LocalQuarantine != nil ||
					immutableCaptureDigest(record) != immutableCaptureDigest(original) {
					t.Fatal("cutoff callback preceded durable Core receipt or changed original capture", err)
				}
			}
			if err := reporter.DeliverNativePage(context.Background(), 16, refused); err != nil {
				t.Fatal(err)
			}
			count, err := spool.QuarantinedCount()
			if err != nil || count != 1 || reporter.NativeQuarantinedCount() != 1 || refusals != 1 {
				t.Fatal("real cutoff receipt was not counted once", err)
			}
			wantSubmits := 1
			if queried {
				wantSubmits = 0
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenSpool(spool.dir, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restarted, err := NewReporter(s, reopened, transport)
			if err != nil || restarted.NativeQuarantinedCount() != 1 {
				t.Fatal("restart forgot persisted cutoff quarantine", err)
			}
			if err := restarted.DeliverNativePage(context.Background(), 16, nil); err != nil {
				t.Fatal(err)
			}
			if transport.submits[submission.Payload.BatchID] != wantSubmits {
				t.Fatal("persisted quarantined batch was posted again")
			}
			transport.receipts[submission.Payload.BatchID] = receiptFor(submission, "settled")
			if err := restarted.DeliverNativePage(context.Background(), 16, nil); err != nil {
				t.Fatal(err)
			}
			if count, err := reopened.QuarantinedCount(); err != nil || count != 0 ||
				restarted.NativeQuarantinedCount() != 0 {
				t.Fatal("settled receipt retained quarantine count", err)
			}
		})
	}
}

func TestNativePersistedCutoffRequiresValidDurableReceiptBeforeRefusal(t *testing.T) {
	for _, failure := range []string{"invalid receipt", "durability failure", "other quarantine", "pending cutoff"} {
		t.Run(failure, func(t *testing.T) {
			spool := linuxSpool(t)
			s := session()
			submission, err := s.Build(s.IssuedAt, s.IssuedAt+1, map[int][2]int64{7: {13, 17}})
			if err != nil {
				t.Fatal(err)
			}
			if err := spool.Save(Record{SchemaVersion: 1, Session: s, Submission: submission}); err != nil {
				t.Fatal(err)
			}
			receipt := receiptFor(submission, "quarantined")
			receipt.ReasonCode = NativeCutoffCode
			switch failure {
			case "invalid receipt":
				receipt.PayloadDigest = "sha256:broken"
			case "other quarantine":
				receipt.ReasonCode = "USAGE_GRANT_OWNERSHIP_OR_COVERAGE"
			case "pending cutoff":
				receipt.SettlementStatus = "pending"
			}
			transport := &nativeCutoffTransport{
				submits: map[string]int{}, receipts: map[string]Receipt{}, reply: &receipt,
			}
			reporter, err := NewReporter(s, spool, transport)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "durability failure" {
				spool.syncFile = func(*os.File) error { return errors.New("synthetic receipt fsync failure") }
			}
			refusals := 0
			err = reporter.DeliverNativePage(context.Background(), 16, func(Record) { refusals++ })
			wantError := failure == "invalid receipt" || failure == "durability failure"
			if (err != nil) != wantError || refusals != 0 || reporter.NativeQuarantinedCount() != 0 {
				t.Fatal("unconfirmed or unrelated receipt stopped current admission", err)
			}
			records, err := spool.Records()
			if err != nil || len(records) != 1 || records[0].LocalQuarantine != nil ||
				(wantError && records[0].Receipt != nil) {
				t.Fatal("failed receipt fabricated durable cutoff evidence", err)
			}
		})
	}
}

func TestNativeCutoffQuarantinePreservesOriginalEvidenceAndDoesNotStarveNewGrant(t *testing.T) {
	spool := linuxSpool(t)
	originalSession := session()
	var original []Record
	for i := 0; i < 2; i++ {
		submission, err := originalSession.Build(originalSession.IssuedAt+int64(i), originalSession.IssuedAt+int64(i)+1,
			map[int][2]int64{7: {13, 17}})
		if err != nil {
			t.Fatal(err)
		}
		record := Record{SchemaVersion: 1, Session: originalSession, Submission: submission}
		original = append(original, record)
		if err := spool.Save(record); err != nil {
			t.Fatal(err)
		}
	}
	firstID := original[0].Submission.Payload.BatchID
	transport := &nativeCutoffTransport{
		reject:  map[string]error{firstID: &HTTPError{Status: 422, Code: NativeCutoffCode}},
		submits: map[string]int{}, receipts: map[string]Receipt{},
	}
	reporter, err := NewReporter(originalSession, spool, transport)
	if err != nil {
		t.Fatal(err)
	}
	refusals := 0
	if err := reporter.DeliverNativePage(context.Background(), 16, func(record Record) {
		refusals++
		if record.LocalQuarantine == nil || record.Receipt != nil {
			t.Fatal("local rejection became a Core receipt")
		}
	}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.Records()
	if err != nil || len(records) != 2 || refusals != 1 ||
		records[0].LocalQuarantine == nil || records[0].Receipt != nil || records[1].Receipt == nil {
		t.Fatal("cutoff stopped independent evidence or fabricated receipt", err)
	}
	before, _ := json.Marshal(original[0])
	recovered := records[0]
	recovered.LocalQuarantine = nil
	after, _ := json.Marshal(recovered)
	if string(before) != string(after) {
		t.Fatal("cutoff rewrote original Session or payload")
	}
	bad := records[0]
	marker := *bad.LocalQuarantine
	bad.LocalQuarantine = &marker
	bad.LocalQuarantine.CaptureDigest = "sha256:broken"
	if bad.Validate() == nil || spool.Save(bad) == nil {
		t.Fatal("corrupt quarantine suppressed delivery")
	}
	missing := records[0]
	missing.LocalQuarantine = nil
	if spool.Save(missing) == nil {
		t.Fatal("quarantine could be silently removed")
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSpool(spool.dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := NewReporter(originalSession, reopened, transport)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.DeliverNativePage(context.Background(), 16, nil); err != nil {
		t.Fatal(err)
	}
	if transport.submits[firstID] != 1 {
		t.Fatal("restart automatically resubmitted quarantined bytes")
	}
	if err := restarted.DeliverPage(context.Background(), 16); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatal("legacy reporter accepted native quarantine", err)
	}
	persisted := receiptFor(original[0].Submission, "quarantined")
	persisted.ReasonCode = NativeCutoffCode
	transport.receipts[firstID] = persisted
	if err := restarted.DeliverNativePage(context.Background(), 16, nil); err != nil {
		t.Fatal(err)
	}
	confirmed, err := reopened.Records()
	count, countErr := reopened.QuarantinedCount()
	if err != nil || countErr != nil || count != 1 || restarted.NativeQuarantinedCount() != 1 ||
		confirmed[0].LocalQuarantine == nil || confirmed[0].Receipt == nil {
		t.Fatal("real quarantine receipt lost local history or double-counted its capture", err, countErr)
	}
	transport.receipts[firstID] = receiptFor(original[0].Submission, "settled")
	if err := restarted.DeliverNativePage(context.Background(), 16, nil); err != nil {
		t.Fatal(err)
	}
	count, err = reopened.QuarantinedCount()
	if err != nil || count != 0 {
		t.Fatal("real recovered receipt was not recognized", err)
	}
}

func TestNativeQuarantineOnlyAcceptsExactAuthenticatedCutoffResponse(t *testing.T) {
	for _, failure := range []*HTTPError{
		{Status: 422, Code: "USAGE_GRANT_OWNERSHIP_OR_COVERAGE"},
		{Status: 403, Code: NativeCutoffCode},
		{Status: 403, Code: "USAGE_NODE_SCOPE"},
		{Status: 409, Code: "BATCH_PAYLOAD_CONFLICT"},
		{Status: 422, Code: "USAGE_SOURCE_UNKNOWN"},
	} {
		t.Run(failure.Code, func(t *testing.T) {
			spool := linuxSpool(t)
			s := session()
			submission, err := s.Build(s.IssuedAt, s.IssuedAt+1, map[int][2]int64{7: {1, 2}})
			if err != nil {
				t.Fatal(err)
			}
			if err := spool.Save(Record{SchemaVersion: 1, Session: s, Submission: submission}); err != nil {
				t.Fatal(err)
			}
			transport := &nativeCutoffTransport{reject: map[string]error{submission.Payload.BatchID: failure},
				submits: map[string]int{}, receipts: map[string]Receipt{}}
			reporter, err := NewReporter(s, spool, transport)
			if err != nil {
				t.Fatal(err)
			}
			if err := reporter.DeliverNativePage(context.Background(), 16, nil); err == nil {
				t.Fatal("non-cutoff error was ignored")
			}
			records, _ := spool.Records()
			if len(records) != 1 || records[0].Receipt != nil || records[0].LocalQuarantine != nil {
				t.Fatal("non-cutoff error created quarantine or receipt")
			}
		})
	}
}
