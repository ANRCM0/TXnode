package usagev2

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type nativeCutoffTransport struct {
	reject   map[string]error
	submits  map[string]int
	receipts map[string]Receipt
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
	t.receipts[id] = receipt
	return receipt, nil
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
	transport.receipts[firstID] = receiptFor(original[0].Submission, "settled")
	if err := restarted.DeliverNativePage(context.Background(), 16, nil); err != nil {
		t.Fatal(err)
	}
	count, err := reopened.QuarantinedCount()
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
