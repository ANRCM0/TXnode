package usagev2

import (
	"context"
	"errors"
	"testing"
)

func TestNativeRetentionRequiresSettlementAndBothRecoveryWindows(t *testing.T) {
	spool := linuxSpool(t)
	s := session()
	s.RetentionSeconds, s.MaxLateReportSeconds, s.ReceiptRetentionSeconds = 100, 50, 200
	record := Record{SchemaVersion: 1, Session: s}
	var err error
	record.Submission, err = s.Build(s.IssuedAt, s.IssuedAt+1, map[int][2]int64{7: {3, 5}})
	if err != nil {
		t.Fatal(err)
	}
	pending := receiptFor(record.Submission, "pending")
	record.Receipt = &pending
	if err := spool.Save(record); err != nil {
		t.Fatal(err)
	}
	if err := spool.PruneSettled(pending.AcceptedAt + 100000); err != nil {
		t.Fatal(err)
	}
	records, _ := spool.Records()
	if len(records) != 1 {
		t.Fatal("pending receipt was treated as settlement")
	}
	settled := receiptFor(record.Submission, "settled")
	record.Receipt = &settled
	if err := spool.Save(record); err != nil {
		t.Fatal(err)
	}
	before := settled.AcceptedAt + s.ReceiptRetentionSeconds - 1
	if err := spool.PruneSettled(before); err != nil {
		t.Fatal(err)
	}
	records, _ = spool.Records()
	if len(records) != 1 {
		t.Fatal("settled payload disappeared inside recovery retention")
	}
	at := settled.AcceptedAt + s.ReceiptRetentionSeconds
	if at < record.Submission.Payload.EndedAt+s.RetentionSeconds {
		at = record.Submission.Payload.EndedAt + s.RetentionSeconds
	}
	if err := spool.PruneSettled(at); err != nil {
		t.Fatal(err)
	}
	records, _ = spool.Records()
	if len(records) != 0 {
		t.Fatal("fully retained settled record was never reclaimed")
	}
	capture := record
	capture.Receipt = nil
	confirmed, err := spool.ConfirmCapture(capture)
	if err != nil || !confirmed {
		t.Fatal("durable settled tombstone did not protect producer replay", err)
	}
}

type pagedTransport struct {
	session  Session
	gets     map[string]int
	receipts map[string]Receipt
}

func (p *pagedTransport) Get(_ context.Context, q Query) (Receipt, bool, error) {
	p.gets[q.BatchID]++
	receipt, found := p.receipts[q.BatchID]
	return receipt, found, nil
}
func (p *pagedTransport) Submit(_ context.Context, s Submission) (Receipt, error) {
	receipt := receiptFor(s, "pending")
	p.receipts[s.Payload.BatchID] = receipt
	return receipt, nil
}
func TestNativeReporterPagesRetainedBatchesWithoutChangingIdentity(t *testing.T) {
	spool := linuxSpool(t)
	s := session()
	transport := &pagedTransport{session: s, gets: map[string]int{}, receipts: map[string]Receipt{}}
	reporter, err := NewReporter(s, spool, transport)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		submission, err := s.Build(s.IssuedAt+int64(i), s.IssuedAt+1+int64(i), map[int][2]int64{7: {1, 2}})
		if err != nil {
			t.Fatal(err)
		}
		if err := spool.Save(Record{SchemaVersion: 1, Session: s, Submission: submission}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := reporter.DeliverPage(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
	}
	if len(transport.receipts) != 3 || len(transport.gets) != 3 {
		t.Fatal("first pending batch starved later durable batches")
	}
	records, _ := spool.Records()
	for _, record := range records {
		if record.Receipt == nil || record.Receipt.PayloadDigest != record.Submission.PayloadDigest {
			t.Fatal("receipt mismatch")
		}
	}
	delete(transport.receipts, records[0].Submission.Payload.BatchID)
	if err := reporter.DeliverPage(context.Background(), 3); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatal("confirmed receipt loss became a fresh submit", err)
	}
}
