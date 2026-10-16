package service

import (
	"context"
	"errors"
	"sync"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

type modeTransport struct {
	mu           sync.Mutex
	session      usagev2.Session
	receipts     map[string]usagev2.Receipt
	submissions  []usagev2.Submission
	err          bool
	blockEntered chan struct{}
	blockRelease chan struct{}
	blockOnce    sync.Once
}

func (f *modeTransport) Get(ctx context.Context, q usagev2.Query) (usagev2.Receipt, bool, error) {
	f.mu.Lock()
	fault, entered, release := f.err, f.blockEntered, f.blockRelease
	r, ok := f.receipts[q.BatchID]
	f.mu.Unlock()
	if entered != nil {
		f.blockOnce.Do(func() { close(entered) })
		<-release
	}
	if ctx.Err() != nil {
		return usagev2.Receipt{}, false, ctx.Err()
	}
	if fault {
		return usagev2.Receipt{}, false, errors.New("synthetic transport failure")
	}
	return r, ok, nil
}
func (f *modeTransport) Submit(_ context.Context, s usagev2.Submission) (usagev2.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := usagev2.Receipt{ProtocolVersion: 2, CoreInstanceID: f.session.CoreInstanceID, ReceiptGeneration: f.session.ReceiptGeneration, NodeID: s.Payload.NodeID, SourceEpoch: s.Payload.SourceEpoch, BatchID: s.Payload.BatchID, PayloadDigest: s.PayloadDigest, ReceiptStatus: "persisted", SettlementStatus: "pending", AcceptedAt: s.Payload.EndedAt, ReceiptID: "service-synthetic-receipt"}
	f.receipts[s.Payload.BatchID] = r
	f.submissions = append(f.submissions, s)
	return r, nil
}
func (f *modeTransport) snapshot() []usagev2.Submission {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]usagev2.Submission{}, f.submissions...)
}
