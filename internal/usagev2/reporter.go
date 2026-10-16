package usagev2

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type Transport interface {
	Submit(context.Context, Submission) (Receipt, error)
	Get(context.Context, Query) (Receipt, bool, error)
}

type Reporter struct {
	session   Session
	spool     *Spool
	transport Transport
	mu        sync.Mutex
	// A failed write retains the same ID in memory until its durability can be
	// retried; accepting fresh counter intervals in that state would risk loss.
	unconfirmed *Record
	cursor      string
	quarantined atomic.Int64
}

func NewReporter(session Session, spool *Spool, transport Transport) (*Reporter, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if spool == nil || transport == nil {
		return nil, errors.New("usage v2 reporter requires durable spool and transport")
	}
	// Do not share mutable grant slices with caller-owned handshake objects.
	b, _ := json.Marshal(session)
	var copySession Session
	if err := json.Unmarshal(b, &copySession); err != nil {
		return nil, err
	}
	records, err := spool.Records()
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.Session.CoreInstanceID != session.CoreInstanceID || record.Submission.Payload.NodeID != session.NodeID {
			return nil, ErrReceiptMismatch
		}
		if record.Session.ReceiptGeneration != session.ReceiptGeneration {
			return nil, ErrRecoveryRequired
		}
		// Old source_epoch remains immutable and is explicitly allowed for
		// historical replay; no current grants are applied to that old batch.
	}
	if err := spool.BindSession(copySession); err != nil {
		return nil, err
	}
	reporter := &Reporter{session: copySession, spool: spool, transport: transport}
	for _, record := range records {
		if nativeQuarantined(record) {
			reporter.quarantined.Add(1)
		}
	}
	return reporter, nil
}

// Capture transfers ownership of already bounded counters to the reporter.
// The returned submission must stay with the collector if validation fails.
// Once a batch ID is returned, persistence failures belong to this reporter:
// retry with RetryPersistence, never roll those bytes into another batch.
func (r *Reporter) Capture(startedAt, endedAt int64, raw map[int][2]int64) (Submission, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unconfirmed != nil {
		return Submission{}, errors.New("usage v2 prior batch durability unconfirmed; stop new collection")
	}
	records, err := r.spool.Records()
	if err != nil {
		return Submission{}, err
	}
	for _, record := range records {
		if startedAt < record.Submission.Payload.EndedAt {
			return Submission{}, errors.New("usage v2 collection interval overlaps a captured interval; refuse duplicate counters or clock rollback")
		}
	}
	submission, err := r.session.Build(startedAt, endedAt, raw)
	if err != nil {
		return Submission{}, err
	}
	record := Record{SchemaVersion: 1, Session: r.session, Submission: submission}
	if err := r.spool.Save(record); err != nil {
		r.unconfirmed = &record
		return submission, err
	}
	return submission, nil
}

func (r *Reporter) RetryPersistence() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unconfirmed == nil {
		return nil
	}
	if err := r.spool.Save(*r.unconfirmed); err != nil {
		return err
	}
	r.unconfirmed = nil
	return nil
}

// Deliver queries before replay, persists receipts before advancing, and never
// deletes payloads. The caller provides bounded timeout/backoff contexts.
func (r *Reporter) Deliver(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unconfirmed != nil {
		return errors.New("usage v2 batch durability unconfirmed; delivery blocked")
	}
	records, err := r.spool.Records()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.LocalQuarantine != nil {
			return ErrRecoveryRequired
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		receipt, found, err := r.transport.Get(ctx, record.Submission.Query())
		if err != nil {
			return err
		}
		if !found {
			if record.Receipt != nil {
				return ErrRecoveryRequired
			}
			receipt, err = r.transport.Submit(ctx, record.Submission)
			if err != nil {
				return err
			}
		}
		if err := receipt.Validate(record.Session, record.Submission); err != nil {
			return err
		}
		record.Receipt = &receipt
		if err := r.spool.Save(record); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reporter) Close() error                  { return r.spool.Close() }
func (r *Reporter) NativeQuarantinedCount() int64 { return r.quarantined.Load() }

// DeliverPage bounds recovery work while advancing through retained records.
// A slow first batch cannot starve newer durable batches on every retry.
func (r *Reporter) DeliverPage(ctx context.Context, limit int) error {
	return r.deliverPage(ctx, limit, false, nil)
}

// DeliverNativePage preserves original authorization evidence and durable Core
// quarantine receipts. Older 422 refusals retain their local marker until a
// query discovers a real receipt; neither capture is rewritten or resubmitted.
func (r *Reporter) DeliverNativePage(ctx context.Context, limit int, refused func(Record)) error {
	return r.deliverPage(ctx, limit, true, refused)
}

func (r *Reporter) deliverPage(ctx context.Context, limit int, native bool, refused func(Record)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit < 1 || limit > 128 || r.unconfirmed != nil {
		return ErrRecoveryRequired
	}
	records, err := r.spool.Records()
	if err != nil {
		return err
	}
	start := 0
	for i, record := range records {
		if recordName(record) == r.cursor {
			start = i + 1
			break
		}
	}
	if start >= len(records) {
		start = 0
	}
	for i := 0; i < len(records) && i < limit; i++ {
		record := records[(start+i)%len(records)]
		if record.LocalQuarantine != nil && !native {
			return ErrRecoveryRequired
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		receipt, found, err := r.transport.Get(ctx, record.Submission.Query())
		if err != nil {
			return err
		}
		if !found {
			if record.Receipt != nil {
				return ErrRecoveryRequired
			}
			if record.LocalQuarantine != nil {
				if refused != nil {
					refused(record)
				}
				r.cursor = recordName(record)
				continue
			}
			receipt, err = r.transport.Submit(ctx, record.Submission)
			if err != nil {
				var response *HTTPError
				if native && errors.As(err, &response) && response.Status == 422 && response.Code == NativeCutoffCode {
					record.LocalQuarantine = &LocalQuarantine{Reason: NativeCutoffCode, HTTPStatus: 422,
						ObservedAt: time.Now().Unix(), CaptureDigest: immutableCaptureDigest(record)}
					if err := r.spool.Save(record); err != nil {
						return err
					}
					r.quarantined.Add(1)
					if refused != nil {
						refused(record)
					}
					r.cursor = recordName(record)
					continue
				}
				return err
			}
		}
		if err := receipt.Validate(record.Session, record.Submission); err != nil {
			return err
		}
		wasQuarantined := nativeQuarantined(record)
		record.Receipt = &receipt
		if err := r.spool.Save(record); err != nil {
			return err
		}
		if quarantined := nativeQuarantined(record); quarantined && !wasQuarantined {
			r.quarantined.Add(1)
		} else if !quarantined && wasQuarantined {
			r.quarantined.Add(-1)
		}
		if native && nativeCutoffReceipt(record.Receipt) && refused != nil {
			refused(record)
		}
		r.cursor = recordName(record)
	}
	return nil
}
