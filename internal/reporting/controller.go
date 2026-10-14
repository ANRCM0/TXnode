package reporting

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/controlplane"
)

// Batch is one immutable report submission prepared by the Service adapter.
// The payload contains the already-flushed runtime counters that may need to be
// restored when an asynchronous delivery fails.
type Batch struct {
	MoreTraffic  bool    `json:"MoreTraffic,omitempty"`
	RecoveryTail []Batch `json:"RecoveryTail,omitempty"`
	Payload      controlplane.ReportPayload
	TrafficCount int
	OnlineCount  int
}

type PrepareFunc func() Batch
type FailureFunc func(Batch, error)
type SuccessFunc func(Batch)

// Controller owns report-delivery mechanics only: overlap prevention, bounded
// retry backoff and asynchronous/synchronous Sink.Report invocation.
//
// Runtime metric collection and tracker flush/restore remain behind Service
// callbacks so this package cannot mutate unrelated data-plane state.
type Controller struct {
	sink controlplane.Sink

	active  atomic.Bool
	backoff backoff

	pendingMu       sync.Mutex
	pending         *Batch
	spool           *batchSpool
	terminal        *Batch
	terminalIndex   int
	terminalSpool   *batchSpool
	admissionClosed bool
	stopped         bool
	checkpointed    bool
}

// Terminal errors are fixed diagnostics; they never include a storage path or payload.
var (
	ErrReportingClosed          = errors.New("REPORTING_ADMISSION_CLOSED")
	ErrTerminalCheckpointExists = errors.New("REPORTING_TERMINAL_CHECKPOINT_EXISTS")
	ErrTerminalCheckpointFailed = errors.New("REPORTING_TERMINAL_CHECKPOINT_FAILED")
	ErrRecoveryFailed           = errors.New("REPORTING_RECOVERY_FAILED")
	ErrRecoveryActive           = errors.New("REPORTING_RECOVERY_ACTIVE")
)

var fallbackNonce atomic.Uint64

func newReportBatchID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	// Only used if OS entropy fails; still distinct across calls/processes.
	return fmt.Sprintf("fallback-%x-%x-%x", time.Now().UnixNano(), os.Getpid(), fallbackNonce.Add(1))
}

// Pending traffic is NOT returned to the tracker after an ambiguous HTTP
// failure. Replaying a byte-identical payload with the same ID is the only
// safe way to distinguish a lost response from a failed commit.
func (c *Controller) nextBatch(prepare PrepareFunc) (Batch, error) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if c.admissionClosed {
		return Batch{}, ErrReportingClosed
	}
	if c.pending != nil {
		return c.checkedSlot(c.pending, c.spool)
	}
	if c.terminal != nil {
		return c.checkedSlot(c.terminal, c.terminalSpool)
	}

	batch := prepare()
	batch.MoreTraffic = false // continuation belongs only to terminal queue capture
	if len(batch.Payload.Traffic) > 0 {
		batch.Payload.BatchID = newReportBatchID()
		if c.spool != nil {
			if err := c.spool.save(batch); err != nil {
				// Nothing was delivered. Return untagged traffic so the
				// adapter can restore it for a later safe retry.
				batch.Payload.BatchID = ""
				return batch, fmt.Errorf("persist traffic batch: %w", err)
			}
		}
		snapshot := batch
		c.pending = &snapshot
	}
	return batch, nil
}

func (c *Controller) acknowledge(batch Batch) error {
	if batch.Payload.BatchID == "" {
		return nil
	}
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if c.pending != nil && c.pending.Payload.BatchID == batch.Payload.BatchID {
		// A failed unlink leaves the same batch available for replay.
		if c.spool != nil {
			if err := c.spool.clear(batch); err != nil {
				return fmt.Errorf("clear acknowledged batch: %w", err)
			}
		}
		c.pending = nil
	} else if c.terminal != nil {
		current := c.terminalItemLocked()
		if current.Payload.BatchID != batch.Payload.BatchID {
			return nil
		} // stale unrelated ACK owns neither slot
		if c.terminalIndex < len(c.terminal.RecoveryTail) {
			c.terminalIndex++
			return nil
		}
		if c.terminalSpool != nil {
			if err := c.terminalSpool.clear(*c.terminal); err != nil {
				return ErrRecoveryFailed
			}
		}
		c.terminal = nil
		c.terminalIndex = 0
	}
	return nil
}

// checkedSlot rejects missing or changed files before any HTTP delivery.
// pendingMu is held by the caller.
func (c *Controller) checkedSlot(batch *Batch, spool *batchSpool) (Batch, error) {
	if spool != nil {
		if err := spool.matches(*batch); err != nil {
			return Batch{}, ErrRecoveryFailed
		}
	}
	return *batch, nil
}

func New(sink controlplane.Sink) *Controller {
	return &Controller{sink: sink}
}

// NewDurable fails closed if the pending batch cannot be loaded or the
// configured directory cannot be written. Callers must surface the error
// rather than silently reverting to memory-only acknowledgements.
func NewDurable(sink controlplane.Sink, path string) (*Controller, error) {
	spool, pending, err := openBatchSpool(path)
	if err != nil {
		return nil, err
	}
	terminalSpool, terminal, err := openBatchSpool(path + ".terminal.json")
	if err != nil {
		return nil, ErrRecoveryFailed
	}
	if pending != nil && len(pending.RecoveryTail) > 0 {
		return nil, ErrRecoveryFailed
	}
	if pending != nil && terminal != nil {
		for _, batch := range terminalBatches(*terminal) {
			if pending.Payload.BatchID == batch.Payload.BatchID {
				return nil, ErrRecoveryFailed
			}
		}
	}
	return &Controller{sink: sink, spool: spool, pending: pending,
		terminalSpool: terminalSpool, terminal: terminal,
		admissionClosed: terminal != nil}, nil
}

func (c *Controller) SupportsReporting() bool {
	return c != nil && c.sink != nil && c.sink.SupportsReporting()
}

// PushAsync starts one report if reporting is supported, no previous report is
// active and retry backoff permits the attempt. Prepare is invoked only after
// those checks, preserving the old rule that skipped reports do not flush
// tracker state.
func (c *Controller) PushAsync(
	prepare PrepareFunc,
	onFailure FailureFunc,
	onSuccess SuccessFunc,
) bool {
	if !c.SupportsReporting() || prepare == nil {
		return false
	}
	c.pendingMu.Lock()
	if c.admissionClosed || !c.active.CompareAndSwap(false, true) {
		c.pendingMu.Unlock()
		return false
	}
	c.pendingMu.Unlock()
	if c.backoff.shouldSkip() {
		c.active.Store(false)
		return false
	}

	batch, err := c.nextBatch(prepare)
	if err != nil {
		c.backoff.onFailure()
		c.active.Store(false)
		if onFailure != nil {
			onFailure(batch, err)
		}
		return false
	}
	go func() {
		defer c.active.Store(false)

		if err := c.sink.Report(batch.Payload); err != nil {
			c.backoff.onFailure()
			if onFailure != nil {
				// The controller retains these counters for a stable replay.
				// Only transient alive IP snapshots may return to the tracker.
				failureNotice := batch
				if batch.Payload.BatchID != "" {
					failureNotice.Payload.Traffic = nil
					failureNotice.Payload.TrafficSegments = nil
				}
				onFailure(failureNotice, err)
			}
			return
		}

		if err := c.acknowledge(batch); err != nil {
			c.backoff.onFailure()
			if onFailure != nil {
				failureNotice := batch
				failureNotice.Payload.Traffic = nil
				failureNotice.Payload.TrafficSegments = nil
				onFailure(failureNotice, err)
			}
			return
		}
		c.backoff.onSuccess()
		if onSuccess != nil {
			onSuccess(batch)
		}
	}()
	return true
}

// PushSync is used for the shutdown flush. It intentionally bypasses async
// overlap/backoff state, matching the previous Service behavior.
func (c *Controller) PushSync(prepare PrepareFunc) error { return c.PushSyncRecoverable(prepare, nil) }

// Only a never-published (untagged) batch is returned for restoration. Stable
// pending/ambiguous batches stay in their slot and retain original attribution.
func (c *Controller) PushSyncRecoverable(prepare PrepareFunc, onFailure FailureFunc) error {
	if !c.SupportsReporting() || prepare == nil {
		return nil
	}
	// On shutdown, attempt the ambiguous in-flight batch first and only
	// then flush new counters; do not roll them into the old batch identity.
	c.pendingMu.Lock()
	if c.admissionClosed {
		c.pendingMu.Unlock()
		return ErrReportingClosed
	}
	hadPending := c.pending != nil || c.terminal != nil
	c.pendingMu.Unlock()
	batch, err := c.nextBatch(prepare)
	if err != nil {
		if onFailure != nil && batch.Payload.BatchID == "" {
			onFailure(batch, err)
		}
		return err
	}
	if err := c.sink.Report(batch.Payload); err != nil {
		return err
	}
	if err := c.acknowledge(batch); err != nil {
		return err
	}
	if hadPending {
		next, err := c.nextBatch(prepare)
		if err != nil {
			if onFailure != nil && next.Payload.BatchID == "" {
				onFailure(next, err)
			}
			return err
		}
		if err := c.sink.Report(next.Payload); err != nil {
			return err
		}
		if err := c.acknowledge(next); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) Active() bool {
	return c != nil && c.active.Load()
}

type backoff struct {
	mu            sync.Mutex
	skipRemaining int
}

func (b *backoff) shouldSkip() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.skipRemaining > 0 {
		b.skipRemaining--
		return true
	}
	return false
}

func (b *backoff) onSuccess() {
	b.mu.Lock()
	b.skipRemaining = 0
	b.mu.Unlock()
}

func (b *backoff) onFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.skipRemaining <= 0 {
		b.skipRemaining = 1
	} else if b.skipRemaining < 8 {
		b.skipRemaining *= 2
	}
}

// EmptyForUsageHandoff is sampled before any reporting/listener worker starts.
// It never drains or acknowledges an uncertain batch.
func (c *Controller) EmptyForUsageHandoff() bool {
	if c == nil || c.active.Load() {
		return false
	}
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	return c.pending == nil && c.terminal == nil && !c.admissionClosed && !c.active.Load()
}

// CheckpointTerminal closes new report admission before preparing final counters.
// It never sends HTTP, never overwrites pending, and reserves at most one tail.
// Even a failed/empty checkpoint permanently closes this controller instance.
func (c *Controller) CheckpointTerminal(prepare PrepareFunc, onFailure FailureFunc) error {
	if c == nil {
		return ErrTerminalCheckpointFailed
	}
	c.pendingMu.Lock()
	c.admissionClosed = true
	c.stopped = true
	if c.checkpointed || c.terminal != nil {
		c.pendingMu.Unlock()
		return ErrTerminalCheckpointExists
	}
	c.checkpointed = true
	if c.terminalSpool != nil {
		if _, err := os.Lstat(c.terminalSpool.path); !errors.Is(err, os.ErrNotExist) {
			c.pendingMu.Unlock()
			return ErrTerminalCheckpointExists
		}
	}
	if prepare == nil {
		c.pendingMu.Unlock()
		return ErrTerminalCheckpointFailed
	}
	c.pendingMu.Unlock() // closed admission is visible before prepare; never call it under the spool mutex
	var batches []Batch
	restore := func() {
		for _, batch := range batches {
			batch.Payload.BatchID = ""
			if onFailure != nil {
				onFailure(batch, ErrTerminalCheckpointFailed)
			}
		}
	}
	for {
		batch := prepare()
		more := batch.MoreTraffic
		batch.MoreTraffic = false
		if len(batch.Payload.Traffic) == 0 {
			if more {
				restore()
				return ErrTerminalCheckpointFailed
			}
			break
		}
		batch.Payload.BatchID = newReportBatchID()
		batch.RecoveryTail = nil
		batches = append(batches, batch)
		if !more {
			break
		}
		if len(batches) >= 4096 {
			restore()
			return ErrTerminalCheckpointFailed
		}
	}
	if len(batches) == 0 {
		return nil
	}
	root := batches[0]
	if len(batches) > 1 {
		root.RecoveryTail = append([]Batch(nil), batches[1:]...)
	}
	if c.terminalSpool != nil {
		if err := c.terminalSpool.save(root); err != nil {
			restore()
			return ErrTerminalCheckpointFailed
		}
	}
	c.pendingMu.Lock()
	c.terminal = &root
	c.terminalIndex = 0
	c.pendingMu.Unlock()
	return nil
}
func terminalBatches(root Batch) []Batch {
	first := root
	first.RecoveryTail = nil
	all := []Batch{first}
	return append(all, root.RecoveryTail...)
}
func (c *Controller) terminalItemLocked() Batch {
	if c.terminalIndex == 0 {
		batch := *c.terminal
		batch.RecoveryTail = nil
		return batch
	}
	return c.terminal.RecoveryTail[c.terminalIndex-1]
}

// HasTerminalTail never interprets a removed/corrupt on-disk tail as empty.
func (c *Controller) HasTerminalTail() bool {
	if c == nil {
		return false
	}
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	return c.terminal != nil
}

// ReplayRecovery only drains already-prepared immutable slots, in FIFO order.
// The caller must obtain fresh authority before invoking it and must not open
// any listener until it succeeds. No fresh metric collection occurs here.
func (c *Controller) ReplayRecovery() error {
	if !c.SupportsReporting() {
		return ErrRecoveryFailed
	}
	c.pendingMu.Lock()
	if !c.active.CompareAndSwap(false, true) {
		c.pendingMu.Unlock()
		return ErrRecoveryActive
	}
	c.pendingMu.Unlock()
	defer c.active.Store(false)
	for {
		c.pendingMu.Lock()
		var slot *Batch
		var spool *batchSpool
		if c.pending != nil {
			slot, spool = c.pending, c.spool
		} else if c.terminal != nil {
			slot, spool = c.terminal, c.terminalSpool
		}
		if slot == nil {
			if !c.stopped {
				c.admissionClosed = false
			}
			c.pendingMu.Unlock()
			return nil
		}
		batch, err := c.checkedSlot(slot, spool)
		if slot == c.terminal && err == nil {
			batch = c.terminalItemLocked()
		}
		c.pendingMu.Unlock()
		if err != nil {
			return ErrRecoveryFailed
		}
		if err := c.sink.Report(batch.Payload); err != nil {
			return ErrRecoveryFailed
		}
		if err := c.acknowledge(batch); err != nil {
			return ErrRecoveryFailed
		}
	}
}

// HasRecoveryBatch includes pending-only startup; neither immutable slot may be
// bypassed by newly admitted native traffic after an authenticated restart.
func (c *Controller) HasRecoveryBatch() bool {
	if c == nil {
		return false
	}
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	return c.pending != nil || c.terminal != nil
}
