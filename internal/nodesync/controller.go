package nodesync

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nlog"
)

// Result is an immutable polling snapshot prepared by Controller for the
// Service orchestration layer to validate/apply on its main goroutine.
type Result struct {
	Config      *model.NodeSpec
	Users       []model.UserSpec
	ConfigHash  string
	UserHash    string
	CertChanged bool
}

// Controller owns asynchronous polling concerns that do not belong in the
// top-level Service orchestrator: overlap prevention, retry backoff, resync
// deduplication, snapshot hashing and delivery back to the main goroutine.
//
// It deliberately does not apply node config/users or touch kernel/cert state.
type Controller struct {
	source controlplane.Source

	pullActive    atomic.Bool
	resyncPending atomic.Bool
	backoff       backoff
	results       chan Result
}

func New(source controlplane.Source) *Controller {
	return &Controller{
		source:  source,
		results: make(chan Result, 1),
	}
}

func (c *Controller) Results() <-chan Result {
	if c == nil {
		return nil
	}
	return c.results
}

// Poll schedules one asynchronous ControlPlane poll if polling is supported,
// no other pull is in flight and the bounded retry backoff allows it.
//
// currentConfigHash and certChanged are runtime facts supplied by Service.
// Controller may use them only to avoid returning an unchanged config.
func (c *Controller) Poll(ctx context.Context, currentConfigHash string, certChanged bool) bool {
	if c == nil || c.source == nil || !c.source.SupportsPolling() {
		return false
	}
	if !c.pullActive.CompareAndSwap(false, true) {
		nlog.Core().Debug("pull already in progress, skipping")
		return false
	}
	if c.backoff.shouldSkip() {
		nlog.Core().Debug("skipping pull due to backoff")
		c.pullActive.Store(false)
		return false
	}

	go func() {
		snapshot, err := c.source.Poll(ctx)
		if err != nil {
			nlog.Core().Error("poll control plane failed", "error", err)
			c.backoff.onFailure()
			c.pullActive.Store(false)
			return
		}
		c.backoff.onSuccess()

		result := Result{CertChanged: certChanged}
		if snapshot.Config != nil {
			result.Config = snapshot.Config
			result.ConfigHash = ConfigHash(snapshot.Config)
			if result.ConfigHash == currentConfigHash && !certChanged {
				result.Config = nil
			}
		}
		if snapshot.Users != nil {
			result.Users = make([]model.UserSpec, len(snapshot.Users))
			copy(result.Users, snapshot.Users)
			result.UserHash = UserHash(snapshot.Users)
		}

		// Mark the poll complete before publishing the buffered result. This
		// guarantees that a consumer receiving the result can immediately
		// schedule the next poll instead of racing the goroutine's deferred
		// cleanup and then waiting forever for a result that was never started.
		c.pullActive.Store(false)
		select {
		case c.results <- result:
		case <-ctx.Done():
		}
	}()

	return true
}

// RequestResync coalesces repeated resync signals until Service confirms that
// a poll result has been applied. This preserves the existing behavior while
// keeping resync concurrency state out of Service.
func (c *Controller) RequestResync(
	ctx context.Context,
	currentConfigHash string,
	certChanged bool,
) bool {
	if c == nil {
		return false
	}
	if !c.resyncPending.CompareAndSwap(false, true) {
		return false
	}
	if !c.Poll(ctx, currentConfigHash, certChanged) {
		c.resyncPending.Store(false)
		return false
	}
	return true
}

func (c *Controller) CompleteResync() {
	if c != nil {
		c.resyncPending.Store(false)
	}
}

// ConfigHash returns a deterministic hash of the complete NodeSpec.
func ConfigHash(cfg *model.NodeSpec) string {
	if cfg == nil {
		return ""
	}
	h := sha256.New()
	data, _ := json.Marshal(cfg)
	_, _ = h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// UserHash returns a deterministic hash of the runtime-relevant user fields.
func UserHash(users []model.UserSpec) string {
	sorted := append([]model.UserSpec(nil), users...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	h := sha256.New()
	var buf [8]byte
	for _, user := range sorted {
		binary.LittleEndian.PutUint64(buf[:], uint64(user.ID))
		_, _ = h.Write(buf[:])
		_, _ = io.WriteString(h, user.UUID)
		binary.LittleEndian.PutUint64(buf[:], uint64(user.SpeedLimit))
		_, _ = h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(user.DeviceLimit))
		_, _ = h.Write(buf[:])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
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
