package pushsync

import (
	"context"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/controlplane"
)

type Transition string

const (
	TransitionNone     Transition = "none"
	TransitionEnabled  Transition = "enabled"
	TransitionDisabled Transition = "disabled"
)

type DiscoveryResult struct {
	Checked    bool
	NeedsPoll  bool
	Transition Transition
}

type StatusObservation struct {
	Connected   bool
	NeedsResync bool
}

// Controller owns push transport lifecycle state for one node Service.
//
// It intentionally does not apply ControlPlane events, mutate node/kernel state,
// or trigger REST polling itself. Those remain Service orchestration concerns.
type Controller struct {
	source controlplane.Source

	events   chan controlplane.Event
	statuses chan controlplane.StatusChange

	mu             sync.RWMutex
	client         controlplane.PushClient
	cancel         context.CancelFunc
	done           chan struct{}
	disconnectedAt time.Time
}

func New(source controlplane.Source) *Controller {
	return &Controller{
		source:   source,
		events:   make(chan controlplane.Event, 16),
		statuses: make(chan controlplane.StatusChange, 4),
	}
}

func (c *Controller) EventSink() chan<- controlplane.Event {
	if c == nil {
		return nil
	}
	return c.events
}

func (c *Controller) Events() <-chan controlplane.Event {
	if c == nil {
		return nil
	}
	return c.events
}

func (c *Controller) StatusSink() chan<- controlplane.StatusChange {
	if c == nil {
		return nil
	}
	return c.statuses
}

func (c *Controller) Statuses() <-chan controlplane.StatusChange {
	if c == nil {
		return nil
	}
	return c.statuses
}

// SetBootstrapClient installs the PushClient returned by Source.Initial.
// The caller starts it after bootstrap/runtime setup is complete.
func (c *Controller) SetBootstrapClient(client controlplane.PushClient) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.client = client
	c.disconnectedAt = time.Time{}
	c.mu.Unlock()
}

// Start launches the currently installed client once.
func (c *Controller) Start(ctx context.Context) bool {
	if c == nil {
		return false
	}

	c.mu.Lock()
	if c.client == nil || c.cancel != nil {
		c.mu.Unlock()
		return false
	}
	client := c.client
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	done := make(chan struct{})
	c.done = done
	c.mu.Unlock()

	go func() { defer close(done); client.Run(runCtx) }()
	return true
}

// Stop stops only the node-level PushClient lifecycle owned by this controller.
// Shared machine WebSocket ownership remains with the machine orchestrator; its
// virtual PushClient simply exits when this derived context is cancelled.
func (c *Controller) Stop() {
	if c == nil {
		return
	}

	c.mu.Lock()
	cancel := c.cancel
	done := c.done
	c.cancel = nil
	c.done = nil
	c.mu.Unlock()

	if cancel != nil {
		cancel()
		if done != nil {
			<-done
		}
	}
}

func (c *Controller) Client() controlplane.PushClient {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client
}

func (c *Controller) State() (enabled, connected bool) {
	client := c.Client()
	if client == nil {
		return false, false
	}
	return true, client.IsConnected()
}

func (c *Controller) Connected() bool {
	_, connected := c.State()
	return connected
}

// ObserveStatus updates connection-lifecycle facts only. Service consumes the
// returned observation to decide runtime side effects such as REST reconcile or
// clearing kernel device state.
func (c *Controller) ObserveStatus(status controlplane.StatusChange) StatusObservation {
	if c == nil {
		return StatusObservation{
			Connected:   status.Connected,
			NeedsResync: status.NeedsResync,
		}
	}

	c.mu.Lock()
	if status.Connected {
		c.disconnectedAt = time.Time{}
	} else if c.disconnectedAt.IsZero() {
		c.disconnectedAt = time.Now()
	}
	c.mu.Unlock()

	return StatusObservation{
		Connected:   status.Connected,
		NeedsResync: status.NeedsResync,
	}
}

func (c *Controller) needsDiscovery(now time.Time, disconnectedFor time.Duration) bool {
	if c == nil || c.source == nil || !c.source.SupportsDiscovery() {
		return false
	}

	c.mu.RLock()
	client := c.client
	disconnectedAt := c.disconnectedAt
	c.mu.RUnlock()

	if client == nil {
		return true
	}
	return !disconnectedAt.IsZero() && now.Sub(disconnectedAt) > disconnectedFor
}

// Discover re-checks whether the ControlPlane currently exposes a push client.
//
// Behavior intentionally mirrors the pre-S2 Service implementation:
// - discover when no client exists;
// - re-check after a prolonged disconnect;
// - enable a newly discovered client;
// - disable an existing client when discovery returns nil;
// - do not replace an already installed non-nil client in-place.
//
// REST reconciliation is represented by NeedsPoll and remains delegated back to
// Service/nodesync rather than being performed here.
func (c *Controller) Discover(
	ctx context.Context,
	metricsFn func() map[string]interface{},
	disconnectedFor time.Duration,
) (DiscoveryResult, error) {
	if !c.needsDiscovery(time.Now(), disconnectedFor) {
		return DiscoveryResult{}, nil
	}

	pushClient, err := c.source.Discover(ctx, metricsFn, c.EventSink(), c.StatusSink())
	if err != nil {
		return DiscoveryResult{Checked: true}, err
	}

	result := DiscoveryResult{
		Checked:    true,
		NeedsPoll:  c.source.SupportsPolling(),
		Transition: TransitionNone,
	}

	c.mu.Lock()
	current := c.client

	switch {
	case pushClient != nil && current == nil:
		runCtx, cancel := context.WithCancel(ctx)
		c.client = pushClient
		c.cancel = cancel
		c.disconnectedAt = time.Time{}
		result.Transition = TransitionEnabled
		c.mu.Unlock()
		go pushClient.Run(runCtx)
		return result, nil

	case pushClient == nil && current != nil:
		cancel := c.cancel
		c.client = nil
		c.cancel = nil
		c.disconnectedAt = time.Time{}
		result.Transition = TransitionDisabled
		c.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return result, nil

	default:
		c.mu.Unlock()
		return result, nil
	}
}
