package kernellifecycle

import (
	"sync"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// AppliedState describes the last full config/user state successfully applied
// through Start/Reload. It is runtime bookkeeping only; ControlPlane remains
// authoritative for desired config/users.
type AppliedState struct {
	Config *model.NodeSpec
	Users  []model.UserSpec
}

// Controller owns disruptive kernel lifecycle transitions and their applied
// runtime bookkeeping. Atomic user add/remove/update remains outside this
// controller because those operations are non-disruptive kernel capabilities.
type Controller struct {
	kernel kernel.Kernel

	mu      sync.RWMutex
	applied AppliedState
}

func New(k kernel.Kernel) *Controller {
	return &Controller{kernel: k}
}

func (c *Controller) Start(
	config *model.NodeSpec,
	users []model.UserSpec,
	tls kernel.TLSCert,
) error {
	if err := c.kernel.Start(config, users, tls); err != nil {
		return err
	}
	c.setApplied(config, users)
	return nil
}

func (c *Controller) Reload(
	config *model.NodeSpec,
	users []model.UserSpec,
	tls kernel.TLSCert,
) error {
	if err := c.kernel.Reload(config, users, tls); err != nil {
		return err
	}
	c.setApplied(config, users)
	return nil
}

// Stop shuts down the kernel without rewriting applied-state bookkeeping.
// This preserves the previous shutdown semantics where process termination did
// not reinterpret the last successfully applied ControlPlane state.
func (c *Controller) Stop() {
	if c == nil || c.kernel == nil {
		return
	}
	c.kernel.Stop()
}

// StopForNoUsers records the existing runtime semantic used when desired user
// state becomes empty: the kernel is stopped and applied users become empty,
// while the last applied config remains available as runtime bookkeeping.
func (c *Controller) StopForNoUsers() {
	if c == nil || c.kernel == nil {
		return
	}
	c.kernel.Stop()

	c.mu.Lock()
	c.applied.Users = nil
	c.mu.Unlock()
}

func (c *Controller) Applied() AppliedState {
	if c == nil {
		return AppliedState{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return AppliedState{
		Config: c.applied.Config,
		Users:  append([]model.UserSpec(nil), c.applied.Users...),
	}
}

func (c *Controller) setApplied(config *model.NodeSpec, users []model.UserSpec) {
	c.mu.Lock()
	c.applied = AppliedState{
		Config: config,
		Users:  append([]model.UserSpec(nil), users...),
	}
	c.mu.Unlock()
}

// RecordUsers follows only a successfully completed atomic user mutation.
func (c *Controller) RecordUsers(users []model.UserSpec) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.applied.Users = append([]model.UserSpec(nil), users...)
	c.mu.Unlock()
}
