package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
)

// Permanent process assignment; contains no Service identity or secret. Tests
// inject a separate instance-owned gate rather than resetting production state.
var localEventProcessOwner usagebucket.ProcessOwner

type localEventKernel interface {
	SetLocalEventConsumer(*usagebucket.Coordinator) bool
}

func (s *Service) localEventDirectory() string {
	root := s.cfg.UsageEventStore.Directory
	if root == "" {
		root = s.cfg.Kernel.ConfigDir
	}
	if root == "" {
		return ""
	}
	key := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%d|%s", s.cfg.Panel.Provider, s.cfg.Panel.URL, s.cfg.Panel.NodeID, s.cfg.Panel.MachineID, s.cfg.InstanceID)))
	return filepath.Join(root, ".txnode-event-store-"+hex.EncodeToString(key[:12]))
}

func (s *Service) initLocalEventConsumer() {
	if s == nil || s.cfg == nil || !s.cfg.UsageEventStore.Enabled {
		return
	}
	s.eventConsumerMu.Lock()
	defer s.eventConsumerMu.Unlock()
	if s.eventConsumerState != "" {
		return
	}
	k, supported := s.kernel.(localEventKernel)
	if !supported {
		s.eventConsumerState = "UNSUPPORTED_KERNEL"
		return
	}
	owner := s.eventOwner
	if owner == nil {
		owner = &localEventProcessOwner
	}
	if !owner.Claim() {
		s.eventConsumerState = "LOCAL_PROCESS_OWNER_EXISTS"
		nlog.Core().Warn("local event observation unavailable; v1 continues", "reason", s.eventConsumerState)
		return
	}
	factory := s.eventFactory
	if factory == nil {
		factory = usagebucket.NewAsyncCoordinator
	}
	c, err := factory(s.localEventDirectory(), usagebucket.StoreOptions{MaxBytes: s.cfg.UsageEventStore.MaxBytes}, usagebucket.CoordinatorOptions{MaxMeters: 8})
	if err != nil {
		s.eventConsumerState = "LOCAL_INITIALIZATION_FAILED"
		return
	}
	s.eventConsumer = c
	s.eventConsumerState = "opening"
	if !k.SetLocalEventConsumer(c) {
		s.eventConsumerState = "LOCAL_ATTACH_REFUSED"
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = c.Close(ctx)
	}
}

func (s *Service) localEventConsumer() *usagebucket.Coordinator {
	if s == nil || s.cfg == nil || !s.cfg.UsageEventStore.Enabled {
		return nil
	}
	s.eventConsumerMu.Lock()
	defer s.eventConsumerMu.Unlock()
	return s.eventConsumer
}

func (s *Service) localEventBoundary(advance bool) {
	if c := s.localEventConsumer(); c != nil {
		c.LocalFence(advance)
	}
}

func (s *Service) closeLocalEventConsumer() {
	if c := s.localEventConsumer(); c != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			nlog.Core().Warn("local event observation shutdown incomplete; tail unknown", "reason", "LOCAL_CLOSE_INCOMPLETE")
		}
	}
}

func (s *Service) localEventMetrics() map[string]interface{} {
	s.eventConsumerMu.Lock()
	c, state := s.eventConsumer, s.eventConsumerState
	s.eventConsumerMu.Unlock()
	if state == "" {
		state = "not_started"
	}
	m := map[string]interface{}{"state": state, "authorizes": false, "attribution": "unattributable", "restore_unknown": true, "tail_unknown": true, "coverage": "single_service_per_process"}
	if c == nil {
		return m
	}
	status := c.Status()
	switch {
	case status.Degraded:
		m["state"] = "stopped"
		m["reason"] = status.Reason
	case state == "LOCAL_ATTACH_REFUSED":
		// Preserve a healthy worker's refusal without hiding an earlier store failure.
	case status.Closed:
		m["state"] = "closed"
	case status.Closing:
		m["state"] = "closing"
	case status.Opening:
		m["state"] = "opening"
	default:
		m["state"] = "recording"
	}
	m["meters"] = status.Meters
	m["retained_event_capacity"] = status.RetainedEventCapacity
	if store, ready := c.StoreSnapshot(); ready {
		m["records"] = store.Sequence
		m["bytes"] = store.Bytes
	}
	return m
}
