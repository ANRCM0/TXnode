package service

import (
	"context"
	"time"

	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/pushsync"
)

const pushRediscoveryAfter = 10 * time.Minute

func (s *Service) handlePushStatus(ctx context.Context, status controlplane.StatusChange) {
	if s == nil || s.push == nil {
		return
	}

	// Invalidate an in-flight pre-reconnect response as well as transport caches.
	s.desiredGeneration++
	s.resetSnapshotCache()
	observation := s.push.ObserveStatus(status)
	if observation.NeedsResync {
		s.requestWSResync(ctx, "drop_detected")
	}

	if observation.Connected {
		if s.nodeLog != nil {
			s.nodeLog.Info("ws connected")
		} else {
			nlog.Core().Info("ws connected")
		}
		// A reconnect may have missed events. Reconcile through the existing
		// nodesync controller rather than applying transport state here.
		s.schedulePoll(ctx)
		return
	}

	if s.nodeLog != nil {
		s.nodeLog.Info("ws disconnected")
	} else {
		nlog.Core().Info("ws disconnected")
	}

	// Device presence is a live runtime fact; stale push connectivity must not
	// leave global device state behind.
	s.kernel.ClearGlobalDevices()
	s.schedulePoll(ctx)
}

func (s *Service) discoverPush(ctx context.Context) {
	if s == nil || s.push == nil {
		return
	}

	result, err := s.push.Discover(ctx, s.wsMetrics, pushRediscoveryAfter)
	if err != nil {
		nlog.Core().Debug("push discovery failed", "error", err)
		return
	}
	if !result.Checked {
		return
	}

	if result.NeedsPoll {
		s.desiredGeneration++
		s.resetSnapshotCache()
		s.schedulePoll(ctx)
	}

	switch result.Transition {
	case pushsync.TransitionEnabled:
		nlog.Core().Info("push discovery: control plane enabled push, creating client")
	case pushsync.TransitionDisabled:
		nlog.Core().Info("push discovery: control plane disabled push, switching to polling")
	}
}
