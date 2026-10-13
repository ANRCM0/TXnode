package service

import (
	"context"
	"fmt"

	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nlog"
)

// startKernel keeps Service-specific logging/limiter hooks outside the generic
// lifecycle coordinator while delegating the disruptive Start transition and
// applied-state bookkeeping to kernellifecycle.Controller.
func (s *Service) startKernel(config *model.NodeSpec, users []model.UserSpec) bool {
	if s == nil || s.kernelLife == nil {
		return false
	}
	s.observeBoundary("KERNEL_START_BEGIN", true)
	if err := s.kernelLife.Start(config, users, s.certs.TLSCert()); err != nil {
		s.observeBoundary("KERNEL_START_FAILED", false)
		nlog.Core().Error("failed to start kernel", "error", err)
		return false
	}
	s.observeBoundary("KERNEL_START_OK", false)

	if s.nodeLog == nil {
		s.nodeLog = nlog.ForNode(config.Protocol, config.ServerPort)
	}
	s.speedTracker.SetLogCallback(func(msg string) {
		fullMsg := fmt.Sprintf(
			"speedtracker: %s active_limiters=%d",
			msg,
			s.speedTracker.LimitedUserCount(),
		)
		s.nodeLog.Info(fullMsg)
	})
	s.nodeLog.Info(fmt.Sprintf("started, %d users", len(users)))
	return true
}

// applyChanges is the narrow Service adapter from accepted desired config/user
// state into disruptive kernel lifecycle transitions.
func (s *Service) applyChanges(ctx context.Context, configChanged, usersChanged bool) {
	_ = ctx
	_ = usersChanged
	if !configChanged || s == nil || s.kernelLife == nil {
		return
	}

	if s.usageMode() {
		s.failUsageV2()
		return
	}
	users := s.users.Users()
	if s.lastConfig == nil || len(users) == 0 {
		if len(users) == 0 {
			s.stopKernelObserved(true)
		}
		return
	}

	if s.kernel.IsRunning() {
		if err := s.reloadKernelObserved(s.lastConfig, users); err != nil {
			nlog.Core().Warn(fmt.Sprintf("reload failed, restarting: %v", err))
			s.startKernel(s.lastConfig, users)
			return
		}
		if s.nodeLog != nil {
			s.nodeLog.Info(fmt.Sprintf("config updated, %d users", len(users)))
		}
		return
	}

	s.startKernel(s.lastConfig, users)
}
