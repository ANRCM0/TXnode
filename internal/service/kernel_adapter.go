package service

import (
	"context"
	"fmt"

	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/tracker"
)

// startKernel keeps Service-specific logging/limiter hooks outside the generic
// lifecycle coordinator while delegating the disruptive Start transition and
// applied-state bookkeeping to kernellifecycle.Controller.
func (s *Service) startKernel(config *model.NodeSpec, users []model.UserSpec) bool {
	if s == nil || s.kernelLife == nil || (s.syncer != nil && s.syncer.Terminal() != nil) {
		return false
	}
	if !s.signedUsersAllowed(users) {
		return false
	}
	if s.nativeUsageMode() && s.nativeUsage.refreshNeeded.Load() {
		return false
	}
	if !s.nativeUsageMode() && s.kernel.IsRunning() {
		s.stopUncertainKernel()
	}
	if !s.nativeUsageMode() && s.tracker != nil && s.tracker.PeriodModeChanged(users) && s.cfg != nil && s.cfg.Panel.Provider == "txboard" {
		// A legacy-to-signed upgrade cannot leave a mixed uncheckpointed cohort.
		// Old immutable bodies are replayed as-is, then unsigned pending bytes get
		// their own durable ID before new signed-period listeners are admitted.
		if s.reporter != nil && s.reporter.HasRecoveryBatch() {
			if err := s.reporter.ReplayRecovery(); err != nil {
				s.markApplicationPending("LEGACY_PERIOD_DRAIN_REQUIRED")
				return false
			}
		}
		for s.tracker.HasTraffic() {
			if s.reporter == nil || s.reporter.PushSyncRecoverable(s.prepareReportBatch, s.restoreUnsubmittedReport) != nil {
				s.markApplicationPending("PERIOD_MODE_DRAIN_REQUIRED")
				return false
			}
		}
	}
	if _, mixed := tracker.AdmissionPeriodMode(users); mixed {
		s.stopUncertainKernel()
		s.markApplicationPending("PERIOD_MODE_MIXED")
		return false
	}
	var previousPeriods tracker.PeriodBindings
	if !s.nativeUsageMode() && s.tracker != nil {
		previousPeriods = s.tracker.BindPeriods(users)
	}
	s.observeBoundary("KERNEL_START_BEGIN", true)
	if err := s.kernelLife.Start(config, users, s.certs.TLSCert()); err != nil {
		if !s.nativeUsageMode() && s.tracker != nil {
			s.tracker.RestorePeriodBindings(previousPeriods)
		}
		s.markApplicationPending("KERNEL_START_FAILED")
		s.observeBoundary("KERNEL_START_FAILED", false)
		nlog.Core().Error("failed to start kernel", "error", err)
		return false
	}
	if !s.signedUsersAllowed(users) {
		s.stopUncertainKernel()
		return false
	}
	if s.nativeUsageMode() && s.tracker != nil {
		s.tracker.BeginCumulativeGeneration()
	}
	if !s.nativeUsageMode() && s.tracker != nil {
		if lifecycle, ok := s.kernel.(interface{ ResetsCumulativeTrafficOnStart() bool }); ok && lifecycle.ResetsCumulativeTrafficOnStart() {
			s.tracker.BeginCumulativeGeneration()
		}
	}
	s.confirmAppliedState(config, users)
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
	if !configChanged && !usersChanged && !s.desiredDirty && !s.pendingCertRenewal {
		return
	}
	s.applyDesiredState(ctx)
}

func (s *Service) markApplicationPending(code string) {
	s.metricsMu.Lock()
	s.desiredDirty = true
	s.applicationFailure = code
	s.metricsMu.Unlock()
}
func (s *Service) confirmAppliedState(cfg *model.NodeSpec, users []model.UserSpec) {
	s.metricsMu.Lock()
	s.appliedConfigHash = computeConfigHash(cfg)
	s.appliedUserHash = computeUserHash(users)
	s.desiredDirty = s.configRejected
	s.pendingCertRenewal = false
	if !s.configRejected {
		s.applicationFailure = ""
	}
	s.metricsMu.Unlock()
}
func (s *Service) confirmAppliedUsers(users []model.UserSpec) {
	if s.kernelLife != nil {
		s.kernelLife.RecordUsers(users)
	}
	s.metricsMu.Lock()
	s.appliedUserHash = computeUserHash(users)
	s.desiredDirty = s.configRejected || s.pendingCertRenewal || (s.lastConfig != nil && s.appliedConfigHash != computeConfigHash(s.lastConfig))
	if !s.desiredDirty {
		s.applicationFailure = ""
	}
	s.metricsMu.Unlock()
}

// Failed user mutation/reconstruction can leave an uncertain kernel behind.
// Stop admission and preserve the native cumulative tail before a later rebuild.
func (s *Service) stopUncertainKernel() {
	s.stopKernelObserved(false)
	if !s.nativeUsageMode() && s.tracker != nil {
		traffic, alive, count, err := s.kernel.GetUserTraffic(context.Background())
		if err == nil {
			s.tracker.Process(traffic, alive, count)
		}
	}
}
func (s *Service) applyDesiredState(ctx context.Context) {
	if s == nil || s.kernelLife == nil || s.authorityTerminal(ctx) {
		return
	}
	if !s.authorizationValid() {
		s.stopUncertainKernel()
		return
	}
	if s.nativeUsageMode() {
		users := s.users.Users()
		if len(users) == 0 {
			s.stopKernelObserved(true)
			s.confirmAppliedUsers(users)
		} else if !s.kernel.IsRunning() || s.appliedConfigHash != computeConfigHash(s.lastConfig) || s.pendingCertRenewal {
			// A fresh signed revision must retire the old metered timeline before
			// retries or certificate/config changes can open another kernel.
			s.requestAuthorizationPoll(ctx)
		}
		return
	}
	users := s.users.Users()
	if s.kernel.IsRunning() && (len(users) == 0 || s.tracker != nil && (s.tracker.PeriodsChanged(users) || s.tracker.PeriodModeChanged(users))) {
		s.stopUncertainKernel()
	}
	if len(users) == 0 {
		if s.kernel.IsRunning() || s.appliedUserHash != computeUserHash(users) {
			s.stopKernelObserved(true)
			s.confirmAppliedUsers(users)
		}
		return
	}
	if s.lastConfig == nil {
		return
	}
	if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), s.lastConfig, s.certs.TLSCert()); err != nil {
		s.markApplicationPending("CONFIG_VALIDATION_FAILED")
		return
	}
	if !s.kernel.IsRunning() {
		if !s.startKernel(s.lastConfig, users) {
			s.stopUncertainKernel()
			s.markApplicationPending("KERNEL_START_FAILED")
		}
		return
	}
	if s.appliedConfigHash == computeConfigHash(s.lastConfig) && !s.pendingCertRenewal {
		if s.appliedUserHash != s.users.Hash() || s.desiredDirty {
			s.applyUserUpdate(ctx, users, s.users.Hash(), srcPollFull)
		}
		return
	}
	if err := s.reloadKernelObserved(s.lastConfig, users); err != nil {
		s.stopUncertainKernel()
		if !s.startKernel(s.lastConfig, users) {
			s.stopUncertainKernel()
			s.markApplicationPending("KERNEL_RELOAD_FAILED")
		}
		return
	}
	s.confirmAppliedState(s.lastConfig, users)
}
