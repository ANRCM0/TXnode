package service

import (
	"context"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/nodesync"
)

func (s *Service) latchCertificateRenewal() {
	if s.certs != nil && s.certs.ConsumeRenewal() {
		s.metricsMu.Lock()
		s.pendingCertRenewal = true
		s.metricsMu.Unlock()
	}
}
func (s *Service) schedulePoll(ctx context.Context) {
	if s.authorizationEnabled() {
		s.requestAuthorizationPoll(ctx)
		return
	}
	if s == nil || s.syncer == nil || s.certs == nil {
		return
	}
	s.latchCertificateRenewal()
	s.syncer.PollAt(ctx, s.pollAppliedConfigHash(), s.pendingCertRenewal, s.desiredGeneration)
}

// A previous successful hash cannot suppress recovery after the kernel stopped
// or a rejected desired construction left an application pending.
func (s *Service) pollAppliedConfigHash() string {
	if s.desiredDirty || s.pendingCertRenewal || s.configRejected || !s.kernel.IsRunning() {
		return ""
	}
	return s.appliedConfigHash
}
func (s *Service) resetSnapshotCache() {
	if reset, ok := s.source.(interface{ ResetSnapshotCache() }); ok {
		reset.ResetSnapshotCache()
	}
}
func (s *Service) requestWSResync(ctx context.Context, reason string) {
	if s.authorizationEnabled() {
		s.requestAuthorizationPoll(ctx)
		return
	}
	if s == nil || s.syncer == nil || s.certs == nil {
		return
	}
	s.latchCertificateRenewal()
	if !s.syncer.RequestResyncAt(ctx, s.pollAppliedConfigHash(), s.pendingCertRenewal, s.desiredGeneration) {
		return
	}
	nlog.Core().Warn("ws state may be stale, scheduling REST reconciliation", "reason", reason)
}

func (s *Service) acceptDesiredConfig(ctx context.Context, node *model.NodeSpec) {
	hash := computeConfigHash(node)
	s.metricsMu.Lock()
	s.lastConfig = node
	s.lastConfigHash = hash
	s.configRejected = false
	s.metricsMu.Unlock()
	if s.cfg != nil && s.applyRemoteOverrides(ctx, node) {
		s.metricsMu.Lock()
		s.pendingCertRenewal = true
		s.metricsMu.Unlock()
	}
}
func (s *Service) applySyncResult(ctx context.Context, result nodesync.Result) {
	if result.Terminal != nil || s.authorityTerminal(ctx) {
		return
	}
	if s.nativeUsageMode() {
		if err := s.applyNativeAuthorization(ctx, controlplane.Snapshot{Config: result.Config, Users: result.Users,
			Authorization: result.Authorization}, result.CertChanged); err != nil {
			s.refuseAuthorization(err)
		}
		return
	}
	if s.syncer != nil {
		s.syncer.CompleteResync()
	}
	if result.HasGeneration && result.Generation != s.desiredGeneration {
		s.resetSnapshotCache()
		s.schedulePoll(ctx)
		return
	}
	if err := s.acceptAuthorization(result.Authorization, result.Users, result.Config); err != nil {
		s.refuseAuthorization(err)
		return
	}
	if result.CertChanged {
		s.metricsMu.Lock()
		s.pendingCertRenewal = true
		s.metricsMu.Unlock()
	}
	configAccepted := false
	if result.Config != nil {
		if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), result.Config, s.certs.TLSCert()); err != nil {
			s.metricsMu.Lock()
			s.configRejected = true
			s.metricsMu.Unlock()
			s.markApplicationPending("CONFIG_VALIDATION_FAILED")
		} else {
			s.acceptDesiredConfig(ctx, result.Config)
			configAccepted = true
		}
	}
	if result.Users != nil {
		if configAccepted || s.pendingCertRenewal || s.appliedConfigHash != s.lastConfigHash {
			s.replaceUserState(result.Users, result.UserHash, srcPollFull)
		} else {
			s.applyUserUpdate(ctx, result.Users, result.UserHash, srcPollFull)
			return
		}
	}
	s.applyDesiredState(ctx)
}
func computeConfigHash(cfg *model.NodeSpec) string  { return nodesync.ConfigHash(cfg) }
func computeUserHash(users []model.UserSpec) string { return nodesync.UserHash(users) }
