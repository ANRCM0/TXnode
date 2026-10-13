package service

import (
	"context"
	"fmt"

	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/nodesync"
)

// schedulePoll exposes only the Service-owned runtime facts needed by the
// independent nodesync.Controller. Poll concurrency, retry/backoff and snapshot
// hashing stay outside the Service orchestrator.
func (s *Service) schedulePoll(ctx context.Context) {
	if s == nil || s.syncer == nil || s.certs == nil {
		return
	}
	s.syncer.Poll(ctx, s.lastConfigHash, s.certs.ConsumeRenewal())
}

func (s *Service) requestWSResync(ctx context.Context, reason string) {
	if s == nil || s.syncer == nil || s.certs == nil {
		return
	}
	if !s.syncer.RequestResync(ctx, s.lastConfigHash, s.certs.ConsumeRenewal()) {
		return
	}

	if s.nodeLog != nil {
		s.nodeLog.Warn("ws state may be stale, scheduling REST reconciliation", "reason", reason)
	} else {
		nlog.Core().Warn("ws state may be stale, scheduling REST reconciliation", "reason", reason)
	}
}

// applySyncResult is the narrow adapter from transport synchronization into
// Service runtime mutation. nodesync prepares immutable snapshots; Service
// remains authoritative for validation and applying them to the data plane.
func (s *Service) applySyncResult(ctx context.Context, result nodesync.Result) {
	if s.usageMode() && (result.CertChanged || result.Config != nil && result.ConfigHash != s.lastConfigHash || result.Users != nil && result.UserHash != s.users.Hash()) {
		s.failUsageV2()
		return
	}

	if s.syncer != nil {
		s.syncer.CompleteResync()
	}

	configChanged := false
	if result.CertChanged {
		nlog.Core().Info("certificate renewed, kernel restart needed")
		configChanged = true
	}

	if result.Config != nil {
		if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), result.Config, s.certs.TLSCert()); err != nil {
			nlog.Core().Warn("runtime config validation failed", "error", err)
			result.Config = nil
		} else {
			configChanged = true
			if s.nodeLog == nil {
				s.nodeLog = nlog.ForNode(result.Config.Protocol, result.Config.ServerPort)
			}
			s.nodeLog.Info(fmt.Sprintf("config updated, %d users", s.users.Count()))

			s.metricsMu.Lock()
			s.lastConfig = result.Config
			s.metricsMu.Unlock()
			s.lastConfigHash = result.ConfigHash

			if s.applyRemoteOverrides(ctx, result.Config) {
				configChanged = true
			}
		}
	}

	if result.Users != nil {
		usersChanged := result.UserHash != s.users.Hash()
		if usersChanged && !configChanged {
			s.applyUserUpdate(ctx, result.Users, result.UserHash, srcPollFull)
		} else if usersChanged {
			s.replaceUserState(result.Users, result.UserHash, srcPollFull)
		}
	}

	if configChanged {
		s.applyChanges(ctx, true, false)
	}
}

// Keep package-local helpers during S2 so user/kernel refactors do not need to
// change at the same time. Hash ownership has moved to nodesync.Controller.
func computeConfigHash(cfg *model.NodeSpec) string {
	return nodesync.ConfigHash(cfg)
}

func computeUserHash(users []model.UserSpec) string {
	return nodesync.UserHash(users)
}
