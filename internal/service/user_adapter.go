package service

import (
	"context"

	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/userstate"
)

// userStateSource labels the path that refreshed the desired user snapshot.
// It remains a Service-side diagnostic concern; userstate.Controller owns only
// state/index mutation and does not know about ControlPlane transport details.
type userStateSource string

const (
	srcBootstrap userStateSource = "bootstrap"
	srcWSFull    userStateSource = "ws_full"
	srcPollFull  userStateSource = "poll_full"
	srcDeltaAdd  userStateSource = "ws_delta_add"
	srcDeltaRm   userStateSource = "ws_delta_remove"
)

func (s *Service) replaceUserState(
	users []model.UserSpec,
	hash string,
	src userStateSource,
) userstate.Snapshot {
	if s == nil || s.users == nil {
		return userstate.Snapshot{}
	}
	if hash == "" {
		hash = computeUserHash(users)
	}

	transition := s.users.Replace(users, hash)
	s.logUserRemovalProbe(transition.Removed, src)
	return transition.Previous
}

func (s *Service) updateUserState(users []model.UserSpec, src userStateSource) {
	s.replaceUserState(users, computeUserHash(users), src)
}

func (s *Service) restoreUserState(snapshot userstate.Snapshot) {
	if s == nil || s.users == nil {
		return
	}
	s.users.Restore(snapshot)
}

// logUserRemovalProbe is a temporary diagnostic probe.
//
// It records every user that vanished from the ControlPlane user list together
// with the path that observed it. Keeping this in the Service adapter avoids
// teaching the generic userstate controller about WebSocket/poll semantics.
func (s *Service) logUserRemovalProbe(removed []int, src userStateSource) {
	if len(removed) == 0 {
		return
	}
	const maxIDs = 20
	shown, extra := removed, 0
	if len(shown) > maxIDs {
		extra = len(shown) - maxIDs
		shown = shown[:maxIDs]
	}
	args := []any{
		"source", string(src),
		"removed", len(removed),
		"user_ids", shown,
	}
	if extra > 0 {
		args = append(args, "more", extra)
	}
	if s.nodeLog != nil {
		s.nodeLog.Info("probe: user removal observed", args...)
	} else {
		nlog.Core().Info("probe: user removal observed", args...)
	}
}

// Desired state stays authoritative after failed kernel mutation. Applied hashes
// advance only after the entire operation succeeds; uncertain revocation stops.
func (s *Service) applyUserUpdate(ctx context.Context, users []model.UserSpec, newHash string, src userStateSource) {
	if !s.signedUsersAllowed(users) {
		return
	}
	if s.usageMode() {
		if computeUserHash(users) != s.users.Hash() {
			s.failUsageV2()
		}
		return
	}
	if s.authorityTerminal(ctx) {
		return
	}
	s.observeBoundary("USER_UPDATE_BEGIN", true)
	defer s.observeBoundary("USER_UPDATE_END", false)
	periodChanged := s.tracker != nil && (s.tracker.PeriodsChanged(users) || s.tracker.PeriodModeChanged(users))
	// Retired connections keep old period until stopped and sampled.
	if s.kernel.IsRunning() && (periodChanged || len(users) == 0) {
		s.stopUncertainKernel()
	}
	s.replaceUserState(users, newHash, src)
	if len(users) == 0 {
		s.applyDesiredState(ctx)
		return
	}
	if !s.kernel.IsRunning() {
		if s.lastConfig != nil && !s.startKernel(s.lastConfig, users) {
			s.stopUncertainKernel()
			s.markApplicationPending("USER_APPLICATION_FAILED")
		}
		return
	}
	if s.appliedUserHash == s.users.Hash() && !s.desiredDirty {
		return
	}
	if _, _, err := s.kernel.UpdateUsers(users); err != nil {
		s.rebuildDesiredUsers(ctx)
		return
	}
	if !s.signedUsersAllowed(users) {
		s.stopUncertainKernel()
		return
	}
	if s.tracker != nil {
		s.tracker.BindPeriods(users)
	}
	s.confirmAppliedUsers(users)
}
func (s *Service) rebuildDesiredUsers(ctx context.Context) {
	s.stopUncertainKernel()
	s.markApplicationPending("USER_APPLICATION_FAILED")
	if s.lastConfig != nil && !s.authorityTerminal(ctx) {
		if !s.startKernel(s.lastConfig, s.users.Users()) {
			s.stopUncertainKernel()
			s.markApplicationPending("USER_APPLICATION_FAILED")
		}
	}
}
func (s *Service) applyUserDelta(ctx context.Context, action string, deltaUsers []model.UserSpec) {
	if s.authorizationEnabled() {
		s.requestAuthorizationPoll(ctx)
		return
	}
	if s.usageMode() {
		if len(deltaUsers) > 0 {
			s.failUsageV2()
		}
		return
	}
	if s.authorityTerminal(ctx) || len(deltaUsers) == 0 || (action != "add" && action != "remove") {
		return
	}
	s.observeBoundary("USER_DELTA_BEGIN", true)
	defer s.observeBoundary("USER_DELTA_END", false)
	oldUsers := s.users.Users()
	var desired []model.UserSpec
	src := srcDeltaAdd
	if action == "add" {
		desired = s.users.Merge(deltaUsers)
	} else {
		desired = s.users.Subtract(deltaUsers)
		src = srcDeltaRm
	}
	periodChanged := s.tracker != nil && (s.tracker.PeriodsChanged(desired) || s.tracker.PeriodModeChanged(desired))
	if s.kernel.IsRunning() && (periodChanged || len(desired) == 0) {
		s.stopUncertainKernel()
	}
	s.replaceUserState(desired, computeUserHash(desired), src)
	if len(desired) == 0 || !s.kernel.IsRunning() {
		s.applyDesiredState(ctx)
		return
	}
	if s.desiredDirty || s.pendingCertRenewal || (s.lastConfig != nil && s.appliedConfigHash != s.lastConfigHash) {
		s.applyDesiredState(ctx)
		return
	}
	var err error
	if action == "add" {
		for _, delta := range deltaUsers {
			for _, old := range oldUsers {
				if old.ID == delta.ID && old.UUID != delta.UUID {
					if _, err = s.kernel.RemoveUsers([]model.UserSpec{old}); err != nil {
						break
					}
				}
			}
			if err != nil {
				break
			}
		}
		if err == nil {
			_, err = s.kernel.AddUsers(deltaUsers)
		}
	} else {
		_, err = s.kernel.RemoveUsers(deltaUsers)
	}
	if err != nil {
		if _, _, fallbackErr := s.kernel.UpdateUsers(desired); fallbackErr != nil {
			s.rebuildDesiredUsers(ctx)
			return
		}
	}
	if s.tracker != nil {
		s.tracker.BindPeriods(desired)
	}
	s.confirmAppliedUsers(desired)
}
