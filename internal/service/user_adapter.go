package service

import (
	"context"
	"fmt"

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

// applyUserUpdate replaces the complete desired user set and then applies that
// state to the kernel. Desired state is prepared first so limiter lookups are
// valid during kernel mutation; it is rolled back if the kernel cannot apply
// the change or restart successfully.
func (s *Service) applyUserUpdate(
	ctx context.Context,
	users []model.UserSpec,
	newHash string,
	src userStateSource,
) {
	if s.usageMode() {
		if computeUserHash(users) != s.users.Hash() {
			s.failUsageV2()
		}
		return
	}
	_ = ctx
	s.observeBoundary("USER_UPDATE_BEGIN", true)
	defer s.observeBoundary("USER_UPDATE_END", false)
	previous := s.replaceUserState(users, newHash, src)

	if !s.kernel.IsRunning() {
		if len(users) == 0 || s.lastConfig == nil {
			return
		}
		if !s.startKernel(s.lastConfig, users) {
			s.restoreUserState(previous)
		}
		return
	}

	added, removed, err := s.kernel.UpdateUsers(users)
	if err != nil {
		nlog.Core().Warn(fmt.Sprintf("UpdateUsers failed, restarting kernel: %v", err))
		if !s.startKernel(s.lastConfig, users) {
			s.restoreUserState(previous)
		}
		return
	}
	if s.nodeLog != nil && (added > 0 || removed > 0) {
		s.nodeLog.Info(fmt.Sprintf("users updated: +%d -%d", added, removed))
	}
}

// applyUserDelta applies an incremental user change through the existing atomic
// kernel user API while userstate.Controller owns the desired snapshot.
func (s *Service) applyUserDelta(
	ctx context.Context,
	action string,
	deltaUsers []model.UserSpec,
) {
	if s.usageMode() {
		if len(deltaUsers) > 0 {
			s.failUsageV2()
		}
		return
	}
	_ = ctx
	if (action == "add" || action == "remove") && len(deltaUsers) > 0 {
		s.observeBoundary("USER_DELTA_BEGIN", true)
		defer s.observeBoundary("USER_DELTA_END", false)
	}
	switch action {
	case "add":
		if len(deltaUsers) == 0 {
			return
		}

		oldUsers := s.users.Users()
		merged := s.users.Merge(deltaUsers)
		newHash := computeUserHash(merged)

		if !s.kernel.IsRunning() {
			previous := s.replaceUserState(merged, newHash, srcDeltaAdd)
			if s.lastConfig == nil {
				return
			}
			if !s.startKernel(s.lastConfig, merged) {
				s.restoreUserState(previous)
			}
			return
		}

		// Preserve the existing UUID-replacement behavior: remove the old kernel
		// user before adding a delta for the same numeric ID with a new UUID.
		for _, delta := range deltaUsers {
			for _, old := range oldUsers {
				if old.ID == delta.ID && old.UUID != delta.UUID {
					s.kernel.RemoveUsers([]model.UserSpec{old})
					break
				}
			}
		}

		previous := s.replaceUserState(merged, newHash, srcDeltaAdd)
		added, err := s.kernel.AddUsers(deltaUsers)
		if err != nil {
			nlog.Core().Warn(fmt.Sprintf("AddUsers failed: %v, falling back to UpdateUsers", err))
			if _, _, err := s.kernel.UpdateUsers(merged); err != nil {
				nlog.Core().Error(fmt.Sprintf("UpdateUsers fallback failed: %v", err))
				s.restoreUserState(previous)
				return
			}
		}
		if s.nodeLog != nil && added > 0 {
			s.nodeLog.Info(fmt.Sprintf("users added: +%d", added))
		}

	case "remove":
		if len(deltaUsers) == 0 {
			return
		}

		filtered := s.users.Subtract(deltaUsers)
		newHash := computeUserHash(filtered)

		// Keep desired state current even while the kernel is stopped; otherwise
		// a later restart could resurrect users already removed by ControlPlane.
		if !s.kernel.IsRunning() {
			s.replaceUserState(filtered, newHash, srcDeltaRm)
			return
		}

		previous := s.replaceUserState(filtered, newHash, srcDeltaRm)
		removed, err := s.kernel.RemoveUsers(deltaUsers)
		if err != nil {
			nlog.Core().Warn(fmt.Sprintf("RemoveUsers failed: %v, falling back to UpdateUsers", err))
			if _, _, err := s.kernel.UpdateUsers(filtered); err != nil {
				nlog.Core().Error(fmt.Sprintf("UpdateUsers fallback failed: %v", err))
				s.restoreUserState(previous)
				return
			}
		}
		if s.nodeLog != nil && removed > 0 {
			s.nodeLog.Info(fmt.Sprintf("users removed: -%d", removed))
		}

	default:
		nlog.Core().Warn(fmt.Sprintf("unknown user delta action: %s", action))
	}
}
