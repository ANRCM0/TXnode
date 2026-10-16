package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nodesync"
)

type authorizationSource interface {
	ConfigureAuthorization(*authorization.Manager) error
	RefreshAuthorization(context.Context) (controlplane.Snapshot, error)
}
type authorizationResult struct {
	snapshot    controlplane.Snapshot
	err         error
	certChanged bool
}

func (s *Service) initAuthorization() error {
	if s.cfg == nil || !s.cfg.Authorization.Enabled || s.authorization != nil {
		return nil
	}
	if err := s.cfg.ValidateAuthorization(); err != nil {
		return err
	}
	source, ok := s.source.(authorizationSource)
	if !ok {
		return errors.New("NODE_AUTHORIZATION_SOURCE_UNSUPPORTED")
	}
	target := authorization.Target{NodeID: s.cfg.Panel.NodeID}
	if s.cfg.Panel.MachineID > 0 {
		v := s.cfg.Panel.MachineID
		target.MachineID = &v
	}
	cfg := s.cfg.Authorization
	cfg.StateDir = filepath.Join(cfg.StateDir, fmt.Sprintf("node-%d", target.NodeID))
	manager, err := authorization.NewManager(cfg, target)
	if err != nil {
		return err
	}
	if err := source.ConfigureAuthorization(manager); err != nil {
		manager.Close()
		return err
	}
	s.authorization = manager
	s.authorizationResults = make(chan authorizationResult, 1)
	return nil
}
func (s *Service) authorizationEnabled() bool { return s != nil && s.authorization != nil }
func (s *Service) authorizationValid() bool {
	if !s.authorizationEnabled() {
		return true
	}
	s.authorizationAdmissionMu.Lock()
	defer s.authorizationAdmissionMu.Unlock()
	return !s.authorizationExpired.Load() && !s.authorizationDeadline.IsZero() && time.Now().Before(s.authorizationDeadline)
}
func (s *Service) acceptAuthorization(snapshot *authorization.Snapshot, users []model.UserSpec, node *model.NodeSpec) error {
	if !s.authorizationEnabled() {
		return nil
	}
	if snapshot == nil || users == nil || nodesync.UserHash(model.UserSpecsFromPanel(snapshot.Users)) != nodesync.UserHash(users) {
		return errors.New("NODE_AUTHORIZATION_USERS_MISMATCH")
	}
	if node == nil {
		node = s.lastConfig
	}
	protocol := ""
	if node != nil {
		protocol = node.Protocol
	}
	// Withdraw the prior cohort before a changed snapshot can extend the
	// authority deadline. The final meter retains its old period bindings.
	if s.kernel.IsRunning() && (nodesync.UserHash(users) != s.users.Hash() ||
		config.ProviderAuthorizationPolicy(s.authorization.Config().PolicyVersion) &&
			(s.lastConfig == nil || s.lastConfig.Protocol != protocol)) {
		s.stopUncertainKernel()
	}
	_, err := s.authorization.AcceptVerifiedForProtocol(snapshot, protocol, time.Now())
	if err == nil {
		deadline := s.authorization.Expiry()
		s.authorizationAdmissionMu.Lock()
		now := time.Now()
		if s.authorizationExpired.Load() || !s.authorizationDeadline.IsZero() && !now.Before(s.authorizationDeadline) || !now.Before(deadline) {
			s.authorizationExpired.Store(true)
			s.authorizationAdmissionMu.Unlock()
			return errors.New("NODE_AUTHORIZATION_EXPIRED")
		}
		s.authorizationDeadline = deadline
		if s.authorizationWatchdog != nil {
			s.authorizationWatchdog.Stop()
		}
		s.authorizationWatchdog = time.AfterFunc(time.Until(deadline), s.expireAuthorizationAdmission)
		s.authorizationAdmissionMu.Unlock()
		s.resetAuthorizationTimer()
	}
	return err
}

// Closing data-plane I/O never waits for an authorization fsync, traffic spool,
// observer write or the Service event loop. Tail persistence follows on the
// main loop after admission has been latched shut.
func (s *Service) expireAuthorizationAdmission() {
	s.authorizationAdmissionMu.Lock()
	if s.authorizationExpired.Load() || time.Now().Before(s.authorizationDeadline) {
		s.authorizationAdmissionMu.Unlock()
		return
	}
	s.authorizationExpired.Store(true)
	s.authorizationAdmissionMu.Unlock()
	s.closeAuthorizationIO()
}
func (s *Service) authorizationChannels() (<-chan time.Time, <-chan time.Time, func()) {
	if !s.authorizationEnabled() {
		return nil, nil, func() {}
	}
	s.authorizationTimer = time.NewTimer(time.Until(s.authorization.Expiry()))
	ticker := time.NewTicker(time.Duration(s.cfg.Authorization.RefreshInterval) * time.Second)
	return s.authorizationTimer.C, ticker.C, func() { s.authorizationTimer.Stop(); ticker.Stop() }
}
func (s *Service) resetAuthorizationTimer() {
	if !s.authorizationEnabled() || s.authorizationTimer == nil {
		return
	}
	if !s.authorizationTimer.Stop() {
		select {
		case <-s.authorizationTimer.C:
		default:
		}
	}
	s.authorizationTimer.Reset(time.Until(s.authorization.Expiry()))
}
func (s *Service) requestAuthorization(ctx context.Context) {
	s.requestAuthorizationSnapshot(ctx, false)
}
func (s *Service) requestAuthorizationPoll(ctx context.Context) {
	s.requestAuthorizationSnapshot(ctx, true)
}
func (s *Service) requestAuthorizationSnapshot(ctx context.Context, full bool) {
	if full {
		s.authorizationFullPending.Store(true)
	}
	if !s.authorizationEnabled() || !s.authorizationRefresh.CompareAndSwap(false, true) {
		return
	}
	full = s.authorizationFullPending.Swap(false)
	source := s.source.(authorizationSource)
	s.latchCertificateRenewal()
	certChanged := s.pendingCertRenewal
	s.authorizationWorkers.Add(1)
	go func() {
		defer s.authorizationWorkers.Done()
		var snapshot controlplane.Snapshot
		var err error
		if full {
			snapshot, err = s.source.Poll(ctx)
		} else {
			snapshot, err = source.RefreshAuthorization(ctx)
		}
		// The flag stays set until the main loop consumes the result, so two
		// channels cannot apply signed revisions out of delivery order.
		select {
		case s.authorizationResults <- authorizationResult{snapshot: snapshot, err: err, certChanged: certChanged}:
		case <-ctx.Done():
			s.authorizationRefresh.Store(false)
		}
	}()
}
func (s *Service) applyAuthorizationResult(ctx context.Context, result authorizationResult) error {
	if result.err != nil {
		if controlerror.IsAuthoritativeStopCause(result.err) {
			return result.err
		}
		// Network loss does not invent a revocation. The independently running
		// hard lease timer will close authority at the fixed signed boundary.
		if authorization.IsRefusal(result.err) {
			return result.err
		}
		return nil
	}
	if s.authorityTerminal(ctx) {
		return context.Cause(ctx)
	}
	if s.nativeUsageMode() {
		return s.applyNativeAuthorization(ctx, result.snapshot, result.certChanged)
	}
	s.applySyncResult(ctx, nodesync.Result{Config: result.snapshot.Config, Users: result.snapshot.Users,
		UserHash: computeUserHash(result.snapshot.Users), Authorization: result.snapshot.Authorization, CertChanged: result.certChanged})
	return s.authorizationFailure
}
func (s *Service) signedUsersAllowed(users []model.UserSpec) bool {
	if !s.authorizationEnabled() {
		return true
	}
	if !s.authorizationValid() {
		return false
	}
	snapshot := s.authorization.Current()
	protocol := ""
	if s.lastConfig != nil {
		protocol = s.lastConfig.Protocol
	}
	return snapshot != nil && authorization.ValidateProtocol(snapshot, protocol) == nil &&
		nodesync.UserHash(model.UserSpecsFromPanel(snapshot.Users)) == nodesync.UserHash(users)
}

// A terminal auth error uses the already proved close-before-checkpoint path.
// It does not claim to be a fabricated Core HTTP rejection or machine denial.
func (s *Service) stopForAuthorization(err error) error {
	s.authorizationExpired.Store(true)
	s.closeAuthorizationIO()
	return s.stopForAuthorityDenial(err)
}
func (s *Service) closeAuthorizationIO() {
	if immediate, ok := s.kernel.(interface{ StopAuthorization() }); ok {
		immediate.StopAuthorization()
	} else {
		s.kernel.Stop()
	}
}
func (s *Service) refuseAuthorization(err error) {
	if s.authorizationFailure == nil {
		s.authorizationFailure = s.stopForAuthorization(err)
	}
}
func (s *Service) closeAuthorization() {
	s.authorizationWorkers.Wait()
	if s.authorization != nil {
		s.authorizationAdmissionMu.Lock()
		s.authorizationExpired.Store(true)
		if s.authorizationWatchdog != nil {
			s.authorizationWatchdog.Stop()
		}
		s.authorizationAdmissionMu.Unlock()
		s.authorization.Close()
	}
}
