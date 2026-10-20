package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// Native WS configuration is authenticated by the control-plane transport;
// credentials and metering authority remain exclusively in the signed snapshot.
// Only a listener-port delta may reuse the current live metered timeline.
func (s *Service) reloadNativeWSPort(ctx context.Context, candidate *model.NodeSpec) bool {
	if !s.nativeUsageMode() || candidate == nil || s.lastConfig == nil || s.kernelLife == nil {
		return false
	}
	applied := s.kernelLife.Applied().Config
	if applied == nil || candidate.ServerPort < 1 || candidate.ServerPort > 65535 {
		return false
	}
	portOnly := *candidate
	portOnly.ServerPort = applied.ServerPort
	before, beforeErr := json.Marshal(applied)
	after, afterErr := json.Marshal(&portOnly)
	if beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
		return false
	}
	if err := nativeUsageConfig(candidate); err != nil {
		return false
	}
	if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), candidate, s.certs.TLSCert()); err != nil {
		return false
	}
	if err := s.nativeConfigAuthority(ctx, candidate); err != nil {
		s.refuseAuthorization(err)
		return true
	}
	if computeConfigHash(candidate) == s.appliedConfigHash && !s.pendingCertRenewal {
		if s.lastConfigHash != s.appliedConfigHash || s.desiredDirty || s.configRejected {
			s.desiredGeneration++
			s.acceptDesiredConfig(ctx, candidate)
			if s.pendingCertRenewal {
				return false
			}
			s.confirmAppliedState(candidate, s.users.Users())
		}
		return true
	}
	// Certificate renewal and any other desired configuration need the existing
	// complete reconciliation path, not this port-only transition.
	if s.pendingCertRenewal {
		return false
	}
	runtime := s.nativeUsage
	collector, meter := runtime.collector.Load(), runtime.active.Load()
	digest := s.authorization.Current().Digest
	s.authorizationAdmissionMu.Lock()
	deadline := s.authorizationDeadline
	s.authorizationAdmissionMu.Unlock()
	s.desiredGeneration++
	s.acceptDesiredConfig(ctx, candidate)
	if s.pendingCertRenewal {
		return false
	}
	if err := s.reloadKernelObserved(candidate, s.users.Users()); err != nil {
		s.markApplicationPending("KERNEL_RELOAD_FAILED")
		if authorityErr := s.nativeConfigAuthority(ctx, candidate); authorityErr != nil {
			s.refuseAuthorization(authorityErr)
		}
		return true
	}
	if err := s.nativeConfigAuthority(ctx, candidate); err != nil {
		s.refuseAuthorization(err)
		return true
	}
	s.authorizationAdmissionMu.Lock()
	sameDeadline := s.authorizationDeadline.Equal(deadline)
	s.authorizationAdmissionMu.Unlock()
	if s.nativeUsage != runtime || runtime.collector.Load() != collector || runtime.active.Load() != meter ||
		s.authorization.Current().Digest != digest || !sameDeadline {
		s.refuseAuthorization(errors.New("NATIVE_CONFIG_OWNER_CHANGED"))
		return true
	}
	s.confirmAppliedState(candidate, s.users.Users())
	return true
}

func (s *Service) nativeConfigAuthority(ctx context.Context, candidate *model.NodeSpec) error {
	if ctx.Err() != nil || s.authorization == nil || s.authorityTerminal(ctx) || !s.authorizationValid() || s.authorization.Check(time.Now()) != nil || !s.kernel.IsRunning() {
		return errors.New("NATIVE_CONFIG_AUTHORITY_UNAVAILABLE")
	}
	snapshot := s.authorization.Current()
	if snapshot == nil || snapshot.Payload.UsageV2 == nil || authorization.ValidateProtocol(snapshot, candidate.Protocol) != nil ||
		!s.signedUsersAllowed(s.users.Users()) {
		return errors.New("NATIVE_CONFIG_AUTHORITY_MISMATCH")
	}
	runtime := s.nativeUsage
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	collector := runtime.collector.Load()
	if runtime.failed.Load() || runtime.refreshNeeded.Load() || runtime.blockedRevision == runtime.revision || collector == nil || collector.Unknown() ||
		runtime.active.Load() == nil || runtime.revision != snapshot.Payload.Revision || !reflect.DeepEqual(runtime.session, *snapshot.Payload.UsageV2) {
		return errors.New("NATIVE_CONFIG_METER_UNAVAILABLE")
	}
	return nil
}
