package service

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

const nativeRenewalTimeout = 2 * time.Second

type nativeRenewalKernel interface {
	PauseNativeRenewal(usageinterval.Meter) (usageinterval.RenewalTicket, error)
}

// A new envelope may replace its lease and snapshot identifiers, but continuous
// I/O cannot carry changed credentials, rights, accounting periods, or policy.
func nativeRenewalEquivalent(current, next *authorization.Snapshot) bool {
	if current == nil || next == nil || current.Payload.UsageV2 == nil || next.Payload.UsageV2 == nil ||
		current.Payload.Provider == nil || next.Payload.Provider == nil || len(current.Users) == 0 ||
		!reflect.DeepEqual(current.Users, next.Users) || next.Payload.ExpiresAt < current.Payload.ExpiresAt {
		return false
	}
	before, after := current.Payload, next.Payload
	before.Revision, after.Revision = "", ""
	before.IssuedAt, after.IssuedAt = 0, 0
	before.NotBefore, after.NotBefore = 0, 0
	before.ExpiresAt, after.ExpiresAt = 0, 0
	left, right := *before.Provider, *after.Provider
	left.Subjects = append([]credentialdelivery.Subject{}, left.Subjects...)
	right.Subjects = append([]credentialdelivery.Subject{}, right.Subjects...)
	if len(left.Subjects) != len(right.Subjects) {
		return false
	}
	for i := range left.Subjects {
		if right.Subjects[i].CredentialExpiresAt < left.Subjects[i].CredentialExpiresAt {
			return false
		}
		left.Subjects[i].CredentialExpiresAt, right.Subjects[i].CredentialExpiresAt = 0, 0
	}
	before.Provider, after.Provider = &left, &right
	leftSession, rightSession := *before.UsageV2, *after.UsageV2
	leftSession.IssuedAt, rightSession.IssuedAt = 0, 0
	leftSession.Grants = append([]usagev2.Grant{}, leftSession.Grants...)
	rightSession.Grants = append([]usagev2.Grant{}, rightSession.Grants...)
	if len(leftSession.Grants) != len(rightSession.Grants) {
		return false
	}
	for i := range leftSession.Grants {
		leftSession.Grants[i].AuthSnapshotID, rightSession.Grants[i].AuthSnapshotID = "", ""
		leftSession.Grants[i].IssuedAt, rightSession.Grants[i].IssuedAt = 0, 0
		leftSession.Grants[i].LeaseExpiresAt, rightSession.Grants[i].LeaseExpiresAt = 0, 0
	}
	before.UsageV2, after.UsageV2 = &leftSession, &rightSession
	return reflect.DeepEqual(before, after)
}

// Once the old collector is sealed, any failure is terminal. The private
// authority high-water and the old immutable batches are never rolled back.
func (s *Service) renewNativeAuthorization(parent context.Context, candidate *authorization.Snapshot, users []model.UserSpec, node *model.NodeSpec) error {
	kernel, ok := s.kernel.(nativeRenewalKernel)
	if !ok {
		return errNativeUsage
	}
	runtime := s.nativeUsage
	oldCollector := runtime.collector.Load()
	oldMeter, ok := runtime.active.Load().(usageinterval.Meter)
	if !ok || oldMeter == nil || oldCollector == nil || s.nativeConfigAuthority(parent, node) != nil {
		return errNativeUsage
	}
	s.authorizationAdmissionMu.Lock()
	oldDeadline := s.authorizationDeadline
	s.authorizationAdmissionMu.Unlock()
	deadline := minTime(time.Now().Add(nativeRenewalTimeout), oldDeadline, time.Unix(candidate.Payload.ExpiresAt, 0))
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	ticket, err := kernel.PauseNativeRenewal(oldMeter)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			ticket.Abort()
		}
	}()
	if err := ticket.WaitQuiescent(ctx); err != nil {
		return err
	}
	boundary, err := ticket.Retire(ctx)
	if err != nil {
		return err
	}
	if ctx.Err() != nil || s.authorityTerminal(ctx) || !s.authorizationValid() ||
		runtime.failed.Load() || runtime.refreshNeeded.Load() {
		return errNativeUsage
	}
	accepted, err := s.authorization.AcceptVerifiedForProtocol(candidate, node.Protocol, time.Now())
	if err != nil {
		return err
	}
	collector, err := s.newNativeCollector(ctx, accepted)
	if err != nil {
		return err
	}
	if collector.ReadyAt().Before(boundary) {
		collector.Fail()
		return errors.New("NATIVE_RENEWAL_BOUNDARY_MISMATCH")
	}
	newDeadline := s.authorization.Expiry()
	// The watchdog uses the first lock; quarantine uses the second and the
	// irreversible meter latch. No network, signing or persistence runs here.
	s.authorizationAdmissionMu.Lock()
	runtime.admissionMu.Lock()
	now := time.Now()
	if ctx.Err() != nil || s.nativeUsage != runtime || runtime.failed.Load() || runtime.refreshNeeded.Load() ||
		runtime.collector.Load() != oldCollector || runtime.active.Load() != oldMeter ||
		s.authorizationExpired.Load() || !s.authorizationDeadline.Equal(oldDeadline) ||
		!now.Before(oldDeadline) || !now.Before(newDeadline) {
		runtime.admissionMu.Unlock()
		s.authorizationAdmissionMu.Unlock()
		collector.Fail()
		return errNativeUsage
	}
	if err := ticket.Commit(collector); err != nil {
		runtime.admissionMu.Unlock()
		s.authorizationAdmissionMu.Unlock()
		collector.Fail()
		return err
	}
	runtime.collector.Store(collector)
	runtime.session = *accepted.Payload.UsageV2
	runtime.session.Grants = append([]usagev2.Grant{}, accepted.Payload.UsageV2.Grants...)
	runtime.revision = accepted.Payload.Revision
	s.authorizationDeadline = newDeadline
	if s.authorizationWatchdog != nil {
		s.authorizationWatchdog.Stop()
	}
	s.authorizationWatchdog = time.AfterFunc(time.Until(newDeadline), s.expireAuthorizationAdmission)
	err = ticket.Resume()
	runtime.admissionMu.Unlock()
	s.authorizationAdmissionMu.Unlock()
	if err != nil {
		return err
	}
	committed = true
	s.resetAuthorizationTimer()
	s.updateUserState(users, srcPollFull)
	s.confirmAppliedState(node, users)
	return nil
}

func minTime(first time.Time, rest ...time.Time) time.Time {
	for _, candidate := range rest {
		if candidate.Before(first) {
			first = candidate
		}
	}
	return first
}
