package service

import (
	"context"
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/reporting"
)

// A native denial or authenticated Machine membership withdrawal stops all I/O
// before sampling the final meter. The original typed cause stays distinguishable.
// Checkpoint's prepare callback executes only after report admission is closed.
func (s *Service) stopForAuthorityDenial(denial error) error {
	if s.nativeUsageMode() {
		s.stopNativeUsageIO()
		s.stopKernelObserved(false)
		return denial
	}
	if s.usageMode() {
		s.failUsageV2()
		s.stopKernelObserved(false)
		return errors.Join(denial, errUsageV2)
	}
	if s.reporter == nil {
		s.stopKernelObserved(false)
		return errors.Join(denial, errors.New("NATIVE_AUTHORITY_CHECKPOINT_FAILED"))
	}
	var meterErr error
	prepared := false
	err := s.reporter.CheckpointTerminal(func() reporting.Batch {
		prepared = true
		s.stopKernelObserved(false)
		traffic, alive, count, e := s.kernel.GetUserTraffic(context.Background())
		if e != nil {
			meterErr = errors.New("NATIVE_AUTHORITY_FINAL_METER_FAILED")
		} else {
			s.tracker.Process(traffic, alive, count)
		}
		return s.prepareReportBatch()
	}, func(batch reporting.Batch, _ error) {
		s.restoreReportBatch(batch)
	})
	// A pre-existing/corrupt slot or persistence refusal cannot keep admission open.
	if !prepared {
		s.stopKernelObserved(false)
	}
	if err != nil {
		return errors.Join(denial, meterErr, errors.New("NATIVE_AUTHORITY_CHECKPOINT_FAILED"))
	}
	return errors.Join(denial, meterErr)
}

// All direct application helpers share the same typed boundary as Run. Queued
// callbacks cannot bypass a successful native membership withdrawal.
func (s *Service) authorityTerminal(ctx context.Context) bool {
	if s == nil {
		return false
	}
	if s.syncer != nil && controlerror.IsAuthoritativeStopCause(s.syncer.Terminal()) {
		return true
	}
	return controlerror.IsAuthoritativeStopCause(context.Cause(ctx))
}
