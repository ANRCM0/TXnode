package service

import (
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
)

// This reuses the denial checkpoint's close-before-meter durable boundary.
// The local successful intent is removed only when that complete boundary succeeds.
func (s *Service) stopForRuntimeCheckpoint() error {
	if s.cfg.Panel.Provider != "txboard" || s.cfg.IsStandalone() || s.cfg.UsageV2.Enabled || s.cfg.UsageObserver.Enabled || s.cfg.UsageEventStore.Enabled {
		s.stopKernelObserved(false)
		return errors.New("NODE_RUNTIME_CHECKPOINT_UNSUPPORTED")
	}
	err := s.stopForAuthorityDenial(controlerror.RuntimeCheckpoint)
	if s.reporter != nil {
		s.reporter.JoinCheckpoint()
	}
	if err == controlerror.RuntimeCheckpoint {
		return nil
	}
	// errors.Join always wraps the intent; inspect its other components rather
	// than using errors.Is, which would also swallow persistence/meter failures.
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var failures []error
		for _, cause := range joined.Unwrap() {
			if cause != controlerror.RuntimeCheckpoint {
				failures = append(failures, cause)
			}
		}
		return errors.Join(failures...)
	}
	return err
}
