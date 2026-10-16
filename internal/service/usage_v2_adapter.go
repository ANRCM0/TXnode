package service

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel/singbox"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

var errUsageV2 = errors.New("USAGE_V2_MODE_STOPPED")
var usageV2ProcessOwner usagebucket.ProcessOwner

type usageV2Kernel interface {
	SetBoundedUsageTracker(*singbox.ConnTracker) bool
	FlushBoundedUsage() (*usagev2.Submission, error)
	CheckBoundedUsage() error
	StopBoundedUsageTraffic()
}
type usageV2TransportSetup interface{ PrepareIsolatedUsageV2(string) error }

type isolatedUsageRuntime struct {
	kernel        usageV2Kernel
	tracker       *singbox.ConnTracker
	journal       *usageinterval.Journal
	reporter      *usagev2.Reporter
	done          chan struct{}
	cancel        context.CancelFunc
	stop          sync.Once
	failure       chan error
	expires       time.Time
	workerStarted bool
}

func (s *Service) usageMode() bool        { return s != nil && s.usageV2 != nil }
func (s *Service) meteredUsageMode() bool { return s.usageMode() || s.nativeUsageMode() }
func (s *Service) preflightUsageV2() error {
	if s.cfg == nil || !s.cfg.UsageV2.Enabled {
		return nil
	}
	if s.cfg.ValidateUsageV2() != nil {
		return errUsageV2
	}
	if s.nativeUsageConfigured() {
		prepare, ok := s.source.(interface{ PrepareNativeUsageV2(string) error })
		if !ok || prepare.PrepareNativeUsageV2(s.cfg.UsageV2.CAFile) != nil {
			return errUsageV2
		}
		return nil
	}
	prepare, supported := s.source.(usageV2TransportSetup)
	if !supported {
		return errUsageV2
	}
	owner := s.usageOwner
	if owner == nil {
		owner = &usageV2ProcessOwner
	}
	if !owner.Claim() {
		return errUsageV2
	}
	if prepare.PrepareIsolatedUsageV2(s.cfg.UsageV2.CAFile) != nil {
		return errUsageV2
	}
	return nil
}
func (s *Service) initUsageV2(ctx context.Context, b controlplane.Bootstrap) error {
	if !s.cfg.UsageV2.Enabled {
		return nil
	}
	if s.nativeUsageConfigured() {
		return s.initNativeUsage(ctx, b)
	}
	if b.UsageV2Session == nil || b.UsageV2Transport == nil || !b.UsageV2NativeHTTP || b.Push != nil || b.Mailbox != nil || len(b.Users) == 0 {
		return errUsageV2
	}
	k, supported := s.kernel.(usageV2Kernel)
	if !supported || s.kernel.IsRunning() || s.tracker == nil || !s.tracker.EmptyForUsageHandoff() || !s.reporter.EmptyForUsageHandoff() {
		return errUsageV2
	}
	traffic, alive, count, err := s.kernel.GetUserTraffic(ctx)
	if err != nil || count != 0 || len(alive) != 0 {
		return errUsageV2
	}
	for _, v := range traffic {
		if v[0] != 0 || v[1] != 0 {
			return errUsageV2
		}
	}
	if usagev2.CheckHandoff(s.legacyPendingPath, true) != nil {
		return errUsageV2
	}
	session := *b.UsageV2Session
	users := make(map[string]int, len(b.Users))
	for _, user := range b.Users {
		if user.UUID == "" || user.ID <= 0 || user.ID > 2147483647 || users[user.UUID] != 0 {
			return errUsageV2
		}
		users[user.UUID] = user.ID
	}
	spool, err := usagev2.OpenSpool(filepath.Join(s.cfg.UsageV2.Directory, "spool"), 0)
	if err != nil {
		return errUsageV2
	}
	journal, err := usageinterval.OpenJournal(filepath.Join(s.cfg.UsageV2.Directory, "journal"), session, spool)
	if err != nil {
		spool.Close()
		return errUsageV2
	}
	tracker, err := singbox.NewConnTrackerWithBoundedUsage(session, users, journal)
	if err != nil || !tracker.EnableEnforcingBounded() {
		journal.Close()
		spool.Close()
		return errUsageV2
	}
	reporter, err := usagev2.NewReporter(session, spool, b.UsageV2Transport)
	if err != nil {
		tracker.CloseBoundedUsage()
		journal.Close()
		spool.Close()
		return errUsageV2
	}
	expires := time.Now().Add(time.Hour)
	for _, grant := range session.Grants {
		end := time.Unix(grant.LeaseExpiresAt, 0)
		if end.Before(expires) {
			expires = end
		}
	}
	if !time.Now().Before(expires) || !k.SetBoundedUsageTracker(tracker) {
		tracker.CloseBoundedUsage()
		journal.Close()
		reporter.Close()
		return errUsageV2
	}
	s.usageV2 = &isolatedUsageRuntime{kernel: k, tracker: tracker, journal: journal, reporter: reporter, done: make(chan struct{}), failure: make(chan error, 1), expires: expires}
	return nil
}

func (s *Service) startUsageV2Worker() {
	if s.nativeUsageMode() {
		s.startNativeUsageWorker()
		return
	}
	if !s.usageMode() {
		return
	}
	runtime := s.usageV2
	ctx, cancel := context.WithCancel(context.Background())
	runtime.cancel = cancel
	runtime.workerStarted = true
	go func() {
		defer close(runtime.done)
		defer runtime.reporter.Close()
		defer runtime.journal.Close()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// Only a previously frozen claim may still commit after stop. Unknown
				// unsealed tail cannot become a new successful shutdown interval.
				_, _ = runtime.kernel.FlushBoundedUsage()
				final, stop := context.WithTimeout(context.Background(), time.Second)
				_ = runtime.reporter.Deliver(final)
				stop()
				return
			case <-ticker.C:
				if runtime.kernel.CheckBoundedUsage() != nil {
					s.failUsageV2()
					return
				}
				_, err := runtime.kernel.FlushBoundedUsage()
				if err != nil && err != usageinterval.ErrPending {
					s.failUsageV2()
					return
				}
				delivery, stop := context.WithTimeout(ctx, 2*time.Second)
				err = runtime.reporter.Deliver(delivery)
				stop()
				if err != nil {
					s.failUsageV2()
					return
				}
			}
		}
	}()
}

func (s *Service) failUsageV2() {
	if s.nativeUsageMode() {
		s.failNativeUsage()
		return
	}
	if !s.usageMode() {
		return
	}
	runtime := s.usageV2
	runtime.stop.Do(func() {
		// This closes active mode I/O without waiting for the journal worker.
		runtime.tracker.StopBoundedUsageTraffic()
		select {
		case runtime.failure <- errUsageV2:
		default:
		}
	})
}
func (s *Service) closeUsageV2() {
	if s.nativeUsageMode() {
		s.closeNativeUsage()
		return
	}
	if !s.usageMode() {
		return
	}
	runtime := s.usageV2
	runtime.tracker.StopBoundedUsageTraffic()
	runtime.tracker.CloseBoundedUsage()
	if !runtime.workerStarted {
		runtime.journal.Close()
		runtime.reporter.Close()
		return
	}
	runtime.cancel()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-runtime.done:
	case <-timer.C:
		// Original worker retains FD/flock; permanent owner is never reused.
	}
}
func (s *Service) usageFailureChannel() <-chan error {
	if s.nativeUsageMode() {
		return s.nativeUsage.failure
	}
	if !s.usageMode() {
		return nil
	}
	return s.usageV2.failure
}
func (s *Service) usageLeaseChannel() (<-chan time.Time, func()) {
	if !s.usageMode() {
		return nil, func() {}
	}
	timer := time.NewTimer(time.Until(s.usageV2.expires))
	return timer.C, func() { timer.Stop() }
}
