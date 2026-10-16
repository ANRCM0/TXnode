package service

import (
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/monitor"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/reporting"
)

func (s *Service) prepareReportBatch() reporting.Batch {
	var traffic map[int][2]int64
	var segments []model.TrafficSegment
	if !s.meteredUsageMode() {
		traffic, segments = s.tracker.FlushBatch()
	}
	aliveIPs := s.tracker.FlushAliveIPs()
	online := s.tracker.CurrentOnline()
	status := monitor.Collect()
	metrics := s.buildMetrics(status)
	metrics["kernel_status"] = s.kernel.IsRunning()

	return reporting.Batch{
		Payload: controlplane.ReportPayload{
			Traffic: traffic, TrafficSegments: segments,
			Alive:   aliveIPs,
			Online:  online,
			CPU:     status.CPU,
			Mem:     [2]uint64{status.MemTotal, status.MemUsed},
			Swap:    [2]uint64{status.SwapTotal, status.SwapUsed},
			Disk:    [2]uint64{status.DiskTotal, status.DiskUsed},
			Metrics: metrics,
		},
		MoreTraffic:  !s.meteredUsageMode() && s.tracker.HasTraffic(),
		TrafficCount: len(traffic),
		OnlineCount:  len(online),
	}
}

// pushReportAsync delegates delivery mechanics to reporting.Controller while
// Service retains ownership of tracker flush/restore and runtime metrics.
func (s *Service) pushReportAsync() {
	if s == nil || s.reporter == nil {
		return
	}

	s.reporter.PushAsync(
		s.prepareReportBatch,
		func(batch reporting.Batch, err error) {
			nlog.Core().Warn("failed to push report", "error", err)
			s.restoreReportBatch(batch)
		},
		func(batch reporting.Batch) {
			nlog.ReportPushed(batch.TrafficCount, batch.OnlineCount)
		},
	)
}

// pushReportSync is used only during shutdown to preserve the existing final
// synchronous report behavior. Like the previous implementation it logs a
// failure but does not restore the shutdown snapshot.
func (s *Service) pushReportSync() error {
	if s == nil || s.reporter == nil {
		return nil
	}
	if !s.meteredUsageMode() && s.cfg != nil && s.cfg.Panel.Provider == "txboard" && s.tracker.HasPeriodAttribution() {
		// A graceful signed-period shutdown also closes/samples before final reports;
		// any failed delivery leaves all remaining chunks in one durable tail bundle.
		s.stopUncertainKernel()
		for {
			err := s.reporter.PushSyncRecoverable(s.prepareReportBatch, s.restoreUnsubmittedReport)
			if err != nil {
				nlog.Core().Warn("failed to push final report", "error", err)
				if e := s.reporter.CheckpointTerminal(s.prepareReportBatch, func(batch reporting.Batch, _ error) { s.restoreReportBatch(batch) }); e != nil {
					return errors.New("NATIVE_SHUTDOWN_CHECKPOINT_FAILED")
				}
				return nil
			}
			if !s.tracker.HasTraffic() {
				return nil
			}
		}
	}
	if err := s.reporter.PushSync(s.prepareReportBatch); err != nil {
		nlog.Core().Warn("failed to push final report", "error", err)
	}
	return nil
}

// A retained durable pending record is never duplicated into the accumulator:
// reporting clears Traffic/Segments together in its failure notice.
func (s *Service) restoreReportBatch(batch reporting.Batch) {
	if len(batch.Payload.Traffic) > 0 {
		s.tracker.RestoreBatch(batch.Payload.Traffic, batch.Payload.TrafficSegments)
	}
	if len(batch.Payload.Alive) > 0 {
		s.tracker.RestoreAliveIPs(batch.Payload.Alive)
	}
}

func (s *Service) restoreUnsubmittedReport(batch reporting.Batch, _ error) {
	s.restoreReportBatch(batch)
}
