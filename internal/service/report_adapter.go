package service

import (
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/monitor"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/reporting"
)

func (s *Service) prepareReportBatch() reporting.Batch {
	var traffic map[int][2]int64
	if !s.usageMode() {
		traffic = s.tracker.FlushTraffic()
	}
	aliveIPs := s.tracker.FlushAliveIPs()
	online := s.tracker.CurrentOnline()
	status := monitor.Collect()
	metrics := s.buildMetrics(status)
	metrics["kernel_status"] = s.kernel.IsRunning()

	return reporting.Batch{
		Payload: controlplane.ReportPayload{
			Traffic: traffic,
			Alive:   aliveIPs,
			Online:  online,
			CPU:     status.CPU,
			Mem:     [2]uint64{status.MemTotal, status.MemUsed},
			Swap:    [2]uint64{status.SwapTotal, status.SwapUsed},
			Disk:    [2]uint64{status.DiskTotal, status.DiskUsed},
			Metrics: metrics,
		},
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
			if len(batch.Payload.Traffic) > 0 {
				s.tracker.RestoreTraffic(batch.Payload.Traffic)
			}
			if len(batch.Payload.Alive) > 0 {
				s.tracker.RestoreAliveIPs(batch.Payload.Alive)
			}
		},
		func(batch reporting.Batch) {
			nlog.ReportPushed(batch.TrafficCount, batch.OnlineCount)
		},
	)
}

// pushReportSync is used only during shutdown to preserve the existing final
// synchronous report behavior. Like the previous implementation it logs a
// failure but does not restore the shutdown snapshot.
func (s *Service) pushReportSync() {
	if s == nil || s.reporter == nil {
		return
	}
	if err := s.reporter.PushSync(s.prepareReportBatch); err != nil {
		nlog.Core().Warn("failed to push final report", "error", err)
	}
}
