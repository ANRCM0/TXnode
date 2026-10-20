package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	"github.com/ANRCM0/TX-Node/internal/tracker"
)

type reportTestControlPlane struct {
	mu      sync.Mutex
	err     error
	calls   int
	payload controlplane.ReportPayload
}

func (p *reportTestControlPlane) Initial(
	context.Context,
	func() map[string]interface{},
	chan<- controlplane.Event,
	chan<- controlplane.StatusChange,
) (controlplane.Bootstrap, error) {
	return controlplane.Bootstrap{}, nil
}
func (p *reportTestControlPlane) Poll(context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{}, nil
}
func (p *reportTestControlPlane) Discover(
	context.Context,
	func() map[string]interface{},
	chan<- controlplane.Event,
	chan<- controlplane.StatusChange,
) (controlplane.PushClient, error) {
	return nil, nil
}
func (p *reportTestControlPlane) Metrics() controlplane.APIMetrics {
	return controlplane.APIMetrics{Success: 7, Failure: 2}
}
func (p *reportTestControlPlane) SupportsPolling() bool   { return false }
func (p *reportTestControlPlane) SupportsDiscovery() bool { return false }
func (p *reportTestControlPlane) Report(payload controlplane.ReportPayload) error {
	p.mu.Lock()
	p.calls++
	p.payload = payload
	err := p.err
	p.mu.Unlock()
	return err
}
func (p *reportTestControlPlane) ReportDevices(controlplane.PushClient, map[int][]string) {}
func (p *reportTestControlPlane) SupportsReporting() bool                                 { return true }
func (p *reportTestControlPlane) SupportsDeviceReports() bool                             { return false }

func (p *reportTestControlPlane) snapshot() (int, controlplane.ReportPayload) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, p.payload
}

func newReportingTestService(k *fakeKernel, cp *reportTestControlPlane) *Service {
	s := newTestService(k)
	s.cfg = &config.Config{}
	s.source = cp
	s.sink = cp
	s.tracker = tracker.New()
	s.reporter = reporting.New(cp)
	return s
}

func TestPrepareReportBatchBuildsExistingPayloadShape(t *testing.T) {
	cp := &reportTestControlPlane{}
	k := &fakeKernel{running: true}
	s := newReportingTestService(k, cp)

	s.tracker.Process(
		map[int][2]int64{1: [2]int64{100, 200}},
		map[int]map[string]bool{1: map[string]bool{"203.0.113.10": true}},
		1,
	)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "user-1"}}, srcBootstrap)

	batch := s.prepareReportBatch()
	if len(batch.Payload.Traffic) != 1 || batch.TrafficCount != 1 {
		t.Fatalf("unexpected traffic batch: %#v", batch)
	}
	if len(batch.Payload.Online) != 1 || batch.OnlineCount != 1 {
		t.Fatalf("unexpected online batch: %#v", batch)
	}
	if batch.Payload.Metrics["kernel_status"] != true {
		t.Fatalf("kernel status missing from metrics: %#v", batch.Payload.Metrics)
	}
	api, ok := batch.Payload.Metrics["api"].(map[string]interface{})
	if !ok || api["success"] != uint64(7) || api["failure"] != uint64(2) {
		t.Fatalf("API metrics changed shape: %#v", batch.Payload.Metrics["api"])
	}
}

func TestPushReportAsyncRetainsIdentifiedPayloadAfterAmbiguousFailure(t *testing.T) {
	cp := &reportTestControlPlane{err: errors.New("panel unavailable")}
	k := &fakeKernel{running: true}
	s := newReportingTestService(k, cp)

	s.tracker.Process(
		map[int][2]int64{1: [2]int64{100, 200}},
		map[int]map[string]bool{1: map[string]bool{"203.0.113.10": true}},
		1,
	)

	s.pushReportAsync()

	deadline := time.Now().Add(time.Second)
	for s.reporter.Active() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.reporter.Active() {
		t.Fatal("report did not finish")
	}
	if s.tracker.HasTraffic() {
		t.Fatal("ambiguous failure must not restore traffic into the accumulator")
	}
	calls, first := cp.snapshot()
	if calls != 1 || first.BatchID == "" || len(first.Traffic) != 1 {
		t.Fatalf("report failed to retain identified payload: calls=%d, payload=%#v", calls, first)
	}
	// First retry is skipped by bounded backoff.
	s.pushReportAsync()
	cp.mu.Lock()
	cp.err = nil
	cp.mu.Unlock()
	s.pushReportAsync()
	deadline = time.Now().Add(time.Second)
	for s.reporter.Active() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	calls, replay := cp.snapshot()
	if calls != 2 || replay.BatchID != first.BatchID || len(replay.Traffic) != 1 {
		t.Fatalf("retry did not reuse payload identity: calls=%d, old=%#v, new=%#v", calls, first, replay)
	}
}

func TestPushReportSyncPreservesShutdownDelivery(t *testing.T) {
	cp := &reportTestControlPlane{}
	k := &fakeKernel{running: true}
	s := newReportingTestService(k, cp)

	s.tracker.Process(
		map[int][2]int64{1: [2]int64{10, 20}},
		map[int]map[string]bool{},
		0,
	)
	s.pushReportSync()

	calls, payload := cp.snapshot()
	if calls != 1 {
		t.Fatalf("report calls = %d, want 1", calls)
	}
	if len(payload.Traffic) != 1 {
		t.Fatalf("shutdown report lost traffic: %#v", payload.Traffic)
	}
}
