package service

import (
	"context"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/certcoord"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/nodesync"
	"github.com/ANRCM0/TX-Node/internal/pushsync"
)

type noPollControlPlane struct{}

func (noPollControlPlane) Initial(
	context.Context,
	func() map[string]interface{},
	chan<- controlplane.Event,
	chan<- controlplane.StatusChange,
) (controlplane.Bootstrap, error) {
	return controlplane.Bootstrap{}, nil
}
func (noPollControlPlane) Poll(context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{}, nil
}
func (noPollControlPlane) Discover(
	context.Context,
	func() map[string]interface{},
	chan<- controlplane.Event,
	chan<- controlplane.StatusChange,
) (controlplane.PushClient, error) {
	return nil, nil
}
func (noPollControlPlane) Metrics() controlplane.APIMetrics { return controlplane.APIMetrics{} }
func (noPollControlPlane) SupportsPolling() bool            { return false }
func (noPollControlPlane) SupportsDiscovery() bool          { return false }
func (noPollControlPlane) Report(controlplane.ReportPayload) error {
	return nil
}
func (noPollControlPlane) ReportDevices(controlplane.PushClient, map[int][]string) {}
func (noPollControlPlane) SupportsReporting() bool                                 { return false }
func (noPollControlPlane) SupportsDeviceReports() bool                             { return false }

func TestHandlePushStatusKeepsTransportStateOutOfService(t *testing.T) {
	cp := noPollControlPlane{}
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.source = cp
	s.sink = cp
	s.cfg = &config.Config{}
	s.certs = certcoord.New(config.CertConfig{})
	s.syncer = nodesync.New(cp)
	s.push = pushsync.New(cp)

	s.handlePushStatus(context.Background(), controlplane.StatusChange{
		Connected:   false,
		NeedsResync: true,
	})

	if k.clearDevicesCalls != 1 {
		t.Fatalf("ClearGlobalDevices calls = %d, want 1", k.clearDevicesCalls)
	}
	if _, connected := s.push.State(); connected {
		t.Fatal("disconnect observation must not report connected push state")
	}
}

func TestHandlePushStatusReconnectDoesNotClearDevices(t *testing.T) {
	cp := noPollControlPlane{}
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.source = cp
	s.sink = cp
	s.cfg = &config.Config{}
	s.certs = certcoord.New(config.CertConfig{})
	s.syncer = nodesync.New(cp)
	s.push = pushsync.New(cp)

	s.handlePushStatus(context.Background(), controlplane.StatusChange{Connected: true})

	if k.clearDevicesCalls != 0 {
		t.Fatalf("ClearGlobalDevices calls = %d, want 0", k.clearDevicesCalls)
	}
}
