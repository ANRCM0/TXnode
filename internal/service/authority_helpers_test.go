package service

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// liveProtocolUUID is the synthetic account used by the service fixtures.
const liveProtocolUUID = "00112233-4455-6677-8899-aabbccddeeff"

// authorityTestPlane is the minimal ControlPlane used by authorization tests.
type authorityTestPlane struct {
	mu           sync.Mutex
	bootstrap    controlplane.Bootstrap
	pollErr      error
	reportErr    error
	reports      []controlplane.ReportPayload
	initialCalls int
}

func (p *authorityTestPlane) Initial(context.Context, func() map[string]interface{}, chan<- controlplane.Event, chan<- controlplane.StatusChange) (controlplane.Bootstrap, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initialCalls++
	return p.bootstrap, nil
}

func (p *authorityTestPlane) Poll(context.Context) (controlplane.Snapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return controlplane.Snapshot{Config: p.bootstrap.Config, Users: p.bootstrap.Users}, p.pollErr
}

func (p *authorityTestPlane) Discover(context.Context, func() map[string]interface{}, chan<- controlplane.Event, chan<- controlplane.StatusChange) (controlplane.PushClient, error) {
	return nil, nil
}

func (p *authorityTestPlane) Metrics() controlplane.APIMetrics { return controlplane.APIMetrics{} }

func (p *authorityTestPlane) SupportsPolling() bool { return true }

func (p *authorityTestPlane) SupportsDiscovery() bool { return false }

func (p *authorityTestPlane) Report(b controlplane.ReportPayload) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reports = append(p.reports, b)
	return p.reportErr
}

func (p *authorityTestPlane) ReportDevices(controlplane.PushClient, map[int][]string) {}

func (p *authorityTestPlane) SupportsReporting() bool { return true }

func (p *authorityTestPlane) SupportsDeviceReports() bool { return false }

func authorityService(t *testing.T, p *authorityTestPlane) *Service {
	t.Helper()
	cfg := &config.Config{
		InstanceID: "native-denial-fixture",
		Panel:      config.PanelConfig{Provider: "txboard", URL: "http://127.0.0.1:1", NodeID: 42, Token: "synthetic"},
		Kernel:     config.KernelConfig{Type: "txnode", ConfigDir: t.TempDir(), GeoDataDir: t.TempDir(), LogLevel: "error"},
		Dataplane:  config.DataplaneConfig{TrustedProxies: "private", MaxFresh: 4096, HandshakeTimeout: 10},
		Cert:       config.CertConfig{CertMode: "none"},
		Node:       config.NodeConfig{TrackInterval: 60, PushInterval: 60, PullInterval: 1, DeviceReportInterval: 60},
		WS:         config.WSConfig{DiscoveryInterval: 60},
	}
	return NewWithControlPlane(cfg, p)
}

func authorityPort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func authorityBootstrap(port int) controlplane.Bootstrap {
	return controlplane.Bootstrap{
		Config: &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port},
		Users:  []model.UserSpec{{ID: 7, UUID: liveProtocolUUID}},
	}
}

func authorityWaitListener(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 20*time.Millisecond)
		if e == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("real listener not opened")
}
