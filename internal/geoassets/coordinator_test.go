package geoassets

import (
	"errors"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/model"
)

type fakeBackend struct {
	called   bool
	dir      string
	needIP   bool
	needSite bool
	err      error
}

func (f *fakeBackend) Ensure(dir string, needGeoIP, needGeoSite bool) error {
	f.called, f.dir, f.needIP, f.needSite = true, dir, needGeoIP, needGeoSite
	return f.err
}

func TestPrepareTxnodeSkipsWhenRoutesDoNotNeedGeoAssets(t *testing.T) {
	backend := &fakeBackend{}
	c := NewWithBackend(backend)
	spec := &model.NodeSpec{Routes: []model.RouteRule{{Match: []string{"example.com"}}}}
	if err := c.PrepareTxnode(config.KernelConfig{GeoDataDir: "/tmp/geo"}, spec); err != nil {
		t.Fatal(err)
	}
	if backend.called {
		t.Fatal("backend called without geo terms")
	}
}

func TestPrepareTxnodeRequestsBothDatabases(t *testing.T) {
	backend := &fakeBackend{}
	c := NewWithBackend(backend)
	spec := &model.NodeSpec{Routes: []model.RouteRule{{Match: []string{"geosite:cn", "geoip:cn"}}}}
	if err := c.PrepareTxnode(config.KernelConfig{GeoDataDir: "/var/lib/tx-node/geo"}, spec); err != nil {
		t.Fatal(err)
	}
	if !backend.called || backend.dir != "/var/lib/tx-node/geo" || !backend.needIP || !backend.needSite {
		t.Fatalf("backend call: %+v", backend)
	}
}

func TestPrepareTxnodeSeesStructuredRoutes(t *testing.T) {
	backend := &fakeBackend{}
	c := NewWithBackend(backend)
	spec := &model.NodeSpec{CustomRouteRules: []model.CustomRouteRule{{
		Match: model.RouteMatch{IPCIDRs: []string{"geoip:private"}},
	}}}
	if err := c.PrepareTxnode(config.KernelConfig{GeoDataDir: "/geo"}, spec); err != nil {
		t.Fatal(err)
	}
	if !backend.needIP || backend.needSite {
		t.Fatalf("needIP=%v needSite=%v", backend.needIP, backend.needSite)
	}
}

func TestPrepareTxnodeReturnsBackendError(t *testing.T) {
	backend := &fakeBackend{err: errors.New("download failed")}
	c := NewWithBackend(backend)
	spec := &model.NodeSpec{Routes: []model.RouteRule{{Match: []string{"geoip:cn"}}}}
	if err := c.PrepareTxnode(config.KernelConfig{GeoDataDir: "/geo"}, spec); err == nil {
		t.Fatal("backend error swallowed")
	}
}
