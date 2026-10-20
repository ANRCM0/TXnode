package geoassets

import (
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/kernel/geodata"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// Backend is the geo-data acquisition runtime. The default backend delegates to
// kernel/geodata and owns the download URLs, filesystem writes and retry/error
// behavior.
type Backend interface {
	Ensure(dir string, needGeoIP, needGeoSite bool) error
}

type defaultBackend struct{}

func (defaultBackend) Ensure(dir string, needGeoIP, needGeoSite bool) error {
	return geodata.Ensure(dir, needGeoIP, needGeoSite)
}

// Coordinator decides whether the native kernel needs geoip.dat / geosite.dat
// and asks the backend to acquire them. The data plane itself only reads files.
type Coordinator struct {
	backend Backend
}

func New() *Coordinator {
	return NewWithBackend(defaultBackend{})
}

func NewWithBackend(backend Backend) *Coordinator {
	if backend == nil {
		backend = defaultBackend{}
	}
	return &Coordinator{backend: backend}
}

// PrepareTxnode downloads the v2ray-format databases when any panel or custom
// route references geoip:/geosite:. Missing files are not fatal: the kernel logs
// the lookup failure and keeps running with the rules it could compile.
func (c *Coordinator) PrepareTxnode(cfg config.KernelConfig, spec *model.NodeSpec) error {
	if c == nil || spec == nil {
		return nil
	}
	needIP := kernel.NeedsGeoIP(spec.Routes) || kernel.NeedsGeoIPRules(spec.CustomRouteRules)
	needSite := kernel.NeedsGeoSite(spec.Routes) || kernel.NeedsGeoSiteRules(spec.CustomRouteRules)
	if !needIP && !needSite {
		return nil
	}
	return c.backend.Ensure(cfg.GeoDataDir, needIP, needSite)
}
