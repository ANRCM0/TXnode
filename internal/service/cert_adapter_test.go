package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/certcoord"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

type serviceCertBackend struct {
	reconfigureErr error
	reconfigured   bool
	reconfigureCfg config.CertConfig
	changed        bool
	hasCert        bool
}

func (b *serviceCertBackend) Start(context.Context) error { return nil }
func (b *serviceCertBackend) Stop()                       {}
func (b *serviceCertBackend) Reconfigure(_ context.Context, cfg config.CertConfig) (bool, error) {
	b.reconfigured = true
	b.reconfigureCfg = cfg
	return b.changed, b.reconfigureErr
}
func (b *serviceCertBackend) TLSCert() kernel.TLSCert { return kernel.TLSCert{} }
func (b *serviceCertBackend) HasCert() bool           { return b.hasCert }
func (b *serviceCertBackend) CertRenewed() bool       { return false }

func TestApplyRemoteOverridesDelegatesModernCertConfig(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	backend := &serviceCertBackend{changed: true, hasCert: true}
	s.certs = certcoord.NewWithBackend(backend)
	s.cfg = &config.Config{
		Kernel: config.KernelConfig{LogLevel: "warn"},
		Cert: config.CertConfig{
			CertDir:  "/var/lib/tx-node/cert",
			CertMode: "none",
		},
	}

	changed := s.applyRemoteOverrides(context.Background(), &model.NodeSpec{
		KernelLogLevel: "error",
		CertConfig: &config.CertConfig{
			CertMode: "self",
			Domain:   "node.example.com",
			CertDir:  "/panel/path",
		},
	})

	if !changed || !backend.reconfigured {
		t.Fatal("modern cert config was not delegated")
	}
	if s.cfg.Kernel.LogLevel != "error" {
		t.Fatalf("kernel log override was lost: %q", s.cfg.Kernel.LogLevel)
	}
	if s.cfg.Cert.CertMode != "self" || s.cfg.Cert.Domain != "node.example.com" {
		t.Fatalf("runtime cert config not accepted: %#v", s.cfg.Cert)
	}
	if s.cfg.Cert.CertDir != "/var/lib/tx-node/cert" || backend.reconfigureCfg.CertDir != "/var/lib/tx-node/cert" {
		t.Fatalf("local cert dir was not preserved: %#v", s.cfg.Cert)
	}
}

func TestApplyRemoteOverridesKeepsCurrentCertConfigOnBackendFailure(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	backend := &serviceCertBackend{reconfigureErr: errors.New("invalid certificate")}
	s.certs = certcoord.NewWithBackend(backend)
	s.cfg = &config.Config{
		Cert: config.CertConfig{
			CertDir:  "/cert",
			CertMode: "file",
			Domain:   "old.example.com",
		},
	}

	changed := s.applyRemoteOverrides(context.Background(), &model.NodeSpec{
		CertConfig: &config.CertConfig{
			CertMode: "self",
			Domain:   "new.example.com",
		},
	})

	if changed {
		t.Fatal("failed reconfigure must not report material change")
	}
	if s.cfg.Cert.CertMode != "file" || s.cfg.Cert.Domain != "old.example.com" {
		t.Fatalf("failed reconfigure changed current cert config: %#v", s.cfg.Cert)
	}
}

func TestApplyRemoteOverridesPreservesLegacyCompatibilityWithoutReconfigure(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	backend := &serviceCertBackend{}
	s.certs = certcoord.NewWithBackend(backend)
	s.cfg = &config.Config{
		Cert: config.CertConfig{
			CertDir: "/cert",
			Domain:  "old.example.com",
		},
	}

	changed := s.applyRemoteOverrides(context.Background(), &model.NodeSpec{
		AutoTLS: true,
		Domain:  "legacy.example.com",
	})

	if changed || backend.reconfigured {
		t.Fatal("legacy fields must preserve old no-reconfigure behavior")
	}
	if !s.cfg.Cert.AutoTLS || s.cfg.Cert.Domain != "legacy.example.com" {
		t.Fatalf("legacy compatibility fields were not retained: %#v", s.cfg.Cert)
	}
}
