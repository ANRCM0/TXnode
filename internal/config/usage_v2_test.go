package config

import (
	"path/filepath"
	"testing"
)

func TestUsageV2StrictIsolatedConfigurationDefaultAndNoInheritance(t *testing.T) {
	base := Config{Panel: PanelConfig{Provider: "txboard", URL: "https://127.0.0.1:18443", NodeID: 1}, Kernel: KernelConfig{Type: "singbox", ConfigDir: t.TempDir()}, UsageV2: UsageV2Config{Enabled: true, IsolatedCopy: true, Directory: t.TempDir()}}
	if err := base.ValidateUsageV2(); err != nil {
		t.Fatal(err)
	}
	child := Config{}
	child.inheritFrom(&base)
	if child.UsageV2.Enabled || child.UsageV2.IsolatedCopy || child.UsageV2.Directory != "" {
		t.Fatal("mode implicitly inherited")
	}
	for _, kind := range []string{"not_isolated", "remote", "http", "standalone", "machine", "nodes", "xray", "observer", "event", "relative_dir", "relative_ca", "missing_kernel_dir", "credentials_url", "query"} {
		t.Run(kind, func(t *testing.T) {
			current := base
			switch kind {
			case "not_isolated":
				current.UsageV2.IsolatedCopy = false
			case "remote":
				current.Panel.URL = "https://example.test"
			case "http":
				current.Panel.URL = "http://127.0.0.1"
			case "standalone":
				current.Standalone = &StandaloneConfig{Enabled: true}
			case "machine":
				current.Machine = &MachineConfig{MachineID: 1}
			case "nodes":
				current.Nodes = []NodeEntry{{NodeID: 1}}
			case "xray":
				current.Kernel.Type = "xray"
			case "observer":
				current.UsageObserver.Enabled = true
			case "event":
				current.UsageEventStore.Enabled = true
			case "relative_dir":
				current.UsageV2.Directory = filepath.Join("relative", "mode")
			case "relative_ca":
				current.UsageV2.CAFile = "relative.pem"
			case "missing_kernel_dir":
				current.Kernel.ConfigDir = ""
			case "credentials_url":
				current.Panel.URL = "https://user:secret@127.0.0.1"
			case "query":
				current.Panel.URL = "https://127.0.0.1?token=secret"
			}
			if current.ValidateUsageV2() == nil {
				t.Fatal("unsupported Service mode accepted")
			}
			current.UsageV2.Enabled = false
			if err := current.ValidateUsageV2(); err != nil {
				t.Fatal("disabled mode changed legacy validation")
			}
		})
	}
	rootOnly := RootConfig{Config: base, Instances: []Config{{}}}
	if rootOnly.validateRoot() == nil {
		t.Fatal("explicit root usage mode silently ignored by instance expansion")
	}
	root := RootConfig{Instances: []Config{base, base}}
	if root.validateRoot() == nil {
		t.Fatal("multi-Service mode accepted")
	}
}
