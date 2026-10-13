package config

import (
	"errors"
	"net/url"
	"path/filepath"
)

type UsageV2Config struct {
	Enabled      bool   `yaml:"enabled"`
	IsolatedCopy bool   `yaml:"isolated_copy"`
	Directory    string `yaml:"directory"`
	CAFile       string `yaml:"ca_file,omitempty"`
}

func (c *Config) ValidateUsageV2() error {
	if c == nil || !c.UsageV2.Enabled {
		return nil
	}
	u, err := url.Parse(c.Panel.URL)
	if !c.UsageV2.IsolatedCopy || c.Panel.Provider != "txboard" || c.Kernel.Type != "singbox" || c.IsStandalone() || c.Machine != nil || c.Panel.MachineID != 0 || len(c.Nodes) != 0 || c.Panel.NodeID <= 0 || c.UsageObserver.Enabled || c.UsageEventStore.Enabled || c.Kernel.ConfigDir == "" || c.UsageV2.Directory == "" || !filepath.IsAbs(c.UsageV2.Directory) || err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" {
		return errors.New("USAGE_V2_ISOLATED_CONFIGURATION_REQUIRED")
	}
	if c.UsageV2.CAFile != "" && !filepath.IsAbs(c.UsageV2.CAFile) {
		return errors.New("USAGE_V2_ISOLATED_CONFIGURATION_REQUIRED")
	}
	return nil
}
