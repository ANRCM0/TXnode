package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeAuthorizationConfigurationIsExplicitAndBounded(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	root := t.TempDir()
	base := Config{Panel: PanelConfig{Provider: "txboard", URL: "https://panel.example.test", NodeID: 42}, Kernel: KernelConfig{Type: "singbox", ConfigDir: root}, Authorization: AuthorizationConfig{Enabled: true, StateDir: filepath.Join(root, "auth"), PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), KeyID: "native-key", KeyEpoch: "1", CoreInstanceID: "core-instance-fixture"}}
	if err := base.ValidateAuthorization(); err != nil {
		t.Fatal(err)
	}
	if base.Authorization.RefreshInterval != 30 || base.Authorization.PolicyVersion != NativeAuthorizationPolicyVersion {
		t.Fatal("unsafe defaults")
	}
	for _, name := range []string{"xboard", "http", "standalone", "usage_v2", "missing_pin", "query", "long_refresh", "bad_epoch", "relative_state", "bad_policy"} {
		t.Run(name, func(t *testing.T) {
			c := base
			switch name {
			case "xboard":
				c.Panel.Provider = "xboard"
			case "http":
				c.Panel.URL = "http://panel.example.test"
			case "standalone":
				c.Standalone = &StandaloneConfig{Enabled: true}
			case "usage_v2":
				c.UsageV2.Enabled = true
			case "missing_pin":
				c.Authorization.PublicKey = ""
			case "query":
				c.Panel.URL += "?token=bad"
			case "long_refresh":
				c.Authorization.RefreshInterval = 31
			case "bad_epoch":
				c.Authorization.KeyEpoch = "0"
			case "relative_state":
				c.Authorization.StateDir = "relative"
			case "bad_policy":
				c.Authorization.PolicyVersion = "wrong"
			}
			if c.ValidateAuthorization() == nil {
				t.Fatal("unsafe authorization configuration accepted")
			}
			c.Authorization.Enabled = false
			if err := c.ValidateAuthorization(); err != nil {
				t.Fatal("disabled mode changed behavior", err)
			}
		})
	}
	for _, kernel := range []string{"singbox", "xray"} {
		c := base
		c.Kernel.Type = kernel
		if err := c.ValidateAuthorization(); err != nil {
			t.Fatal("dual kernel validation failed", err)
		}
	}
}

func TestLoadRootRefusesTopLevelAuthorizationWithInstancesWithoutSilentDowngrade(t *testing.T) {
	child := Config{Panel: PanelConfig{Provider: "txboard", URL: "https://panel.example.test", Token: "synthetic-node-token", NodeID: 42}, Kernel: KernelConfig{Type: "singbox", ConfigDir: t.TempDir()}}
	root := RootConfig{Config: Config{Authorization: AuthorizationConfig{Enabled: true}}, Instances: []Config{child}}
	body, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoot(path); err == nil || !strings.Contains(err.Error(), "NODE_AUTHORIZATION_EXPLICIT_INSTANCE_REQUIRED") {
		t.Fatal("top-level signed mode disappeared during LoadRoot", err)
	}
	// Programmatic callers of NormalizeInstances must receive the same refusal,
	// even if they bypass the file loader and validateRoot.
	if _, err := root.NormalizeInstances(); err == nil || !strings.Contains(err.Error(), "NODE_AUTHORIZATION_EXPLICIT_INSTANCE_REQUIRED") {
		t.Fatal("normalization silently discarded root enrollment", err)
	}
}
func TestLoadRootPreservesExplicitPerInstanceAuthorization(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	signed := Config{Panel: PanelConfig{Provider: "txboard", URL: "https://panel.example.test", Token: "synthetic-node-token", NodeID: 42}, Kernel: KernelConfig{Type: "singbox", ConfigDir: filepath.Join(t.TempDir(), "signed")}, Authorization: AuthorizationConfig{Enabled: true, StateDir: filepath.Join(t.TempDir(), "authority"), CoreInstanceID: "core-instance-fixture", KeyID: "native-key", KeyEpoch: "1", PublicKey: public}}
	ordinary := Config{Panel: PanelConfig{Provider: "txboard", URL: "https://panel.example.test", Token: "synthetic-other-node", NodeID: 43}, Kernel: KernelConfig{Type: "xray", ConfigDir: filepath.Join(t.TempDir(), "ordinary")}}
	root := RootConfig{Instances: []Config{signed, ordinary}}
	body, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	instances, err := loaded.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 2 || !instances[0].Authorization.Enabled || instances[0].Authorization.PublicKey != public || instances[0].Authorization.RefreshInterval != 30 || instances[0].Authorization.PolicyVersion != NativeAuthorizationPolicyVersion {
		t.Fatal("explicit enrolled child lost trust or finite policy")
	}
	if instances[1].Authorization.Enabled || instances[1].Authorization.PublicKey != "" {
		t.Fatal("unenrolled child inherited authority from sibling")
	}
	inherited := Config{}
	inherited.inheritFrom(&signed)
	if inherited.Authorization.Enabled || inherited.Authorization.PublicKey != "" {
		t.Fatal("explicit authority was implicitly inherited")
	}
}
