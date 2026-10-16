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
	base := Config{Panel: PanelConfig{Provider: "txboard", URL: "https://panel.example.test", NodeID: 42}, Kernel: KernelConfig{Type: "singbox", ConfigDir: root}, Authorization: AuthorizationConfig{Enabled: true, StateDir: filepath.Join(root, "auth"), PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), KeyID: "native-key", KeyEpoch: "1", CoreInstanceID: "core-instance-fixture", Provider: AuthorizationProviderConfig{Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1", CAFile: filepath.Join(root, "ca.pem"), ClientCert: filepath.Join(root, "node.pem"), ClientKey: filepath.Join(root, "node.key")}}}
	if err := base.ValidateAuthorization(); err != nil {
		t.Fatal(err)
	}
	if base.Authorization.RefreshInterval != 30 || base.Authorization.PolicyVersion != NativeProviderAuthorizationPolicyVersion {
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
			c.Authorization.Provider = AuthorizationProviderConfig{}
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
	signed := Config{Panel: PanelConfig{Provider: "txboard", URL: "https://panel.example.test", Token: "synthetic-node-token", NodeID: 42}, Kernel: KernelConfig{Type: "singbox", ConfigDir: filepath.Join(t.TempDir(), "signed")}, Authorization: AuthorizationConfig{Enabled: true, StateDir: filepath.Join(t.TempDir(), "authority"), CoreInstanceID: "core-instance-fixture", KeyID: "native-key", KeyEpoch: "1", PublicKey: public, Provider: AuthorizationProviderConfig{Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1", CAFile: filepath.Join(t.TempDir(), "ca.pem"), ClientCert: filepath.Join(t.TempDir(), "node.pem"), ClientKey: filepath.Join(t.TempDir(), "node.key")}}}
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
	if len(instances) != 2 || !instances[0].Authorization.Enabled || instances[0].Authorization.PublicKey != public || instances[0].Authorization.RefreshInterval != 30 || instances[0].Authorization.PolicyVersion != NativeProviderAuthorizationPolicyVersion {
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

func TestProviderAuthorizationRequiresExplicitCompletePinnedConfiguration(t *testing.T) {
	root := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	base := Config{Panel: PanelConfig{Provider: "txboard", URL: "https://core.example.test", NodeID: 42}, Kernel: KernelConfig{ConfigDir: root},
		Authorization: AuthorizationConfig{Enabled: true, StateDir: filepath.Join(root, "state"), CoreInstanceID: "1b32d316-8cb8-4b46-8d49-e281c28d5169", KeyID: "native-key", KeyEpoch: "1", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), PolicyVersion: NativeProviderAuthorizationPolicyVersion,
			Provider: AuthorizationProviderConfig{Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1", CAFile: filepath.Join(root, "ca.pem"), ClientCert: filepath.Join(root, "node.pem"), ClientKey: filepath.Join(root, "node.key")}}}
	if err := base.ValidateAuthorization(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"disabled", "old_policy", "empty", "http", "userinfo", "query", "fragment", "path", "provider", "epoch", "overflow", "ca", "cert", "key", "relative", "usage_v2"} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			switch name {
			case "disabled":
				cfg.Authorization.Enabled = false
			case "old_policy":
				cfg.Authorization.PolicyVersion = NativeAuthorizationPolicyVersion
			case "empty":
				cfg.Authorization.Provider = AuthorizationProviderConfig{}
			case "http":
				cfg.Authorization.Provider.Endpoint = "http://provider.example.test"
			case "userinfo":
				cfg.Authorization.Provider.Endpoint = "https://secret@provider.example.test"
			case "query":
				cfg.Authorization.Provider.Endpoint += "?identity=other"
			case "fragment":
				cfg.Authorization.Provider.Endpoint += "#other"
			case "path":
				cfg.Authorization.Provider.Endpoint += "/credentials"
			case "provider":
				cfg.Authorization.Provider.ProviderID = "Wrong.ID"
			case "epoch":
				cfg.Authorization.Provider.ProviderInstanceEpoch = "01"
			case "overflow":
				cfg.Authorization.Provider.ProviderInstanceEpoch = "9999999999999999999"
			case "ca":
				cfg.Authorization.Provider.CAFile = ""
			case "cert":
				cfg.Authorization.Provider.ClientCert = ""
			case "key":
				cfg.Authorization.Provider.ClientKey = ""
			case "relative":
				cfg.Authorization.Provider.ClientKey = "node.key"
			case "usage_v2":
				cfg.UsageV2.Enabled = true
			}
			if cfg.ValidateAuthorization() == nil {
				t.Fatal("unsafe Provider authorization config accepted")
			}
		})
	}
	rootConfig := RootConfig{Config: Config{Authorization: AuthorizationConfig{Provider: base.Authorization.Provider}}, Instances: []Config{base}}
	if _, err := rootConfig.NormalizeInstances(); err == nil {
		t.Fatal("root Provider config silently disappeared across instance expansion")
	}
	child := Config{}
	child.inheritFrom(&base)
	if child.Authorization.Provider != (AuthorizationProviderConfig{}) {
		t.Fatal("Machine-independent instance inherited a Provider identity")
	}
}
