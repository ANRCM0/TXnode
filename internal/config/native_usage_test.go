package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"
)

func TestNativeUsageRequiresV2SignedAuthorityAndKeepsMachineChildIdentity(t *testing.T) {
	root := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	base := Config{Panel: PanelConfig{Provider: "txboard", URL: "https://core.example.test", NodeID: 42},
		Kernel:  KernelConfig{Type: "singbox", ConfigDir: root},
		UsageV2: UsageV2Config{Enabled: true, Directory: filepath.Join(root, "usage")},
		Authorization: AuthorizationConfig{Enabled: true, PolicyVersion: NativeProviderUsagePolicyVersion,
			CoreInstanceID: "1b32d316-8cb8-4b46-8d49-e281c28d5169", KeyID: "native-usage", KeyEpoch: "1",
			PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
			Provider: AuthorizationProviderConfig{Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1",
				CAFile: filepath.Join(root, "ca.pem"), ClientCert: filepath.Join(root, "node.pem"), ClientKey: filepath.Join(root, "node.key")}}}
	if err := base.ValidateAuthorization(); err != nil {
		t.Fatal(err)
	}
	if err := base.ValidateUsageV2(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"v1", "no_usage", "no_authority", "xray", "observer", "http"} {
		t.Run(mode, func(t *testing.T) {
			cfg := base
			switch mode {
			case "v1":
				cfg.Authorization.PolicyVersion = NativeProviderAuthorizationPolicyVersion
			case "no_usage":
				cfg.UsageV2.Enabled = false
			case "no_authority":
				cfg.Authorization.Enabled = false
			case "xray":
				cfg.Kernel.Type = "xray"
			case "observer":
				cfg.UsageObserver.Enabled = true
			case "http":
				cfg.Panel.URL = "http://core.example.test"
			}
			if cfg.ValidateAuthorization() == nil && cfg.ValidateUsageV2() == nil {
				t.Fatal("unsafe native billing configuration accepted")
			}
		})
	}
	machine := base
	machine.Panel.NodeID = 0
	machine.Machine = &MachineConfig{MachineID: 9, Token: "synthetic-machine"}
	if err := machine.ValidateUsageV2(); err != nil {
		t.Fatal("explicit Machine parent rejected", err)
	}
	for _, id := range []int{42, 43} {
		child := machine.ExpandMachineNode(id, "vless")
		if !child.UsageV2.Enabled || child.Authorization.PolicyVersion != NativeProviderUsagePolicyVersion ||
			child.Panel.MachineID != 9 || child.Panel.NodeID != id || child.Panel.Token != "synthetic-machine" {
			t.Fatal("native child lost its Node/Machine billing identity")
		}
		if err := child.ValidateUsageV2(); err != nil {
			t.Fatal(err)
		}
	}
}
