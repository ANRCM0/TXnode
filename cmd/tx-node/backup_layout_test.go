package main

import (
	"bytes"
	"github.com/ANRCM0/TX-Node/internal/config"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func layoutConfig() *config.RootConfig {
	return &config.RootConfig{Config: config.Config{Panel: config.PanelConfig{Provider: "txboard", URL: "https://core.example", NodeID: 42, Token: "DO_NOT_EMIT_BEARER"}, Kernel: config.KernelConfig{Type: "singbox", ConfigDir: "/etc/txnode/runtime", GeoDataDir: "/etc/txnode/runtime"}, Cert: config.CertConfig{CertDir: "/etc/txnode/runtime/certs", KeyContent: "DO_NOT_EMIT_PRIVATE_KEY"}, Log: config.LogConfig{Output: "stdout"}, Authorization: config.AuthorizationConfig{Enabled: true, StateDir: "/etc/txnode/authorization", CoreInstanceID: "core-instance-1", PolicyVersion: config.NativeAuthorizationPolicyVersion, KeyID: "native", KeyEpoch: "1", PublicKey: "public-pin"}}}
}
func TestBackupLayoutExcludesSecretsAndUsesExactRuntimePaths(t *testing.T) {
	root := layoutConfig()
	var out bytes.Buffer
	if err := writeBackupLayout(&out, root); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "DO_NOT_EMIT") {
		t.Fatal("private configuration leaked")
	}
	layout, err := makeBackupLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	target := layout.Targets[0]
	if target.Authorization.StatePattern != "authorization/node-42/state.json" || target.DynamicChildren || len(target.SpoolPatterns) != 2 || !strings.HasSuffix(target.SpoolPatterns[1], ".pending.json.terminal.json") {
		t.Fatal("runtime path mismatch", out.String())
	}
	if strings.Contains(target.SpoolPatterns[0], "{") {
		t.Fatal("static spool is not exact")
	}
}
func TestBackupLayoutMachineUsesBoundedDynamicPathsAndNoMachineToken(t *testing.T) {
	root := layoutConfig()
	root.Config.Panel.NodeID = 0
	root.Config.Machine = &config.MachineConfig{MachineID: 9, Token: "DO_NOT_EMIT_MACHINE"}
	layout, err := makeBackupLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	target := layout.Targets[0]
	if !target.DynamicChildren || target.MachineID != 9 || target.NodeID != 0 || target.Authorization.StatePattern != "authorization/node-{positive_id}/state.json" || target.SpoolPatterns[0] != "runtime/node-{positive_id}/.txnode-traffic-{hex24}.pending.json" {
		t.Fatal("machine layout mismatch", target)
	}
}
func TestBackupLayoutRefusesExternalPathsExperimentalModesAndSecretURLs(t *testing.T) {
	for _, change := range []func(*config.RootConfig){
		func(r *config.RootConfig) { r.Kernel.ConfigDir = "/var/lib/external" },
		func(r *config.RootConfig) { r.Authorization.StateDir = "/etc/txnode/../secret" },
		func(r *config.RootConfig) { r.Kernel.GeoDataDir = "/opt/geodata" },
		func(r *config.RootConfig) { r.Cert.KeyFile = "/run/secrets/key" },
		func(r *config.RootConfig) { r.Log.Output = "/tmp/log" },
		func(r *config.RootConfig) { r.Kernel.CustomConfig = "/etc/txnode/custom.json" },
		func(r *config.RootConfig) { r.UsageObserver.Enabled = true },
		func(r *config.RootConfig) { r.Panel.URL = "https://core.example?token=DO_NOT_EMIT" },
		func(r *config.RootConfig) { r.Panel.URL = "https://DO_NOT_EMIT@core.example" },
	} {
		root := layoutConfig()
		change(root)
		if _, err := makeBackupLayout(root); err == nil {
			t.Fatal("unsafe layout admitted")
		}
	}
}
func TestBackupLayoutLoadedConfigurationNeverCreatesRuntimeState(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("canonical container paths are Linux only")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yml")
	body := `panel:
  provider: txboard
  url: https://core.example
  token: DO_NOT_EMIT
  node_id: 42
kernel:
  type: singbox
  config_dir: /etc/txnode/read-only-probe-missing
cert:
  cert_mode: none
`
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := config.LoadRoot(file)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeBackupLayout(&out, root); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("probe wrote runtime state")
	}
	if strings.Contains(out.String(), "DO_NOT_EMIT") {
		t.Fatal("probe leaked token")
	}
}
