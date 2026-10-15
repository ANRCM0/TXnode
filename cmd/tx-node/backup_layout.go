package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/config"
)

const backupDataRoot = "/etc/txnode"
const checkpointReceipt = ".runtime-checkpoint.json"

type backupLayout struct {
	Format   string         `json:"format"`
	DataRoot string         `json:"data_root"`
	Receipt  string         `json:"checkpoint_receipt"`
	Targets  []backupTarget `json:"targets"`
}
type backupTarget struct {
	InstanceID      string      `json:"instance_id"`
	Provider        string      `json:"provider"`
	PanelURL        string      `json:"panel_url"`
	NodeID          int         `json:"node_id"`
	MachineID       int         `json:"machine_id"`
	Kernel          string      `json:"kernel"`
	KernelRoot      string      `json:"kernel_root"`
	DynamicChildren bool        `json:"dynamic_children"`
	Authorization   backupTrust `json:"authorization"`
	SpoolPatterns   []string    `json:"spool_patterns"`
}
type backupTrust struct {
	Enabled        bool   `json:"enabled"`
	CoreInstanceID string `json:"core_instance_id"`
	PolicyVersion  string `json:"policy_version"`
	KeyID          string `json:"key_id"`
	KeyEpoch       string `json:"key_epoch"`
	PublicKey      string `json:"public_key"`
	StatePattern   string `json:"state_pattern"`
}

// Probe paths are POSIX container paths, independent of the build host. No
// directories, authorization stores, transports or runtime services are opened.
func makeBackupLayout(root *config.RootConfig) (*backupLayout, error) {
	instances, err := root.NormalizeInstances()
	if err != nil {
		return nil, errors.New("NODE_BACKUP_LAYOUT_INVALID_CONFIG")
	}
	out := &backupLayout{Format: "txnode.backup-layout/v1", DataRoot: backupDataRoot, Receipt: checkpointReceipt, Targets: []backupTarget{}}
	relative := func(value string) (string, error) {
		if value == "" {
			return "", nil
		}
		if !strings.HasPrefix(value, "/") || path.Clean(value) != value || (value != backupDataRoot && !strings.HasPrefix(value, backupDataRoot+"/")) || strings.ContainsAny(value, "\\\x00\n\r*?[]{}") {
			return "", errors.New("NODE_BACKUP_LAYOUT_EXTERNAL_PATH")
		}
		if value == backupDataRoot {
			return ".", nil
		}
		return strings.TrimPrefix(value, backupDataRoot+"/"), nil
	}
	for _, instance := range instances {
		endpoint, e := url.Parse(instance.Panel.URL)
		if e != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
			return nil, errors.New("NODE_BACKUP_LAYOUT_PANEL_INVALID")
		}
		if instance.IsStandalone() || instance.Panel.Provider != "txboard" || instance.UsageV2.Enabled || instance.UsageObserver.Enabled || instance.UsageEventStore.Enabled {
			return nil, errors.New("NODE_BACKUP_LAYOUT_UNSUPPORTED")
		}
		nodes := instance.ExpandNodes()
		if instance.IsMachineMode() {
			nodes = []*config.Config{instance}
		}
		for _, cfg := range nodes {
			if cfg.Kernel.Type != "singbox" && cfg.Kernel.Type != "xray" {
				return nil, errors.New("NODE_BACKUP_LAYOUT_UNSUPPORTED")
			}
			if len(cfg.Kernel.CustomOutbound) > 0 || len(cfg.Kernel.CustomRoute) > 0 || cfg.Kernel.CustomConfig != "" {
				return nil, errors.New("NODE_BACKUP_LAYOUT_CUSTOM_KERNEL_UNSUPPORTED")
			}
			for _, candidate := range []string{cfg.Kernel.ConfigDir, cfg.Kernel.GeoDataDir, cfg.Cert.CertDir, cfg.Cert.CertFile, cfg.Cert.KeyFile} {
				if _, err := relative(candidate); err != nil {
					return nil, err
				}
			}
			if cfg.Log.Output != "" && cfg.Log.Output != "stdout" && cfg.Log.Output != "stderr" {
				if _, err := relative(cfg.Log.Output); err != nil {
					return nil, err
				}
			}
			kernelRoot, err := relative(cfg.Kernel.ConfigDir)
			if err != nil || kernelRoot == "" {
				return nil, errors.New("NODE_BACKUP_LAYOUT_EXTERNAL_PATH")
			}
			target := backupTarget{InstanceID: cfg.InstanceID, Provider: cfg.Panel.Provider, PanelURL: cfg.Panel.URL, NodeID: cfg.Panel.NodeID, MachineID: cfg.Panel.MachineID, Kernel: cfg.Kernel.Type, KernelRoot: kernelRoot, SpoolPatterns: []string{}}
			a := cfg.Authorization
			target.Authorization = backupTrust{Enabled: a.Enabled, CoreInstanceID: a.CoreInstanceID, PolicyVersion: a.PolicyVersion, KeyID: a.KeyID, KeyEpoch: a.KeyEpoch, PublicKey: a.PublicKey}
			if cfg.IsMachineMode() {
				target.NodeID = 0
				target.MachineID = cfg.Machine.MachineID
				target.DynamicChildren = true
				if a.Enabled {
					stateRoot, e := relative(a.StateDir)
					if e != nil {
						return nil, e
					}
					target.Authorization.StatePattern = path.Join(stateRoot, "node-{positive_id}", "state.json")
				}
				target.SpoolPatterns = []string{path.Join(kernelRoot, "node-{positive_id}", ".txnode-traffic-{hex24}.pending.json"), path.Join(kernelRoot, "node-{positive_id}", ".txnode-traffic-{hex24}.pending.json.terminal.json")}
			} else {
				if a.Enabled {
					stateRoot, e := relative(a.StateDir)
					if e != nil {
						return nil, e
					}
					target.Authorization.StatePattern = path.Join(stateRoot, fmt.Sprintf("node-%d", cfg.Panel.NodeID), "state.json")
				}
				key := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%s", cfg.Panel.URL, cfg.Panel.NodeID, cfg.Panel.MachineID, cfg.InstanceID)))
				pending := path.Join(kernelRoot, ".txnode-traffic-"+hex.EncodeToString(key[:12])+".pending.json")
				target.SpoolPatterns = []string{pending, pending + ".terminal.json"}
			}
			out.Targets = append(out.Targets, target)
		}
	}
	sort.Slice(out.Targets, func(i, j int) bool {
		a, b := out.Targets[i], out.Targets[j]
		if a.InstanceID != b.InstanceID {
			return a.InstanceID < b.InstanceID
		}
		return a.NodeID < b.NodeID
	})
	return out, nil
}
func writeBackupLayout(output io.Writer, root *config.RootConfig) error {
	layout, err := makeBackupLayout(root)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(layout)
}
