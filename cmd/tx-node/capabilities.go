package main

import (
	"encoding/json"
	"io"
	"runtime"

	"github.com/ANRCM0/TX-Node/internal/buildinfo"
)

// This read-only entrypoint runs before configuration loading and never starts
// a kernel, panel transport or disk-state manager. Installers can inspect the
// exact selected image without receiving credentials or writing runtime state.
func writeRuntimeCapabilities(output io.Writer) error {
	capabilities := []string{}
	if runtime.GOOS == "linux" {
		capabilities = append(capabilities, "node_authorization_snapshot_v1", "node_runtime_checkpoint_v1")
	}
	return json.NewEncoder(output).Encode(struct {
		ProtocolVersion int      `json:"protocol_version"`
		Runtime         string   `json:"runtime"`
		Version         string   `json:"version"`
		Commit          string   `json:"commit"`
		Capabilities    []string `json:"capabilities"`
	}{1, "tx-node", buildinfo.Version, buildinfo.Commit, capabilities})
}
