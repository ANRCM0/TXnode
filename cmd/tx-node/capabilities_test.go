package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
)

func TestRuntimeCapabilitiesCanBeReadBeforeConfigOrCredentials(t *testing.T) {
	var output bytes.Buffer
	if err := writeRuntimeCapabilities(&output); err != nil {
		t.Fatal(err)
	}
	var actual struct {
		ProtocolVersion int      `json:"protocol_version"`
		Runtime         string   `json:"runtime"`
		Capabilities    []string `json:"capabilities"`
	}
	if err := json.Unmarshal(output.Bytes(), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.ProtocolVersion != 1 || actual.Runtime != "tx-node" || actual.Capabilities == nil {
		t.Fatal("invalid capability response", output.String())
	}
	if runtime.GOOS == "linux" {
		if len(actual.Capabilities) != 3 || actual.Capabilities[0] != "node_authorization_snapshot_v1" || actual.Capabilities[1] != "node_runtime_checkpoint_v1" || actual.Capabilities[2] != "node_provider_credential_delivery_v1" {
			t.Fatal("Linux finite authorization capability missing")
		}
	} else if len(actual.Capabilities) != 0 {
		t.Fatal("unsupported persistent authorization was advertised")
	}
}
