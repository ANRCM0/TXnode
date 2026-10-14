package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

// The runner provisions Core identity changes and performs actual SQL restores.
// This child starts the real Service over its retained production-owned storage.
// Socket-table observations never open a synthetic connection to the listener.
func TestServiceUsageV2LiveRecovery(t *testing.T) {
	dir := os.Getenv("TXBOARD_LIVE_REVOCATION_DIR")
	if dir == "" {
		t.Skip("requires exclusive live recovery Core fixture")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("live recovery listener observations require Linux")
	}
	caseName := os.Getenv("TXBOARD_LIVE_REVOCATION_CASE")
	expectedError := ""
	switch caseName {
	case "generation-drift":
		expectedError = "initial setup: USAGE_V2_MODE_STOPPED"
	case "instance-drift":
		expectedError = "initial setup: USAGE_V2_NATIVE_HTTP_REQUIRED"
	case "receipt-missing":
		expectedError = "USAGE_V2_MODE_STOPPED"
	default:
		t.Fatal("invalid live recovery case", caseName)
	}
	var fixture liveProtocolFixture
	liveProtocolDecode(t, filepath.Join(dir, "fixture.json"), &fixture)
	id, err := strconv.Atoi(fixture.NodeID)
	if err != nil || id <= 0 || (fixture.Protocol != "vless" && fixture.Protocol != "vmess") || fixture.NodePort < 1024 || fixture.NodePort > 65535 {
		t.Fatal("invalid recovery fixture")
	}
	modeDir := filepath.Join(dir, "mode")
	records, err := revocationRecords(modeDir)
	if err != nil || len(records) != 1 || records[0].Session.SourceEpoch != "1" || records[0].Receipt == nil || records[0].Receipt.SettlementStatus != "settled" {
		t.Fatal("recovery requires the retained settled historical receipt", err)
	}
	original := records[0]
	originalHashes, err := recoveryJSONHashes(modeDir)
	if err != nil || len(originalHashes) == 0 {
		t.Fatal("missing immutable recovery JSON evidence", err)
	}
	if listened, err := recoveryPortListening(fixture.NodePort); err != nil || listened {
		t.Fatal("recovery listener was not initially absent", err)
	}
	routes := []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{fixture.OriginPort}, "outbound": "direct"}}
	cfg := &config.Config{InstanceID: "live-revocation-" + fixture.Protocol,
		Panel:   config.PanelConfig{Provider: "txboard", URL: os.Getenv("TXBOARD_LIVE_REVOCATION_ENDPOINT"), NodeID: id, Token: "live-revocation-local-test-only"},
		Kernel:  config.KernelConfig{Type: "singbox", ConfigDir: filepath.Join(dir, "kernel"), LogLevel: "error", CustomRoute: routes},
		Cert:    config.CertConfig{CertMode: "none"},
		Node:    config.NodeConfig{TrackInterval: 1, PushInterval: 5, PullInterval: 1, DeviceReportInterval: 60},
		WS:      config.WSConfig{DiscoveryInterval: 60},
		UsageV2: config.UsageV2Config{Enabled: true, IsolatedCopy: true, Directory: modeDir, CAFile: filepath.Join(dir, "cert.pem")}}
	svc, err := NewChecked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- svc.Run(ctx) }()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	kernelObserved, listenerObserved := false, false
	observe := func() {
		kernelObserved = kernelObserved || svc.kernel.IsRunning()
		listening, err := recoveryPortListening(fixture.NodePort)
		if err != nil {
			t.Fatal("recovery socket-table observation failed", err)
		}
		listenerObserved = listenerObserved || listening
	}
	var runError error
wait:
	for {
		observe()
		select {
		case runError = <-done:
			break wait
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("actual Service did not reject the recovery condition")
		}
	}
	observe()
	if runError == nil || runError.Error() != expectedError {
		t.Fatal("unexpected recovery Service outcome", runError, "want", expectedError)
	}
	listening, err := recoveryPortListening(fixture.NodePort)
	if err != nil || listening || svc.kernel.IsRunning() {
		t.Fatal("actual recovery failure retained a kernel or listener", err)
	}
	if caseName != "receipt-missing" && (kernelObserved || listenerObserved) {
		t.Fatal("Core identity drift reached listener startup")
	}
	if caseName == "receipt-missing" {
		if !kernelObserved || !listenerObserved || svc.usageV2 == nil {
			t.Fatal("missing-receipt case did not exercise the running real Service")
		}
		var session usagev2.Session
		liveProtocolDecode(t, filepath.Join(modeDir, "spool", ".usage-session"), &session)
		if session.SourceEpoch != "2" || session.CoreInstanceID != original.Session.CoreInstanceID || session.ReceiptGeneration != original.Session.ReceiptGeneration {
			t.Fatal("missing-receipt case did not negotiate the actual fresh Core source")
		}
	}
	missingQueryObserved := recoveryCheckTransport(t, dir, original, started, caseName == "receipt-missing")
	currentHashes, err := recoveryJSONHashes(modeDir)
	if err != nil || len(currentHashes) != len(originalHashes) {
		t.Fatal("recovery changed the immutable JSON inventory", err)
	}
	for path, digest := range originalHashes {
		if currentHashes[path] != digest {
			t.Fatal("recovery changed an original immutable JSON file", path)
		}
	}
	liveProtocolWrite(t, filepath.Join(dir, "recovery-result.json"), map[string]any{
		"case": caseName, "protocol": fixture.Protocol, "actual_service_run": true,
		"service_error": runError.Error(), "kernel_started": kernelObserved,
		"kernel_started_observed": kernelObserved, "listener_started_observed": listenerObserved,
		"startup_refused_before_kernel": caseName != "receipt-missing",
		"listener_closed":               true, "original_json_files_unchanged": true,
		"confirmed_receipt_missing_query_observed": missingQueryObserved,
		"usage_submit_after_restart":               0, "old_source_epoch": original.Session.SourceEpoch,
		"old_batch_id": original.Submission.Payload.BatchID, "old_receipt_id": original.Receipt.ReceiptID,
	})
}

func recoveryJSONHashes(modeDir string) (map[string]string, error) {
	hashes := make(map[string]string)
	err := filepath.WalkDir(modeDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("recovery JSON evidence is not a regular file: %s", path)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hashes[path] = liveProtocolSHA(body)
		return nil
	})
	return hashes, err
}

func recoveryPortListening(port int) (bool, error) {
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		body, err := os.ReadFile(path)
		if os.IsNotExist(err) && strings.HasSuffix(path, "tcp6") {
			continue // Linux can disable IPv6 entirely.
		}
		if err != nil {
			return false, err
		}
		for _, line := range strings.Split(string(body), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			local := strings.Split(fields[1], ":")
			if len(local) != 2 {
				return false, fmt.Errorf("unexpected Linux socket-table address")
			}
			localPort, err := strconv.ParseInt(local[1], 16, 32)
			if err != nil {
				return false, err
			}
			if int(localPort) == port {
				return true, nil
			}
		}
	}
	return false, nil
}

func recoveryCheckTransport(t *testing.T, dir string, original usagev2.Record, started time.Time, requireMissing bool) bool {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "native-observations.jsonl"))
	if err != nil {
		t.Fatal("recovery requires native HTTP observations", err)
	}
	query, err := json.Marshal(original.Submission.Query())
	if err != nil {
		t.Fatal(err)
	}
	queryDigest := liveProtocolSHA(query)
	missingObserved := false
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var observation struct {
			Path          string  `json:"path"`
			Status        int     `json:"status"`
			StartedAt     float64 `json:"started_at"`
			RequestSHA256 string  `json:"request_sha256"`
			ErrorCode     string  `json:"error_code"`
		}
		if err := json.Unmarshal(line, &observation); err != nil {
			t.Fatal("invalid retained HTTP observation", err)
		}
		if observation.StartedAt < float64(started.UnixNano())/1e9 {
			continue
		}
		if observation.Path == "/txapi/node/v2/usage/submit" {
			t.Fatal("recovery silently submitted a batch")
		}
		if observation.Path == "/txapi/node/v2/usage/batch/get" && observation.Status == 404 && observation.ErrorCode == "BATCH_NOT_FOUND" && observation.RequestSHA256 == queryDigest {
			missingObserved = true
		}
	}
	if requireMissing && !missingObserved {
		t.Fatal("missing-receipt case did not query the original confirmed receipt")
	}
	return missingObserved
}
