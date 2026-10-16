//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// The CI runner uses production admission, HTTP routes, queue jobs, Provider
// listeners and billing workers. No installation or domain service is mocked.
func TestNativeC2RuntimeEndToEnd(t *testing.T) {
	directory := os.Getenv("NATIVE_PROVIDER_NODE_DIR")
	if directory == "" {
		t.Skip("requires the private native C2 process runner")
	}
	var fixture struct {
		NodeID        int `json:"node_id"`
		UserID        int `json:"user_id"`
		Port          int `json:"port"`
		SecondaryPort int `json:"secondary_port"`
		OriginPort    int `json:"origin_port"`
	}
	liveProtocolDecode(t, filepath.Join(directory, "fixture.json"), &fixture)
	var bundle struct {
		Connections []struct {
			UUID string `json:"uuid"`
		} `json:"connections"`
	}
	liveProtocolDecode(t, filepath.Join(directory, "subscription.json"), &bundle)
	if fixture.NodeID != 1 || len(bundle.Connections) != 2 || len(bundle.Connections[0].UUID) != 36 {
		t.Fatal("invalid native C2 consumer fixture")
	}
	cfg, err := config.Load(filepath.Join(directory, "node.json"))
	if err != nil {
		t.Fatal("native C2 configuration refused", err)
	}
	secondaryConfig, err := config.Load(filepath.Join(directory, "node-secondary.json"))
	if err != nil {
		t.Fatal("native C2 sibling configuration refused", err)
	}
	origin, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.OriginPort)))
	if err != nil {
		t.Fatal("native C2 echo origin unavailable")
	}
	defer origin.Close()
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	command := func(mode string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "php", os.Getenv("NATIVE_PROVIDER_NODE_FIXTURE"), mode)
		cmd.Env = os.Environ()
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("native C2 fixture %s failed: %s", mode, output)
		}
		return output
	}
	start := func(nodeConfig *config.Config, port int) (*Service, context.CancelFunc, <-chan error) {
		t.Helper()
		svc, err := NewChecked(nodeConfig)
		if err != nil {
			t.Fatal("native C2 service configuration refused", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- svc.Run(ctx) }()
		t.Cleanup(cancel)
		liveProtocolWait(t, done, 20*time.Second, func() bool {
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 30*time.Millisecond)
			if err == nil {
				conn.Close()
			}
			return err == nil && svc.kernel.IsRunning()
		})
		return svc, cancel, done
	}
	stop := func(cancel context.CancelFunc, done <-chan error) {
		t.Helper()
		cancel()
		select {
		case <-done:
		case <-time.After(12 * time.Second):
			t.Fatal("native C2 service failed to drain and stop")
		}
	}
	snapshot := func(svc *Service) *authorization.Snapshot {
		t.Helper()
		svc.authorizationAdmissionMu.Lock()
		manager := svc.authorization
		svc.authorizationAdmissionMu.Unlock()
		if manager == nil {
			t.Fatal("native C2 authority manager missing")
		}
		return manager.Current()
	}
	echo := func(stream net.Conn) {
		t.Helper()
		_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
		body := bytes.Repeat([]byte("native-c2-real-billable-traffic"), 256)
		if _, err := stream.Write(body); err != nil {
			t.Fatal("native C2 VLESS write refused", err)
		}
		received := make([]byte, len(body))
		if _, err := io.ReadFull(stream, received); err != nil || !bytes.Equal(body, received) {
			t.Fatal("native C2 VLESS echo failed", err)
		}
		_ = stream.SetDeadline(time.Time{})
	}
	connect := func(svc *Service, port int) (net.Conn, string) {
		t.Helper()
		current := snapshot(svc)
		if current == nil || current.Payload.PolicyVersion != config.NativeProviderUsagePolicyVersion ||
			current.Payload.UsageV2 == nil || len(current.Users) != 1 || current.Users[0].ID != fixture.UserID {
			t.Fatal("native C2 signed billing grant missing")
		}
		uuid := current.Users[0].UUID
		raw, stream := liveProtocolDial(t, "vless", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			uuid, M.ParseSocksaddr(origin.Addr().String()))
		t.Cleanup(func() { raw.Close() })
		t.Cleanup(func() { stream.Close() })
		echo(stream)
		return stream, uuid
	}
	waitGeneration := func(svc *Service, done <-chan error, old string) {
		t.Helper()
		liveProtocolWait(t, done, 18*time.Second, func() bool {
			current := snapshot(svc)
			return current != nil && len(current.Users) == 1 && current.Users[0].UUID != old && svc.kernel.IsRunning()
		})
	}
	waitClosed := func(stream net.Conn, port int, timeout time.Duration) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		_ = stream.SetReadDeadline(deadline)
		var b [1]byte
		_, err := stream.Read(b[:])
		if err == nil {
			t.Fatal("withdrawn native C2 stream remained readable")
		}
		if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatal("withdrawn native C2 stream remained open past deadline")
		}
		var closedSince time.Time
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 30*time.Millisecond)
			if err != nil {
				if closedSince.IsZero() {
					closedSince = time.Now()
				} else if time.Since(closedSince) >= time.Second {
					return
				}
			} else {
				conn.Close()
				closedSince = time.Time{}
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("withdrawn native C2 listener remained open")
	}
	first, cancelFirst, doneFirst := start(cfg, fixture.Port)
	stream, originalUUID := connect(first, fixture.Port)
	if originalUUID != bundle.Connections[0].UUID || originalUUID != bundle.Connections[1].UUID {
		t.Fatal("direct recipient-bound render and Node material differ")
	}
	second, cancelSecond, doneSecond := start(secondaryConfig, fixture.SecondaryPort)
	sibling, siblingUUID := connect(second, fixture.SecondaryPort)
	sibling.Close()
	if siblingUUID != originalUUID {
		t.Fatal("native C2 sibling received a different generation")
	}
	expectedExpiry := snapshot(first).Payload.ExpiresAt
	if err := os.WriteFile(filepath.Join(directory, "offline"), []byte("offline"), 0600); err != nil {
		t.Fatal(err)
	}
	waitClosed(stream, fixture.Port, 35*time.Second)
	if time.Now().Unix() < expectedExpiry-1 {
		t.Fatal("offline native C2 stopped before the finite authority deadline")
	}
	stop(cancelFirst, doneFirst)
	records, err := first.nativeUsage.spool.Records()
	if err != nil || len(records) == 0 {
		t.Fatal("offline finite lease lost its durable usage evidence", err)
	}
	pending := make(map[string]usagev2.Record)
	for _, record := range records {
		if record.Receipt == nil || record.Receipt.SettlementStatus != "settled" {
			pending[record.Submission.Payload.BatchID] = record
		}
	}
	if len(pending) == 0 {
		t.Fatal("offline fixture did not retain an original unacknowledged batch")
	}
	var evidence []map[string]any
	for _, record := range pending {
		var periods []string
		for _, entry := range record.Submission.Payload.Entries {
			periods = append(periods, entry.UsagePeriodID)
		}
		evidence = append(evidence, map[string]any{
			"node_id": record.Submission.Payload.NodeID, "source_epoch": record.Submission.Payload.SourceEpoch,
			"batch_id": record.Submission.Payload.BatchID, "payload_digest": record.Submission.PayloadDigest,
			"period_ids": periods,
		})
	}
	if err := os.WriteFile(filepath.Join(directory, "offline-replay.json"), mustNativeC2JSON(t, evidence), 0600); err != nil {
		t.Fatal("cannot preserve non-secret original-period evidence")
	}
	command("work")
	command("reset")
	if err := os.Remove(filepath.Join(directory, "offline")); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(directory, "offline-ready"))
	// Restart after the reset: old batches must keep their original Session,
	// period and digest, while new traffic receives the new period.
	restarted, cancelRestarted, doneRestarted := start(cfg, fixture.Port)
	currentStream, _ := connect(restarted, fixture.Port)
	currentStream.Close()
	deadline := time.Now().Add(18 * time.Second)
	replayed := false
	for time.Now().Before(deadline) {
		command("work")
		current, err := restarted.nativeUsage.spool.Records()
		if err != nil {
			t.Fatal("native C2 replay spool unreadable", err)
		}
		remaining := len(pending)
		for _, record := range current {
			old, ok := pending[record.Submission.Payload.BatchID]
			if !ok {
				continue
			}
			if record.Submission.PayloadDigest != old.Submission.PayloadDigest ||
				!bytes.Equal(mustNativeC2JSON(t, record.Session), mustNativeC2JSON(t, old.Session)) ||
				!bytes.Equal(mustNativeC2JSON(t, record.Submission), mustNativeC2JSON(t, old.Submission)) {
				t.Fatal("native C2 restart rewrote original billing evidence")
			}
			if record.Receipt != nil && record.Receipt.SettlementStatus == "settled" {
				remaining--
			}
		}
		if remaining == 0 {
			replayed = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !replayed {
		t.Fatal("native C2 original-period replay did not settle")
	}
	deadline = time.Now().Add(12 * time.Second)
	newPeriodSettled := false
	for time.Now().Before(deadline) {
		command("work")
		var state struct {
			Periods []struct {
				Billable string `json:"billable_bytes"`
			} `json:"periods"`
		}
		if json.Unmarshal(command("state"), &state) != nil || len(state.Periods) < 2 {
			t.Fatal("native C2 period evidence unreadable")
		}
		if state.Periods[len(state.Periods)-1].Billable != "0" {
			newPeriodSettled = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !newPeriodSettled {
		t.Fatal("native C2 post-reset traffic did not settle in its new period")
	}
	beforeRenew := snapshot(restarted).Users[0].UUID
	command("renew")
	waitGeneration(restarted, doneRestarted, beforeRenew)
	liveProtocolWait(t, doneRestarted, 10*time.Second, func() bool {
		return snapshot(restarted).Payload.ExpiresAt-time.Now().Unix() >= 20
	})
	if err := os.WriteFile(filepath.Join(directory, "offline"), []byte("offline"), 0600); err != nil {
		t.Fatal(err)
	}
	liveProtocolWait(t, doneRestarted, 10*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(directory, "offline-ready"))
		return err == nil
	})
	liveProtocolWait(t, doneRestarted, 5*time.Second, func() bool {
		return !restarted.authorizationRefresh.Load() && restarted.kernel.IsRunning()
	})
	if snapshot(restarted).Payload.ExpiresAt-time.Now().Unix() < 10 {
		t.Fatal("authority drain left insufficient finite lease for real rotation")
	}
	// Only a newly refused users refresh can acknowledge the offline barrier,
	// after the main loop finished its prior response/material handoff. The
	// old finite lease can now meter I/O across the real rotation.
	renewedStream, renewedUUID := connect(restarted, fixture.Port)
	restarted.nativeUsage.admissionMu.Lock()
	rotationSession := restarted.nativeUsage.session
	rotationSession.Grants = append([]usagev2.Grant(nil), rotationSession.Grants...)
	restarted.nativeUsage.admissionMu.Unlock()
	var rotation struct {
		Cutoffs []struct {
			AuthSnapshotID string `json:"auth_snapshot_id"`
			CutoffAt       int64  `json:"cutoff_at"`
			UsagePeriodID  string `json:"usage_period_id"`
			SourceEpoch    string `json:"source_epoch"`
		} `json:"cutoffs"`
	}
	if err := json.Unmarshal(command("rotate"), &rotation); err != nil || len(rotation.Cutoffs) == 0 {
		t.Fatal("real rotation cutoff evidence missing", err)
	}
	cutoffs := make(map[string]int64)
	for _, cutoff := range rotation.Cutoffs {
		for _, grant := range rotationSession.Grants {
			if cutoff.AuthSnapshotID == grant.AuthSnapshotID && cutoff.SourceEpoch == rotationSession.SourceEpoch &&
				cutoff.UsagePeriodID == grant.UsagePeriodID {
				cutoffs[cutoff.AuthSnapshotID] = cutoff.CutoffAt
			}
		}
	}
	if len(cutoffs) != len(rotationSession.Grants) || len(cutoffs) != 1 {
		t.Fatal("rotation failed to cut off the actual original signed grant")
	}
	if snapshot(restarted).Payload.ExpiresAt-time.Now().Unix() < 5 {
		t.Fatal("real rotation consumed the remaining finite lease")
	}
	echo(renewedStream)
	renewedStream.Close()
	cutoffCaptures := make(map[string]usagev2.Record)
	liveProtocolWait(t, doneRestarted, 5*time.Second, func() bool {
		records, err := restarted.nativeUsage.spool.Records()
		if err != nil {
			t.Fatal("native C2 cutoff capture unreadable", err)
		}
		for _, record := range records {
			for _, entry := range record.Submission.Payload.Entries {
				cutoff, exists := cutoffs[entry.AuthSnapshotID]
				if exists && record.Session.SourceEpoch == rotationSession.SourceEpoch &&
					record.Submission.Payload.EndedAt > cutoff {
					if record.Receipt != nil || record.LocalQuarantine != nil ||
						record.Submission.Payload.EndedAt > record.Session.Grants[0].LeaseExpiresAt {
						t.Fatal("offline real cutoff capture invented a receipt or exceeded its original lease")
					}
					cutoffCaptures[record.Submission.Payload.BatchID] = record
				}
			}
		}
		return len(cutoffCaptures) > 0
	})
	if err := os.Remove(filepath.Join(directory, "offline")); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(directory, "offline-ready"))
	waitGeneration(restarted, doneRestarted, renewedUUID)
	var quarantined []usagev2.Record
	liveProtocolWait(t, doneRestarted, 12*time.Second, func() bool {
		records, err := restarted.nativeUsage.spool.Records()
		if err != nil {
			t.Fatal("native C2 Core quarantine receipt unreadable", err)
		}
		quarantined = nil
		for _, record := range records {
			original, exists := cutoffCaptures[record.Submission.Payload.BatchID]
			if !exists {
				continue
			}
			if !bytes.Equal(mustNativeC2JSON(t, original.Session), mustNativeC2JSON(t, record.Session)) ||
				!bytes.Equal(mustNativeC2JSON(t, original.Submission), mustNativeC2JSON(t, record.Submission)) ||
				record.LocalQuarantine != nil {
				t.Fatal("persisted cutoff receipt relabeled original evidence or fabricated local quarantine")
			}
			if record.Receipt != nil {
				if record.Receipt.ReceiptStatus != "persisted" || record.Receipt.SettlementStatus != "quarantined" ||
					record.Receipt.ReasonCode != usagev2.NativeCutoffCode || record.Receipt.SettledAt != nil {
					t.Fatal("cross-cutoff traffic received an incorrect settlement receipt")
				}
				quarantined = append(quarantined, record)
			}
		}
		return len(quarantined) == len(cutoffCaptures)
	})
	if err := os.WriteFile(filepath.Join(directory, "rotation-quarantine.json"),
		mustNativeC2JSON(t, quarantined), 0600); err != nil {
		t.Fatal("cannot retain original Core quarantine receipt evidence")
	}
	if restarted.nativeUsage.reporter.NativeQuarantinedCount() < int64(len(quarantined)) {
		t.Fatal("native C2 health omitted real Core quarantine receipts")
	}
	rotatedStream, rotatedUUID := connect(restarted, fixture.Port)
	rotatedStream.Close()
	if rotatedUUID == originalUUID || rotatedUUID == renewedUUID {
		t.Fatal("native C2 immediate rotation reused retired material")
	}
	// The old UUID must fail at the actual kernel, even though the listener
	// remains active for the new generation.
	raw, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.Port)), time.Second)
	if err != nil {
		t.Fatal("native C2 rotation closed the new listener")
	}
	_ = raw.SetDeadline(time.Now().Add(time.Second))
	client, err := vless.NewClient(renewedUUID, "", logger.NOP())
	if err != nil {
		t.Fatal("retired credential fixture malformed")
	}
	retired, err := client.DialConn(raw, M.ParseSocksaddr(origin.Addr().String()))
	if err == nil {
		_, _ = retired.Write([]byte("retired"))
		var b [1]byte
		if _, err = retired.Read(b[:]); err == nil {
			t.Fatal("retired Provider generation admitted actual traffic")
		}
		retired.Close()
	}
	raw.Close()
	command("work")
	liveProtocolWait(t, doneSecond, 18*time.Second, func() bool {
		current := snapshot(second)
		return current != nil && len(current.Users) == 1 && current.Users[0].UUID == rotatedUUID && second.kernel.IsRunning()
	})
	sibling, _ = connect(second, fixture.SecondaryPort)
	command("revoke")
	waitClosed(sibling, fixture.SecondaryPort, 15*time.Second)
	stop(cancelRestarted, doneRestarted)
	stop(cancelSecond, doneSecond)
	command("work")
	command("ban")
	command("verify")
	for _, stateDirectory := range []string{cfg.Authorization.StateDir, secondaryConfig.Authorization.StateDir} {
		err := filepath.WalkDir(stateDirectory, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			if err == nil && (bytes.Contains(data, []byte(originalUUID)) ||
				bytes.Contains(data, []byte(renewedUUID)) || bytes.Contains(data, []byte(rotatedUUID))) {
				t.Error("native C2 credential leaked into persistent authorization state")
			}
			return err
		})
		if err != nil {
			t.Fatal("native C2 authorization state unreadable", err)
		}
	}
	t.Log("Production native activation, HTTP identity/checkout, real queued fulfillment, recipient render, VLESS, durable billing, offline expiry, original-period restart replay, reset, renewal, rotation with real reserved cutoff receipts and revoke passed.")
}

func mustNativeC2JSON(t *testing.T, value any) []byte {
	t.Helper()
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal("native C2 evidence serialization failed")
	}
	return result
}
