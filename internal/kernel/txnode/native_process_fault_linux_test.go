//go:build linux

package txnode

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

type nativeCrashProgress struct {
	Stage string `json:"stage"`
	Port  int    `json:"port,omitempty"`
	Up    int64  `json:"up,omitempty"`
	Down  int64  `json:"down,omitempty"`
}

func nativeCrashSession() usagev2.Session {
	now := time.Now().Unix()
	return usagev2.Session{ProtocolVersion: 2, CoreInstanceID: "native-load-crash", NodeID: "3", SourceEpoch: "5", ReceiptGeneration: "1", RetentionSeconds: 86400, MaxLateReportSeconds: 3600, ReceiptRetentionSeconds: 86400, IssuedAt: now - 1,
		Grants: []usagev2.Grant{{UserID: "7", AccessSubjectID: "8", AuthSnapshotID: "11", TariffRevisionID: "12", TermsID: "13", UsagePeriodID: "14", IssuedAt: now - 1, LeaseExpiresAt: now + 90, RevocationVersion: "0"}}}
}

func nativeCrashWindow(session usagev2.Session, revision string) usageinterval.NativeWindow {
	return usageinterval.NativeWindow{Revision: revision, Digest: strings.Repeat("a", 64), IssuedAt: session.IssuedAt, ExpiresAt: session.Grants[0].LeaseExpiresAt}
}

func nativeCrashOpen(t *testing.T, root string, session usagev2.Session) (*usageinterval.NativeStore, *usagev2.Spool) {
	t.Helper()
	spool, err := usagev2.OpenSpool(filepath.Join(root, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	store, err := usageinterval.OpenNativeStore(filepath.Join(root, "native"), session, spool)
	if err != nil {
		_ = spool.Close()
		t.Fatal(err)
	}
	return store, spool
}

func nativeCrashStart(t *testing.T, store *usageinterval.NativeStore, session usagev2.Session, revision, password string, port int) *Kernel {
	t.Helper()
	collector, err := store.NewCollector(session, nativeCrashWindow(session, revision), map[string]int{password: 7})
	if err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(collector.ReadyAt()); delay > 0 {
		time.Sleep(delay)
	}
	k := New(RuntimeConfig{MaxFresh: 128, DrainTimeout: time.Second, HandshakeTimeout: 3 * time.Second})
	meter, ok := k.NewNativeMeter(collector, map[string]int{password: 7})
	if !ok || !k.SetNativeUsageTracker(meter) {
		t.Fatal("process fault native meter refused")
	}
	if err := k.Start(&model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}, []model.UserSpec{{ID: 7, UUID: password}}, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNativeProcessLoadHelper(t *testing.T) {
	if os.Getenv("TXNODE_NATIVE_CRASH_CHILD") != "1" {
		return
	}
	root := os.Getenv("TXNODE_NATIVE_CRASH_ROOT")
	var session usagev2.Session
	body, err := os.ReadFile(filepath.Join(root, "session.json"))
	if err != nil || json.Unmarshal(body, &session) != nil {
		t.Fatal("process helper session missing", err)
	}
	store, spool := nativeCrashOpen(t, root, session)
	defer store.Close()
	defer spool.Close()
	k := nativeCrashStart(t, store, session, "1", "native-crash-pass", freePortTB(t))
	defer k.Stop()
	events := os.NewFile(3, "native-process-progress")
	defer events.Close()
	encoder := json.NewEncoder(events)
	if err := encoder.Encode(nativeCrashProgress{Stage: "ready", Port: k.spec.Port}); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var minimum int64
		if _, err := fmt.Sscanf(scanner.Text(), "SNAPSHOT %d", &minimum); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(12 * time.Second)
		for {
			progress, err := nativeCrashDurableProgress(filepath.Join(root, "native"))
			if err != nil {
				t.Fatal(err)
			}
			if progress.Up >= minimum && progress.Down >= minimum {
				progress.Stage = "durable-load"
				if err := encoder.Encode(progress); err != nil {
					t.Fatal(err)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("durable load handshake incomplete: %+v minimum=%d", progress, minimum)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	t.Fatal("process helper must end by SIGKILL at its durable load handshake")
}

func nativeCrashDurableProgress(root string) (nativeCrashProgress, error) {
	var result nativeCrashProgress
	files, err := filepath.Glob(filepath.Join(root, "*.native"))
	if err != nil {
		return result, err
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			return result, err
		}
		var envelope struct {
			Payload struct {
				Events []struct {
					Done     bool `json:"done"`
					Eligible bool `json:"eligible"`
					Evidence struct {
						Direction string `json:"direction"`
						Bytes     int64  `json:"bytes,string"`
					} `json:"evidence"`
				} `json:"events"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return result, err
		}
		for _, event := range envelope.Payload.Events {
			if event.Done && event.Eligible {
				if event.Evidence.Direction == "upload" {
					result.Up += event.Evidence.Bytes
				} else if event.Evidence.Direction == "download" {
					result.Down += event.Evidence.Bytes
				}
			}
		}
	}
	return result, nil
}

func TestNativeLoadedSIGKILLRestartsWithOriginalUsagePeriod(t *testing.T) {
	root := t.TempDir()
	session := nativeCrashSession()
	body, _ := json.Marshal(session)
	if err := os.WriteFile(filepath.Join(root, "session.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeProcessLoadHelper$", "-test.timeout=40s")
	command.Env = append(os.Environ(), "TXNODE_NATIVE_CRASH_CHILD=1", "TXNODE_NATIVE_CRASH_ROOT="+root)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	command.ExtraFiles = []*os.File{writer}
	control, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			<-waited
		}
	}()
	progress := make(chan nativeCrashProgress, 4)
	decodeErr := make(chan error, 1)
	go func() {
		decoder := json.NewDecoder(reader)
		for {
			var event nativeCrashProgress
			if err := decoder.Decode(&event); err != nil {
				decodeErr <- err
				return
			}
			progress <- event
		}
	}()
	await := func(stage string) nativeCrashProgress {
		t.Helper()
		select {
		case event := <-progress:
			if event.Stage != stage {
				t.Fatalf("wrong native process stage: %+v", event)
			}
			return event
		case err := <-waited:
			finished = true
			t.Fatalf("native process exited before %s: %v %s", stage, err, output.String())
		case err := <-decodeErr:
			t.Fatalf("native process progress closed before %s: %v", stage, err)
		case <-ctx.Done():
			t.Fatalf("native process %s budget exhausted", stage)
		}
		return nativeCrashProgress{}
	}
	ready := await("ready")
	var clients []net.Conn
	var wg sync.WaitGroup
	var completed, written atomic.Int64
	errorsSeen := make(chan error, 8)
	var killing atomic.Bool
	for i := 0; i < 8; i++ {
		c := socksConnectTB(t, ready.Port, "native-crash-pass", origin.Addr().String())
		clients = append(clients, c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := bytes.Repeat([]byte{'c'}, 1024)
			got := make([]byte, len(payload))
			for {
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				n, err := c.Write(payload)
				written.Add(int64(n))
				if err == nil {
					_, err = io.ReadFull(c, got)
					if err == nil && !bytes.Equal(got, payload) {
						err = fmt.Errorf("process fault payload mismatch")
					}
				}
				if err != nil {
					if !killing.Load() {
						errorsSeen <- err
					}
					return
				}
				completed.Add(1)
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	defer func() {
		killing.Store(true)
		for _, c := range clients {
			_ = c.Close()
		}
		wg.Wait()
	}()
	if _, err := fmt.Fprintln(control, "SNAPSHOT", int64(64*1024)); err != nil {
		t.Fatal(err)
	}
	checkpoint := await("durable-load")
	if completed.Load() == 0 {
		t.Fatal("process kill had no real completed traffic")
	}
	select {
	case err := <-errorsSeen:
		t.Fatalf("traffic failed before SIGKILL: %v", err)
	default:
	}
	killing.Store(true)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waited:
		finished = true
		if err == nil {
			t.Fatal("process did not die by signal")
		}
	case <-ctx.Done():
		t.Fatal("SIGKILL did not stop native process")
	}
	status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("native load process was not SIGKILLed")
	}
	for _, c := range clients {
		_ = c.Close()
	}
	wg.Wait()
	store, spool := nativeCrashOpen(t, root, session)
	records, err := spool.Records()
	if err != nil || len(records) == 0 {
		t.Fatal("SIGKILL discarded durable native load", err)
	}
	identities := map[string]string{}
	var up, down int64
	for _, record := range records {
		if record.Receipt != nil || record.Session.CoreInstanceID != session.CoreInstanceID {
			t.Fatal("recovery invented a receipt or changed session")
		}
		identities[record.Submission.Payload.BatchID] = record.Submission.PayloadDigest
		for _, entry := range record.Submission.Payload.Entries {
			if entry.UsagePeriodID != "14" || entry.AuthSnapshotID != "11" {
				t.Fatal("crashed bytes moved to a new authority period")
			}
			n, err := strconv.ParseInt(entry.RawUpBytes, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			up += n
			n, err = strconv.ParseInt(entry.RawDownBytes, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			down += n
		}
	}
	if up < checkpoint.Up || down < checkpoint.Down || up > written.Load() || down > written.Load() {
		t.Fatalf("SIGKILL recovered bytes outside durable/actual bounds: checkpoint=%+v up=%d down=%d written=%d", checkpoint, up, down, written.Load())
	}
	if store.QuarantinedCollectors() == 0 {
		t.Fatal("active in-flight I/O vanished from crash quarantine")
	}
	if _, err := store.NewCollector(session, nativeCrashWindow(session, "1"), map[string]int{"native-crash-pass": 7}); err == nil {
		t.Fatal("same crashed signed revision reopened")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	store, spool = nativeCrashOpen(t, root, session)
	defer store.Close()
	defer spool.Close()
	again, err := spool.Records()
	if err != nil || len(again) != len(identities) {
		t.Fatal("reopening duplicated or discarded the original crash batch", err)
	}
	for _, record := range again {
		if identities[record.Submission.Payload.BatchID] != record.Submission.PayloadDigest {
			t.Fatal("replay relabelled original crash payload")
		}
	}
	next := session
	next.Grants = append([]usagev2.Grant(nil), session.Grants...)
	next.Grants[0].AuthSnapshotID = "12"
	next.Grants[0].UsagePeriodID = "15"
	k := nativeCrashStart(t, store, next, "2", "native-crash-pass-next", ready.Port)
	defer k.Stop()
	if socksCredentialAccepted(t, ready.Port, "native-crash-pass") {
		t.Fatal("restart revived old credential")
	}
	c := socksConnectTB(t, ready.Port, "native-crash-pass-next", origin.Addr().String())
	if err := nativeFaultEcho(c, []byte("new-period")); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	k.Stop()
	if err := k.meter.collector.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	final, err := spool.Records()
	if err != nil || len(final) <= len(identities) {
		t.Fatal("fresh signed revision failed to preserve a separate usage period", err)
	}
	foundNew := false
	for _, record := range final {
		for _, entry := range record.Submission.Payload.Entries {
			if entry.UsagePeriodID == "15" {
				foundNew = true
			}
		}
	}
	if !foundNew {
		t.Fatal("fresh traffic did not remain in its new period")
	}
	t.Logf("SIGKILL loaded completed=%d durable_up=%d durable_down=%d recovered_up=%d recovered_down=%d original_batches=%d", completed.Load(), checkpoint.Up, checkpoint.Down, up, down, len(identities))
}
