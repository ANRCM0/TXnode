//go:build linux

package usageinterval

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

const intervalCrashHelperBudget = 20 * time.Second

type intervalCrashEvent struct {
	Stage string `json:"stage"`
	Phase string `json:"phase"`
}

type intervalCrashOutput struct {
	mu sync.Mutex
	bytes.Buffer
}

func (o *intervalCrashOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.Buffer.Write(p)
}

func (o *intervalCrashOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.Buffer.String()
}

func TestBoundedIntervalSIGKILLHelper(t *testing.T) {
	if os.Getenv("TX_INTERVAL_CRASH_HELPER") != "1" {
		return
	}
	dir, stage := os.Getenv("TX_INTERVAL_CRASH_DIR"), os.Getenv("TX_INTERVAL_CRASH_STAGE")
	events := os.NewFile(3, "interval-crash-events")
	defer events.Close()
	encoder := json.NewEncoder(events)
	emit := func(phase string) {
		t.Helper()
		if err := encoder.Encode(intervalCrashEvent{Stage: stage, Phase: phase}); err != nil {
			t.Fatalf("publish crash phase %s: %v", phase, err)
		}
	}
	emit("started")
	spool, err := usagev2.OpenSpool(filepath.Join(dir, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	emit("spool_opened")
	journal, err := OpenJournal(filepath.Join(dir, "interval"), fixtureSession(), spool)
	if err != nil {
		t.Fatal(err)
	}
	emit("journal_opened")
	clock := &testClock{}
	clock.set(1000, 100000000, 0)
	collector, err := newCollector(fixtureSession(), map[string]int{"private-runtime-user": 7}, journal, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	// The parent arms only this stage after durable initialization. The second
	// stdin read keeps the helper at the original fault hook until SIGKILL.
	emit("ready")
	control := bufio.NewScanner(os.Stdin)
	if !control.Scan() || control.Text() != "ARM "+stage {
		t.Fatalf("crash stage %s was not armed: %v", stage, control.Err())
	}
	emit("armed")
	gate := func() {
		emit("gate")
		_, err := io.Copy(io.Discard, os.Stdin)
		t.Fatalf("parent released crash stage %s without SIGKILL: %v", stage, err)
	}
	if stage == "before_seal" {
		op(collector, 31, "upload")
		gate()
	}
	journal.fault = func(at string) error {
		if at == stage {
			gate()
		}
		return nil
	}
	op(collector, 31, "upload")
	clock.set(1001, 0, time.Second)
	if _, err := collector.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("did not reach crash stage")
}

func TestBoundedIntervalSIGKILLRetainsOriginalSealedJournalAndNeverResumesTail(t *testing.T) {
	for _, stage := range []string{"before_seal", "after_file_sync", "after_publish", "after_dir_sync", "before_spool", "after_spool"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			deadline := time.Now().Add(intervalCrashHelperBudget)
			if parentDeadline, ok := t.Deadline(); ok && parentDeadline.Add(-2*time.Second).Before(deadline) {
				deadline = parentDeadline.Add(-2 * time.Second)
			}
			if !time.Now().Before(deadline) {
				t.Fatal("no remaining test budget for crash helper and cleanup")
			}
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBoundedIntervalSIGKILLHelper$", "-test.timeout="+time.Until(deadline).String())
			command.Env = append(os.Environ(), "TX_INTERVAL_CRASH_HELPER=1", "TX_INTERVAL_CRASH_DIR="+dir, "TX_INTERVAL_CRASH_STAGE="+stage)
			events, eventWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer events.Close()
			defer eventWriter.Close()
			command.ExtraFiles = []*os.File{eventWriter}
			control, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			var output intervalCrashOutput
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			_ = eventWriter.Close()
			waited := make(chan error, 1)
			go func() { waited <- command.Wait() }()
			finished := false
			t.Cleanup(func() {
				if !finished {
					_ = command.Process.Kill()
					select {
					case <-waited:
					case <-time.After(2 * time.Second):
						t.Errorf("crash helper cleanup did not finish: stage=%s output=%s", stage, output.String())
					}
				}
			})
			progress := make(chan intervalCrashEvent, 8)
			decodeErr := make(chan error, 1)
			go func() {
				decoder := json.NewDecoder(events)
				for {
					var event intervalCrashEvent
					if err := decoder.Decode(&event); err != nil {
						decodeErr <- err
						return
					}
					select {
					case progress <- event:
					case <-ctx.Done():
						return
					}
				}
			}()
			lastPhase := "not_started"
			await := func(want string) {
				t.Helper()
				for {
					select {
					case event := <-progress:
						if event.Stage != stage {
							t.Fatalf("wrong crash gate: want=%s got=%s last_phase=%s output=%s", stage, event.Stage, lastPhase, output.String())
						}
						lastPhase = event.Phase
						if event.Phase == want {
							return
						}
					case err := <-waited:
						finished = true
						t.Fatalf("helper exited before %s: stage=%s last_phase=%s err=%v output=%s", want, stage, lastPhase, err, output.String())
					case err := <-decodeErr:
						t.Fatalf("helper event pipe closed before %s: stage=%s last_phase=%s err=%v output=%s", want, stage, lastPhase, err, output.String())
					case <-ctx.Done():
						t.Fatalf("helper budget exhausted before %s: stage=%s last_phase=%s err=%v output=%s", want, stage, lastPhase, ctx.Err(), output.String())
					}
				}
			}
			await("ready")
			if _, err := fmt.Fprintln(control, "ARM "+stage); err != nil {
				t.Fatalf("arm crash helper: stage=%s last_phase=%s err=%v output=%s", stage, lastPhase, err, output.String())
			}
			await("gate")
			if err := command.Process.Kill(); err != nil {
				t.Fatalf("kill crash helper: stage=%s last_phase=%s err=%v output=%s", stage, lastPhase, err, output.String())
			}
			select {
			case err := <-waited:
				finished = true
				if err == nil {
					t.Fatalf("helper not killed: stage=%s output=%s", stage, output.String())
				}
			case <-ctx.Done():
				t.Fatalf("helper did not exit after SIGKILL: stage=%s last_phase=%s output=%s", stage, lastPhase, output.String())
			}
			status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("unexpected helper death: stage=%s status=%v output=%s", stage, status, output.String())
			}
			spool, err := usagev2.OpenSpool(filepath.Join(dir, "spool"), 0)
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			journal, err := OpenJournal(filepath.Join(dir, "interval"), fixtureSession(), spool)
			if err != nil {
				t.Fatal(err)
			}
			defer journal.Close()
			records := batches(t, spool)
			if stage == "before_seal" || stage == "after_file_sync" {
				if len(records) != 0 {
					t.Fatal("unknown volatile/unpublished tail became batch")
				}
			} else {
				if len(records) != 1 || records[0].Submission.Payload.Entries[0].RawUpBytes != "31" || records[0].Receipt != nil {
					t.Fatal("committed journal did not recover original batch")
				}
				original := records[0].Submission
				if err := journal.Recover(); err != nil {
					t.Fatal(err)
				}
				again := batches(t, spool)
				if len(again) != 1 || again[0].Submission.Payload.BatchID != original.Payload.BatchID || again[0].Submission.PayloadDigest != original.PayloadDigest {
					t.Fatal("replay generated duplicate batch")
				}
			}
			clock := &testClock{}
			clock.set(1001, 0, time.Second)
			if _, err := newCollector(fixtureSession(), map[string]int{"private-runtime-user": 7}, journal, clock.read); err != ErrUnknown {
				t.Fatal("SIGKILL tail resumed without fresh Core epoch")
			}
		})
	}
}
