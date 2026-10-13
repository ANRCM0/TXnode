//go:build linux

package usageinterval

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

func TestBoundedIntervalSIGKILLHelper(t *testing.T) {
	if os.Getenv("TX_INTERVAL_CRASH_HELPER") != "1" {
		return
	}
	dir, stage := os.Getenv("TX_INTERVAL_CRASH_DIR"), os.Getenv("TX_INTERVAL_CRASH_STAGE")
	spool, err := usagev2.OpenSpool(filepath.Join(dir, "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(filepath.Join(dir, "interval"), fixtureSession(), spool)
	if err != nil {
		t.Fatal(err)
	}
	clock := &testClock{}
	clock.set(1000, 100000000, 0)
	collector, err := newCollector(fixtureSession(), map[string]int{"private-runtime-user": 7}, journal, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	if stage == "before_seal" {
		op(collector, 31, "upload")
		fmt.Println("INTERVAL_CRASH_GATE")
		select {}
	}
	journal.fault = func(at string) error {
		if at == stage {
			fmt.Println("INTERVAL_CRASH_GATE")
			select {}
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
			command := exec.Command(os.Args[0], "-test.run=^TestBoundedIntervalSIGKILLHelper$", "-test.timeout=20s")
			command.Env = append(os.Environ(), "TX_INTERVAL_CRASH_HELPER=1", "TX_INTERVAL_CRASH_DIR="+dir, "TX_INTERVAL_CRASH_STAGE="+stage)
			out, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			command.Stderr = os.Stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			finished := false
			t.Cleanup(func() {
				if !finished {
					command.Process.Kill()
					command.Wait()
				}
			})
			gate := make(chan bool, 1)
			go func() {
				scanner := bufio.NewScanner(out)
				for scanner.Scan() {
					if scanner.Text() == "INTERVAL_CRASH_GATE" {
						gate <- true
						return
					}
				}
				gate <- false
			}()
			select {
			case ready := <-gate:
				if !ready {
					t.Fatal("helper exited before gate")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("helper crash gate timeout")
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := command.Wait(); err == nil {
				t.Fatal("helper not killed")
			}
			status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("unexpected helper death")
			}
			finished = true
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
