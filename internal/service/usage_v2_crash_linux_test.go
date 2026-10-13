//go:build linux

package service

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

func TestServiceUsageV2SIGKILLHelper(t *testing.T) {
	if os.Getenv("TX_SERVICE_USAGE_KILL_HELPER") != "1" {
		return
	}
	s, _, source, transport := modeFixture(t, 30*time.Second)
	dir := os.Getenv("TX_SERVICE_USAGE_KILL_DIR")
	s.cfg.Kernel.ConfigDir = filepath.Join(dir, "kernel")
	s.cfg.UsageV2.Directory = filepath.Join(dir, "mode")
	if err := os.MkdirAll(s.cfg.Kernel.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	s = NewWithControlPlane(s.cfg, source)
	s.usageOwner = &usagebucket.ProcessOwner{}
	k := &usageModeKernel{started: make(chan struct{})}
	s.kernel = k
	s.kernelLife = kernellifecycle.New(k)
	_, _ = startMode(t, s, k)
	ioMode(t, k)
	waitMode(t, func() bool { return len(transport.snapshot()) == 1 })
	// Transport submission precedes the Reporter's durable receipt write. Wait
	// for the latter before telling the parent to kill only this helper process.
	waitMode(t, func() bool {
		// Reading the atomically published file is fixture observation only.
		files, _ := filepath.Glob(filepath.Join(dir, "mode", "spool", "*.json"))
		if len(files) != 1 {
			return false
		}
		body, err := os.ReadFile(files[0])
		if err != nil {
			return false
		}
		var r usagev2.Record
		return usagev2.StrictDecode(body, &r, usagev2.MaxPayloadBytes) == nil && r.Validate() == nil && r.Receipt != nil
	})
	fmt.Println("SERVICE_USAGE_KILL_GATE")
	select {}
}

func TestServiceUsageV2SIGKILLKeepsReceiptAndRefusesSameEpochResume(t *testing.T) {
	dir := t.TempDir()
	helper := exec.Command(os.Args[0], "-test.run=^TestServiceUsageV2SIGKILLHelper$", "-test.timeout=30s")
	helper.Env = append(os.Environ(), "TX_SERVICE_USAGE_KILL_HELPER=1", "TX_SERVICE_USAGE_KILL_DIR="+dir)
	out, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	helper.Stderr = os.Stderr
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	finished := false
	t.Cleanup(func() {
		if !finished {
			helper.Process.Kill()
			helper.Wait()
		}
	})
	gate := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			if scanner.Text() == "SERVICE_USAGE_KILL_GATE" {
				gate <- true
				return
			}
		}
		gate <- false
	}()
	select {
	case ready := <-gate:
		if !ready {
			t.Fatal("helper exited before durable Service receipt")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Service crash gate timed out")
	}
	if err := helper.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := helper.Wait(); err == nil {
		t.Fatal("helper not killed")
	}
	status, ok := helper.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("unexpected helper death")
	}
	finished = true
	spool, err := usagev2.OpenSpool(filepath.Join(dir, "mode", "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	records, err := spool.Records()
	if err != nil || len(records) != 1 || records[0].Receipt == nil || records[0].Submission.Payload.Entries[0].RawUpBytes != "11" || records[0].Submission.Payload.Entries[0].RawDownBytes != "7" {
		t.Fatal("actual Service SIGKILL lost original capture/receipt")
	}
	original := records[0]
	spool.Close()
	s, k, source, _ := modeFixture(t, 30*time.Second)
	s.cfg.Kernel.ConfigDir = filepath.Join(dir, "kernel")
	s.cfg.UsageV2.Directory = filepath.Join(dir, "mode")
	session := original.Session
	source.bootstrap.UsageV2Session = &session
	next := NewWithControlPlane(s.cfg, source)
	next.usageOwner = &usagebucket.ProcessOwner{}
	next.kernel = k
	next.kernelLife = kernellifecycle.New(k)
	if err := next.Run(context.Background()); err == nil || k.starts != 0 {
		t.Fatal("same source restarted after process death")
	}
	spool, err = usagev2.OpenSpool(filepath.Join(dir, "mode", "spool"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	after, err := spool.Records()
	if err != nil || len(after) != 1 || after[0].Submission.PayloadDigest != original.Submission.PayloadDigest || after[0].Receipt.ReceiptID != original.Receipt.ReceiptID {
		t.Fatal("failed restart rewrote original receipt")
	}
}
