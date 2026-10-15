//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func checkpointSignal() os.Signal { return syscall.SIGUSR1 }

// start_ticks is field22 in proc stat; comm may itself contain spaces and ')'.
func processStartTicks(body string) (string, error) {
	end := strings.LastIndex(body, ")")
	if end < 0 {
		return "", errors.New("NODE_CHECKPOINT_PROCESS_IDENTITY_FAILED")
	}
	fields := strings.Fields(body[end+1:])
	if len(fields) < 20 {
		return "", errors.New("NODE_CHECKPOINT_PROCESS_IDENTITY_FAILED")
	}
	ticks := fields[19]
	if _, err := strconv.ParseUint(ticks, 10, 64); err != nil {
		return "", errors.New("NODE_CHECKPOINT_PROCESS_IDENTITY_FAILED")
	}
	return ticks, nil
}
func writeCheckpointReceipt() error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return errors.New("NODE_CHECKPOINT_PROCESS_IDENTITY_FAILED")
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return errors.New("NODE_CHECKPOINT_PROCESS_IDENTITY_FAILED")
	}
	ticks, err := processStartTicks(string(stat))
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Format      string `json:"format"`
		PID         int    `json:"pid"`
		BootID      string `json:"boot_id"`
		StartTicks  string `json:"process_start_ticks"`
		CompletedAt string `json:"completed_at"`
	}{"txnode.runtime-checkpoint/v1", os.Getpid(), strings.TrimSpace(string(boot)), ticks, time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return errors.New("NODE_CHECKPOINT_RECEIPT_FAILED")
	}
	dir, err := os.Open(backupDataRoot)
	if err != nil {
		return errors.New("NODE_CHECKPOINT_RECEIPT_FAILED")
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil || !info.IsDir() {
		return errors.New("NODE_CHECKPOINT_RECEIPT_FAILED")
	}
	// O_EXCL temp creation and atomic rename never follow an existing receipt.
	file, err := os.CreateTemp(backupDataRoot, ".runtime-checkpoint-*")
	if err != nil {
		return errors.New("NODE_CHECKPOINT_RECEIPT_FAILED")
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, filepath.Join(backupDataRoot, checkpointReceipt))
	}
	if err == nil {
		err = dir.Sync()
	}
	if err != nil {
		return errors.New("NODE_CHECKPOINT_RECEIPT_FAILED")
	}
	return nil
}
