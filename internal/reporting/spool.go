package reporting

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// batchSpool contains one immutable unacknowledged report. It is written
// atomically and fsynced BEFORE HTTP delivery is attempted.
type batchSpool struct {
	path string
}

func openBatchSpool(path string) (*batchSpool, *Batch, error) {
	if path == "" {
		return nil, nil, errors.New("empty pending batch spool path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create spool directory: %w", err)
	}
	// Fail early if the directory is read-only, instead of acknowledging
	// traffic using a silently degraded in-memory path.
	probe, err := os.CreateTemp(dir, ".traffic-probe-*")
	if err != nil {
		return nil, nil, fmt.Errorf("spool directory not writable: %w", err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)

	s := &batchSpool{path: path}
	batch, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	return s, batch, nil
}

func (s *batchSpool) load() (*Batch, error) {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, errors.New("invalid pending batch spool file")
	}
	payload, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load pending batch: %w", err)
	}
	var batch Batch
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&batch); err != nil {
		return nil, fmt.Errorf("corrupt pending batch spool: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid pending batch spool trailing data")
	}
	if err := validateRecoveryBundle(batch); err != nil {
		return nil, err
	}
	return &batch, nil
}

func (s *batchSpool) matches(expected Batch) error {
	actual, err := s.load()
	if err != nil || actual == nil {
		return errors.New("pending batch spool changed or missing")
	}
	actualJSON, actualErr := json.Marshal(actual)
	expectedJSON, expectedErr := json.Marshal(expected)
	if actualErr != nil || expectedErr != nil || !bytes.Equal(actualJSON, expectedJSON) {
		return errors.New("pending batch spool changed or missing")
	}
	return nil
}

func (s *batchSpool) save(batch Batch) error {
	dir := filepath.Dir(s.path)
	if err := validateRecoveryBundle(batch); err != nil {
		return err
	}
	encoded, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if len(encoded) > 64<<20 {
		return errors.New("REPORTING_RECOVERY_BUNDLE_TOO_LARGE")
	}
	tmp, err := os.CreateTemp(dir, ".traffic-write-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	// Exclusive publication refuses to overwrite an older ambiguous batch.
	if err = os.Link(name, s.path); err != nil {
		return err
	}
	if err = syncDirectory(dir); err != nil {
		// Do not deliver an unconfirmed durable write. Remove the
		// uncommitted record before restoring bytes to the tracker.
		_ = os.Remove(s.path)
		return err
	}
	return nil
}

func (s *batchSpool) clear(expected Batch) error {
	if err := s.matches(expected); err != nil {
		return err
	}
	// Preserve the exact bytes, including the representation of legacy spools.
	encoded, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if err := os.Remove(s.path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(s.path)); err != nil {
		// Restore the original record without deleting it again on a repeated
		// directory fsync failure. The failure remains visible: persistent I/O
		// failure cannot certify durability, but a readable record can replay.
		_ = s.restoreAfterClearFailure(encoded)
		return err
	}
	return nil
}

func (s *batchSpool) restoreAfterClearFailure(encoded []byte) error {
	file, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(s.path))
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func validateRecoveryBundle(root Batch) error {
	if len(root.RecoveryTail) > 4095 {
		return errors.New("REPORTING_RECOVERY_BUNDLE_INVALID")
	}
	ids := make(map[string]bool, len(root.RecoveryTail)+1)
	for _, batch := range terminalBatches(root) {
		id := batch.Payload.BatchID
		if id == "" || len(id) > 128 || ids[id] || len(batch.Payload.Traffic) == 0 || len(batch.RecoveryTail) > 0 || batch.MoreTraffic {
			return errors.New("REPORTING_RECOVERY_BUNDLE_INVALID")
		}
		ids[id] = true
		for uid, raw := range batch.Payload.Traffic {
			if uid <= 0 || raw[0] < 0 || raw[1] < 0 {
				return errors.New("invalid pending batch spool traffic")
			}
		}
		if err := validateSpoolTrafficSegments(batch); err != nil {
			return err
		}
	}
	return nil
}
