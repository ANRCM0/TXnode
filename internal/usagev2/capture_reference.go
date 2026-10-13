package usagev2

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// ConfirmCapture checks an immutable producer capture under the current spool
// owner's lock. It never writes or discards a Core receipt. Closed-spool reads
// are not evidence that this writer still owns the durable reporting path.
func (s *Spool) ConfirmCapture(r Record) (bool, error) {
	if s == nil {
		return false, errors.New("usage v2 spool missing")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return false, errors.New("usage v2 spool closed")
	}
	if r.Receipt != nil || r.Validate() != nil {
		return false, errors.New("invalid producer capture")
	}
	path := filepath.Join(s.dir, recordName(r))
	old, err := readRecord(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if old.Submission.PayloadDigest != r.Submission.PayloadDigest {
		return false, ErrPayloadConflict
	}
	left, _ := json.Marshal(old.Session)
	right, _ := json.Marshal(r.Session)
	if !bytes.Equal(left, right) {
		return false, ErrReceiptMismatch
	}
	// An earlier Save may have published the file but failed directory fsync.
	// Reconfirm both durable edges while retaining the exact original receipt.
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	err = s.syncFile(f)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return false, err
	}
	if err := s.syncDir(s.dir); err != nil {
		return false, err
	}
	return true, nil
}
