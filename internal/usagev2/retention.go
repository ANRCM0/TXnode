package usagev2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

type retiredCapture struct {
	Query         Query   `json:"query"`
	Core          string  `json:"core"`
	Generation    string  `json:"generation"`
	SessionDigest string  `json:"session_digest"`
	Receipt       Receipt `json:"receipt"`
	KeepUntil     int64   `json:"keep_until"`
}

func sessionDigest(session Session) string {
	raw, _ := json.Marshal(session)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *Spool) retired(r Record) (bool, error) {
	directory := filepath.Join(s.dir, ".usage-retired")
	info, err := os.Lstat(directory)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, ErrRecoveryRequired
	}
	path := filepath.Join(directory, recordName(r))
	raw, err := readSessionBytes(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var saved retiredCapture
	if StrictDecode(raw, &saved, MaxPayloadBytes) != nil || saved.Query != r.Submission.Query() ||
		saved.Core != r.Session.CoreInstanceID || saved.Generation != r.Session.ReceiptGeneration ||
		saved.SessionDigest != sessionDigest(r.Session) || saved.Receipt.SettlementStatus != "settled" ||
		saved.Receipt.Validate(r.Session, r.Submission) != nil {
		return false, ErrRecoveryRequired
	}
	return true, nil
}

// PruneSettled retains complete payloads until both negotiated windows expire.
// A durable settled tombstone precedes removal; unconfirmed/pending/quarantined
// records are never reclaimed by age or by an HTTP success status.
func (s *Spool) PruneSettled(now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return ErrRecoveryRequired
	}
	records, err := s.records()
	if err != nil {
		return err
	}
	dir := filepath.Join(s.dir, ".usage-retired")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrRecoveryRequired
	}
	if err := s.syncDir(s.dir); err != nil {
		return err
	}
	for _, record := range records {
		receipt := record.Receipt
		if receipt == nil || receipt.SettlementStatus != "settled" ||
			now < record.Submission.Payload.EndedAt || now-record.Submission.Payload.EndedAt < record.Session.RetentionSeconds ||
			now < receipt.AcceptedAt || now-receipt.AcceptedAt < record.Session.ReceiptRetentionSeconds {
			continue
		}
		saved := retiredCapture{record.Submission.Query(), record.Session.CoreInstanceID, record.Session.ReceiptGeneration,
			sessionDigest(record.Session), *receipt, now + record.Session.MaxLateReportSeconds}
		raw, err := json.Marshal(saved)
		if err != nil {
			return err
		}
		if err := s.atomicWrite(filepath.Join(dir, recordName(record)), raw); err != nil {
			return err
		}
		if err := s.syncDir(dir); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(s.dir, recordName(record))); err != nil {
			return err
		}
		if err := s.syncDir(s.dir); err != nil {
			return err
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return ErrRecoveryRequired
		}
		raw, err := readSessionBytes(filepath.Join(dir, file.Name()))
		var saved retiredCapture
		if err != nil || StrictDecode(raw, &saved, MaxPayloadBytes) != nil {
			return ErrRecoveryRequired
		}
		if now >= saved.KeepUntil {
			if err := os.Remove(filepath.Join(dir, file.Name())); err != nil {
				return err
			}
		}
	}
	return s.syncDir(dir)
}
