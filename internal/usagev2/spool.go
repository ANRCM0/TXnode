package usagev2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const DefaultSpoolBytes int64 = 64 << 20

type Record struct {
	SchemaVersion   int              `json:"schema_version"`
	Session         Session          `json:"session"`
	Submission      Submission       `json:"submission"`
	Receipt         *Receipt         `json:"receipt,omitempty"`
	LocalQuarantine *LocalQuarantine `json:"local_quarantine,omitempty"`
}

type Spool struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
	lock     *os.File
	// Hooks are private fault-injection points; production uses real fsync.
	syncFile func(*os.File) error
	syncDir  func(string) error
}

func OpenSpool(dir string, maxBytes int64) (*Spool, error) {
	if dir == "" {
		return nil, errors.New("usage v2 requires independent durable spool directory")
	}
	if maxBytes == 0 {
		maxBytes = DefaultSpoolBytes
	}
	if maxBytes < MaxPayloadBytes*2 {
		return nil, errors.New("usage v2 spool capacity too small")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("usage v2 spool directory must not be a symlink")
	}
	lock, err := lockDirectory(dir)
	if err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, maxBytes: maxBytes, lock: lock, syncFile: func(f *os.File) error { return f.Sync() }, syncDir: syncUsageDirectory}
	if _, err := s.Records(); err != nil {
		s.Close()
		return nil, err
	}
	// Exercise the same file and directory durability path before traffic starts.
	probe, err := os.CreateTemp(dir, ".usage-probe-")
	if err != nil {
		s.Close()
		return nil, err
	}
	name := probe.Name()
	err = s.syncFile(probe)
	closeErr := probe.Close()
	removeErr := os.Remove(name)
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = removeErr
	}
	if err == nil {
		err = s.syncDir(dir)
	}
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("usage v2 spool durability unavailable: %w", err)
	}
	return s, nil
}

func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

func recordName(r Record) string {
	p := r.Submission.Payload
	hash := sha256.Sum256([]byte(r.Session.CoreInstanceID + "\x00" + p.NodeID + "\x00" + p.SourceEpoch + "\x00" + p.BatchID))
	return hex.EncodeToString(hash[:]) + ".usage.json"
}

func (r Record) Validate() error {
	if r.SchemaVersion != 1 {
		return errors.New("unsupported usage v2 spool schema")
	}
	if err := r.Session.Validate(); err != nil {
		return err
	}
	if err := r.Submission.Validate(); err != nil {
		return err
	}
	if r.Session.NodeID != r.Submission.Payload.NodeID || r.Session.SourceEpoch != r.Submission.Payload.SourceEpoch {
		return ErrReceiptMismatch
	}
	if err := validateLocalQuarantine(r); err != nil {
		return err
	}
	if r.Receipt != nil {
		return r.Receipt.Validate(r.Session, r.Submission)
	}
	return nil
}

func readRecord(path string) (Record, error) {
	var r Record
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return r, err
	}
	if !info.Mode().IsRegular() {
		return r, errors.New("usage v2 spool record is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxPayloadBytes*3+1))
	if err != nil {
		return r, err
	}
	if err := StrictDecode(b, &r, MaxPayloadBytes*3); err != nil {
		return r, fmt.Errorf("corrupt usage v2 spool (preserved): %w", err)
	}
	return r, r.Validate()
}

func (s *Spool) Records() ([]Record, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.records() }

func (s *Spool) records() ([]Record, error) {
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		if file.Type()&os.ModeSymlink != 0 || file.IsDir() {
			return nil, errors.New("unsafe usage v2 spool record")
		}
		r, err := readRecord(filepath.Join(s.dir, file.Name()))
		if err != nil {
			return nil, err
		}
		if file.Name() != recordName(r) {
			return nil, errors.New("usage v2 spool record identity filename mismatch")
		}
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i].Submission.Payload, records[j].Submission.Payload
		if a.StartedAt != b.StartedAt {
			return a.StartedAt < b.StartedAt
		}
		return recordName(records[i]) < recordName(records[j])
	})
	return records, nil
}

// Save never overwrites a conflicting identity. A failure after rename keeps
// the original record and batch ID: the caller must retry the same submission,
// never restore its bytes to an unrelated batch or send without confirmed fsync.
func (s *Spool) Save(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return errors.New("usage v2 spool closed")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	path := filepath.Join(s.dir, recordName(r))
	old, err := readRecord(path)
	if err == nil {
		if old.Submission.PayloadDigest != r.Submission.PayloadDigest {
			return ErrPayloadConflict
		}
		if old.Session.CoreInstanceID != r.Session.CoreInstanceID || old.Session.ReceiptGeneration != r.Session.ReceiptGeneration {
			return ErrRecoveryRequired
		}
		oldSession, _ := json.Marshal(old.Session)
		newSession, _ := json.Marshal(r.Session)
		if string(oldSession) != string(newSession) {
			return errors.New("cannot change immutable usage batch session")
		}
		if old.LocalQuarantine != nil && (r.LocalQuarantine == nil || *old.LocalQuarantine != *r.LocalQuarantine) {
			return ErrRecoveryRequired
		}
		if r.Receipt == nil && old.Receipt != nil {
			return errors.New("cannot discard stored usage receipt")
		}
		if old.Receipt != nil && r.Receipt != nil {
			if old.Receipt.ReceiptID != r.Receipt.ReceiptID || old.Receipt.AcceptedAt != r.Receipt.AcceptedAt {
				return ErrReceiptMismatch
			}
			if old.Receipt.SettlementStatus == "settled" && r.Receipt.SettlementStatus != "settled" {
				return errors.New("cannot regress settled usage receipt")
			}
			if old.Receipt.SettledAt != nil && (r.Receipt.SettledAt == nil || *old.Receipt.SettledAt != *r.Receipt.SettledAt) {
				return ErrReceiptMismatch
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if retired, err := s.retired(r); err != nil || retired {
		return err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var used int64
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			info, err := file.Info()
			if err != nil {
				return err
			}
			if filepath.Join(s.dir, file.Name()) != path {
				used += info.Size()
			}
		}
	}
	if used+int64(len(encoded)) > s.maxBytes {
		return errors.New("usage v2 spool capacity reached; collection must backpressure")
	}
	return s.atomicWrite(path, encoded)
}

func (s *Spool) atomicWrite(path string, encoded []byte) error {
	tmp, err := os.CreateTemp(s.dir, ".usage-write-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return err
	}
	if err := s.syncFile(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return s.syncDir(s.dir)
}

// BindSession persists negotiated recovery parameters even before the first
// batch. A new source epoch can coexist with old pending records, but a new
// Core or receipt generation requires an explicit recovery procedure.
func (s *Spool) BindSession(session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return errors.New("usage v2 spool closed")
	}
	if err := session.Validate(); err != nil {
		return err
	}
	path := filepath.Join(s.dir, ".usage-session")
	data, err := readSessionBytes(path)
	if err == nil {
		var old Session
		if err := StrictDecode(data, &old, MaxPayloadBytes); err != nil {
			return err
		}
		if err := old.Validate(); err != nil {
			return err
		}
		if old.CoreInstanceID != session.CoreInstanceID || old.NodeID != session.NodeID {
			return ErrReceiptMismatch
		}
		if old.ReceiptGeneration != session.ReceiptGeneration {
			return ErrRecoveryRequired
		}
		// Numeric source epochs are monotonic within the same node domain.
		if len(session.SourceEpoch) < len(old.SourceEpoch) || (len(session.SourceEpoch) == len(old.SourceEpoch) && session.SourceEpoch < old.SourceEpoch) {
			return errors.New("usage source epoch rollback requires recovery")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		return err
	}
	if len(encoded) > MaxPayloadBytes {
		return errors.New("usage session exceeds byte limit")
	}
	return s.atomicWrite(path, encoded)
}

func readSessionBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("unsafe usage session metadata")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxPayloadBytes+1))
}

func syncUsageDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// CheckHandoff does not read or rewrite the legacy payload. Only absence of
// the exact v1 pending file and explicitly empty collector counters permits a
// new v2 collector; live protocol changes are unsupported.
func CheckHandoff(legacyPendingPath string, countersEmpty bool) error {
	if !countersEmpty {
		return errors.New("usage v2 requires explicit empty counter handoff")
	}
	if legacyPendingPath == "" {
		return errors.New("usage v2 requires exact legacy pending path")
	}
	_, err := os.Lstat(legacyPendingPath)
	if err == nil {
		return errors.New("usage v1 pending must drain before enabling v2")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
