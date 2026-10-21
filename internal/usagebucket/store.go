package usagebucket

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	DefaultStoreMaxBytes int64 = 64 << 20
	storeMaxFiles              = 4096
	storeMaxRecordBytes        = 512 << 10
	storeControlReserve  int64 = 64 << 10
	storeFileReserve           = 16
)

var (
	ErrStoreEvidence = errors.New("local event evidence invalid")
	ErrStoreRecovery = errors.New("local event store recovery required")
	ErrStoreCapacity = errors.New("local event store capacity reached")
	ErrStoreClosed   = errors.New("local event store closed")
	ErrStoreOwner    = errors.New("local event store already owned")
	ErrStorePlatform = errors.New("local event store requires Linux durability")
)

type StoreOptions struct{ MaxBytes int64 }
type StoreStatus struct {
	StoreID        string
	Sequence       uint64
	Buckets        uint64
	Bytes          int64
	Files          int
	Degraded       bool
	Reason         string
	Closed         bool
	Authorizes     bool
	Attribution    string
	RestoreUnknown bool
	TailUnknown    bool
}

// StoredRecord is a single read-only local observation. It is never a Core
// receipt, billing payload or permission to discard an uncommitted meter tail.
type StoredRecord struct {
	Sequence       uint64
	Kind           string
	Digest         string
	LocalReceiptID string
	BucketDigest   string
	Bucket         *Bucket
	Capture        *Status
	Reasons        []string
	Authorizes     bool
	Attribution    string
	RestoreUnknown bool
	TailUnknown    bool
}

type bucketIndex struct {
	digest   string
	sequence uint64
}
type trackerPosition struct {
	number uint64
	end    uint64
}

// writeMu belongs to the one persistence worker and covers filesystem work.
// statusMu is independent: reading state never waits for a stalled disk sync.
type Store struct {
	writeMu       sync.Mutex
	statusMu      sync.Mutex
	status        StoreStatus
	dir           string
	stateDir      string
	lock          *os.File
	maxBytes      int64
	sequence      uint64
	digest        string
	storeID       string
	processID     string
	usedBytes     int64
	files         int
	index         map[string]bucketIndex
	positions     map[string]trackerPosition
	lastKind      string
	recordDigests map[uint64]string // statusMu protects readers after Open
	reservedBytes int64
	reservedFiles int
	owner         *Coordinator
	attached      bool // statusMu; fast external Close rejection during disk stall
	failed        error
	uncertain     bool
	closed        bool
	fault         func(string) error // instance-local test hook; no process-global state
}

func OpenStore(dir string, options StoreOptions) (*Store, error) {
	return openStore(dir, options, nil)
}

func openStore(dir string, options StoreOptions, fault func(string) error) (*Store, error) {
	if dir == "" {
		return nil, ErrStoreEvidence
	}
	if options.MaxBytes == 0 {
		options.MaxBytes = DefaultStoreMaxBytes
	}
	if options.MaxBytes < 1<<20 || options.MaxBytes > 1<<30 {
		return nil, ErrStoreCapacity
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: absolute, stateDir: absolute + ".state", maxBytes: options.MaxBytes, index: make(map[string]bucketIndex), positions: make(map[string]trackerPosition), recordDigests: make(map[uint64]string), fault: fault}
	// A journal-only restore/removal cannot silently initialize a new history
	// while its independent state directory remains.
	_, journalErr := os.Lstat(s.dir)
	_, stateErr := os.Lstat(s.stateDir)
	if os.IsNotExist(journalErr) && stateErr == nil {
		return nil, ErrStoreRecovery
	}
	if err := durableStoreDirectory(s.dir); err != nil {
		return nil, err
	}
	if err := durableStoreDirectory(s.stateDir); err != nil {
		return nil, err
	}
	s.lock, err = lockStore(s.dir)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = s.lock.Close()
		}
	}()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	s.processID = hex.EncodeToString(id[:])
	if err := s.restore(); err != nil {
		return nil, err
	}
	s.status = StoreStatus{StoreID: s.storeID, Sequence: s.sequence, Bytes: s.usedBytes, Files: s.files, Attribution: "unattributable", RestoreUnknown: true, TailUnknown: true, Buckets: uint64(len(s.index))}
	reasons := []string{"PROCESS_BOUNDARY_UNKNOWN", "UNSYNCED_TAIL_UNKNOWN", "RESTORE_NOT_EXTERNALLY_VERIFIED"}
	if s.sequence == 0 {
		reasons = append(reasons, "NEW_LOCAL_HISTORY_UNVERIFIED")
	} else if s.lastKind != "PROCESS_END" {
		reasons = append(reasons, "UNCLEAN_PROCESS_BOUNDARY")
	}
	if err := s.appendControl("PROCESS_BEGIN", reasons); err != nil {
		return nil, err
	}
	success = true
	return s, nil
}

func durableStoreDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrStoreEvidence
		}
		parent := filepath.Dir(dir)
		if parent != dir {
			return durableStoreDirectory(parent)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return ErrStoreEvidence
	}
	if err := durableStoreDirectory(parent); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	return syncDirectory(parent)
}

func syncDirectory(dir string) error {
	f, err := openStoreFile(dir, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func recordName(seq uint64) string { return fmt.Sprintf("%020d.json", seq) }

func (s *Store) scanDirectory(dir string, limit int) ([]os.DirEntry, error) {
	f, err := openStoreFile(dir, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > limit {
		return nil, ErrStoreCapacity
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func readStoreFile(path string, limit int64) ([]byte, error) {
	f, err := openStoreFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || info.Size() < 0 {
		return nil, ErrStoreEvidence
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrStoreEvidence
	}
	return data, nil
}

func (s *Store) restore() error {
	s.files = 1 // Include the single exclusive-lock file in the hard limit.
	stateEntries, err := s.scanDirectory(s.stateDir, storeFileReserve)
	if err != nil {
		return err
	}
	var head *journalHead
	for _, entry := range stateEntries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return ErrStoreEvidence
		}
		s.files++
		s.usedBytes += info.Size()
		if entry.Name() != "head.json" {
			return ErrStoreRecovery
		}
		data, err := readStoreFile(filepath.Join(s.stateDir, entry.Name()), 4096)
		if err != nil {
			return err
		}
		head = &journalHead{}
		if err := decodeCanonical(data, head); err != nil {
			return err
		}
		if head.Version != 1 || !validHex(head.StoreID, 32) || head.Authorizes || head.Attribution != "unattributable" || !head.RestoreUnknown || (head.Sequence == 0 && head.Digest != "") || (head.Sequence > 0 && !validHex(head.Digest, 64)) {
			return ErrStoreEvidence
		}
		s.storeID = head.StoreID
	}
	entries, err := s.scanDirectory(s.dir, storeMaxFiles)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return ErrStoreEvidence
		}
		s.files++
		s.usedBytes += info.Size()
		if s.usedBytes > s.maxBytes || s.files > storeMaxFiles {
			return ErrStoreCapacity
		}
		if strings.HasPrefix(entry.Name(), ".pending-") {
			return ErrStoreRecovery
		}
		if head == nil || s.sequence == math.MaxUint64 || entry.Name() != recordName(s.sequence+1) {
			return ErrStoreRecovery
		}
		data, err := readStoreFile(filepath.Join(s.dir, entry.Name()), storeMaxRecordBytes)
		if err != nil {
			return err
		}
		var envelope journalEnvelope
		if err := decodeCanonical(data, &envelope); err != nil {
			return err
		}
		r := envelope.Record
		payload, _ := json.Marshal(r)
		if err := validateRecord(r); err != nil {
			return err
		}
		if r.StoreID != s.storeID || r.Sequence != s.sequence+1 || r.PreviousDigest != s.digest || envelope.Digest != digestBytes(payload) {
			return ErrStoreEvidence
		}
		if r.Kind == "BUCKET" {
			key := diskBucketKey(r.Bucket)
			if _, exists := s.index[key]; exists {
				return ErrStoreEvidence
			}
			if err := s.checkPosition(r.Bucket); err != nil {
				return err
			}
			s.index[key] = bucketIndex{r.Receipt.BucketDigest, r.Sequence}
			s.positions[r.Bucket.Tracker] = trackerPosition{r.Bucket.Number, r.Bucket.End}
		}
		s.sequence = r.Sequence
		s.digest = envelope.Digest
		s.lastKind = r.Kind
		s.recordDigests[r.Sequence] = envelope.Digest
	}
	if head != nil {
		if head.Sequence != s.sequence || head.Digest != s.digest {
			return ErrStoreRecovery
		}
		return nil
	}
	// Completely absent local history is distinguishable neither from first
	// installation nor whole-directory deletion/restore. The record says so.
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	s.storeID = hex.EncodeToString(id[:])
	if err := s.persistHead(journalHead{Version: 1, StoreID: s.storeID, Attribution: "unattributable", RestoreUnknown: true}); err != nil {
		return err
	}
	s.files = 2
	info, err := os.Stat(filepath.Join(s.stateDir, "head.json"))
	if err != nil {
		return err
	}
	s.usedBytes = info.Size()
	return nil
}

func (s *Store) checkPosition(b *diskBucket) error {
	last, exists := s.positions[b.Tracker]
	if !exists {
		if b.Number != 1 || b.Start != 1 {
			return ErrStoreEvidence
		}
		return nil
	}
	if last.number == math.MaxUint64 || b.Number != last.number+1 || b.Start != last.end {
		return ErrStoreEvidence
	}
	return nil
}

func (s *Store) hook(stage string) error {
	if s.fault != nil {
		return s.fault(stage)
	}
	return nil
}

func (s *Store) persistHead(head journalHead) error {
	data, err := json.Marshal(head)
	if err != nil {
		return err
	}
	path := filepath.Join(s.stateDir, fmt.Sprintf(".pending-head-%020d", head.Sequence))
	f, err := openStoreFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := s.hook("before_head_sync"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := s.hook("after_head_sync"); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := s.hook("before_head_publish"); err != nil {
		return err
	}
	if err := os.Rename(path, filepath.Join(s.stateDir, "head.json")); err != nil {
		return err
	}
	if err := s.hook("before_head_dir_sync"); err != nil {
		return err
	}
	if err := syncDirectory(s.stateDir); err != nil {
		return err
	}
	return s.hook("after_head_dir_sync")
}

func (s *Store) persistRecord(record journalRecord, control bool) (string, error) {
	if s.sequence == math.MaxUint64 {
		return "", ErrStoreCapacity
	}
	if err := validateRecord(record); err != nil {
		return "", err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	digest := digestBytes(payload)
	data := encodeJournalEnvelope(payload, digest)
	byteLimit, fileLimit := s.maxBytes-storeControlReserve, storeMaxFiles-storeFileReserve
	if control {
		byteLimit = s.maxBytes
		fileLimit = storeMaxFiles
	}
	// Account for candidate, duplicate pending link and independent head temp.
	// Conservative reservation keeps actual disk evidence under hard limits.
	if len(data) > storeMaxRecordBytes || s.usedBytes+int64(2*len(data))+8192 > byteLimit || s.files+4 > fileLimit {
		return "", ErrStoreCapacity
	}
	if err := s.hook("before_write"); err != nil {
		return "", err
	}
	s.reservedBytes = int64(2*len(data)) + 8192
	s.reservedFiles = 4
	pending := filepath.Join(s.dir, fmt.Sprintf(".pending-%020d", record.Sequence))
	f, err := openStoreFile(pending, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s.uncertain = true
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := s.hook("before_file_sync"); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := s.hook("after_file_sync"); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := s.hook("before_publish"); err != nil {
		return "", err
	}
	if err := os.Link(pending, filepath.Join(s.dir, recordName(record.Sequence))); err != nil {
		return "", err
	}
	if err := s.hook("before_dir_sync"); err != nil {
		return "", err
	}
	if err := syncDirectory(s.dir); err != nil {
		return "", err
	}
	if err := s.hook("after_dir_sync"); err != nil {
		return "", err
	}
	if err := s.persistHead(journalHead{Version: 1, StoreID: s.storeID, Sequence: record.Sequence, Digest: digest, Attribution: "unattributable", RestoreUnknown: true}); err != nil {
		return "", err
	}
	if err := s.hook("before_pending_remove"); err != nil {
		return "", err
	}
	if err := os.Remove(pending); err != nil {
		return "", err
	}
	if err := s.hook("before_cleanup_dir_sync"); err != nil {
		return "", err
	}
	if err := syncDirectory(s.dir); err != nil {
		return "", err
	}
	// Every gate succeeded. State publication and meter release are separate;
	// a lost local ACK must not create another record or different identity.
	s.uncertain = false
	s.reservedBytes = 0
	s.reservedFiles = 0
	s.sequence = record.Sequence
	s.digest = digest
	s.lastKind = record.Kind
	s.usedBytes += int64(len(data)) + 128
	s.files++
	s.statusMu.Lock()
	s.recordDigests[record.Sequence] = digest
	s.statusMu.Unlock()
	s.updateStatus()
	return digest, nil
}

// payload is the canonical json.Marshal(record) output and digest is its SHA-256
// hex string. Reusing those bytes preserves the envelope without encoding the
// complete record a second time.
func encodeJournalEnvelope(payload []byte, digest string) []byte {
	data := make([]byte, 0, len(payload)+len(digest)+25)
	data = append(data, `{"record":`...)
	data = append(data, payload...)
	data = append(data, `,"digest":"`...)
	data = append(data, digest...)
	return append(data, '"', '}')
}

func (s *Store) updateStatus() {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.StoreID = s.storeID
	s.status.Sequence = s.sequence
	s.status.Buckets = uint64(len(s.index))
	s.status.Bytes = s.usedBytes + s.reservedBytes
	s.status.Files = s.files + s.reservedFiles
	s.status.Closed = s.closed
	if s.failed != nil {
		s.status.Degraded = true
		s.status.Reason = storeErrorReason(s.failed)
	}
}

func storeErrorReason(err error) string {
	switch {
	case errors.Is(err, ErrStoreCapacity):
		return "STORE_CAPACITY_REACHED"
	case errors.Is(err, ErrStoreEvidence):
		return "STORE_EVIDENCE_INVALID"
	case errors.Is(err, ErrStoreRecovery):
		return "STORE_RECOVERY_REQUIRED"
	default:
		return "STORE_IO_FAILED"
	}
}

func (s *Store) appendControl(kind string, reasons []string) error {
	r := journalRecord{Version: 1, StoreID: s.storeID, ProcessID: s.processID, Sequence: s.sequence + 1, PreviousDigest: s.digest, Kind: kind, Attribution: "unattributable", RestoreUnknown: true, TailUnknown: true, Reasons: reasons}
	_, err := s.persistRecord(r, true)
	return err
}

func (s *Store) persistClaim(claim *bucketClaim) (durableReceipt, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed {
		return durableReceipt{}, ErrStoreClosed
	}
	if s.failed != nil {
		return durableReceipt{}, s.failed
	}
	b := bucketToDisk(claim.bucket)
	if err := validateDiskBucket(&b); err != nil {
		s.failed = err
		s.updateStatus()
		return durableReceipt{}, err
	}
	data, _ := json.Marshal(b)
	digest := digestBytes(data)
	key := bucketKey(claim.bucket)
	claim.meter.mu.Lock()
	if claim.meter.claim != claim {
		claim.meter.mu.Unlock()
		return durableReceipt{}, ErrStoreEvidence
	}
	claim.digest = digest
	claim.meter.mu.Unlock()
	if old, exists := s.index[key]; exists {
		if old.digest != digest {
			s.failed = ErrStoreEvidence
			s.updateStatus()
			return durableReceipt{}, s.failed
		}
		return durableReceipt{s, claim, key, digest, old.sequence, true}, nil
	}
	if err := s.checkPosition(&b); err != nil {
		s.failed = err
		s.updateStatus()
		return durableReceipt{}, err
	}
	capture := claim.status
	reasons := []string{"AUTHORIZATION_BOUNDARY_UNKNOWN", "UNSYNCED_TAIL_UNKNOWN"}
	if capture.Stopped {
		reasons = append(reasons, capture.StopReason)
	}
	r := journalRecord{Version: 1, StoreID: s.storeID, ProcessID: s.processID, Sequence: s.sequence + 1, PreviousDigest: s.digest, Kind: "BUCKET", Attribution: "unattributable", RestoreUnknown: true, TailUnknown: true, Reasons: reasons, Bucket: &b, Capture: &diskCapture{capture.Degraded, capture.Reason, capture.Generation, capture.NextSequence, capture.DroppedEvents, eventToDisk(capture.FirstGap), true}, Receipt: &localReceipt{"local_receipt", "local:" + s.storeID + ":" + fmt.Sprint(s.sequence+1), false, digest, "unattributable", true}}
	_, err := s.persistRecord(r, false)
	if err != nil {
		s.failed = err
		s.updateStatus()
		return durableReceipt{}, err
	}
	s.index[key] = bucketIndex{digest, r.Sequence}
	s.positions[b.Tracker] = trackerPosition{b.Number, b.End}
	s.updateStatus()
	return durableReceipt{s, claim, key, digest, r.Sequence, true}, nil
}

func (s *Store) Status() StoreStatus { s.statusMu.Lock(); defer s.statusMu.Unlock(); return s.status }

func (s *Store) Read(sequence uint64) (StoredRecord, error) {
	s.statusMu.Lock()
	status := s.status
	expected := s.recordDigests[sequence]
	previous := s.recordDigests[sequence-1]
	s.statusMu.Unlock()
	if sequence == 0 || sequence > status.Sequence || expected == "" {
		return StoredRecord{}, ErrStoreEvidence
	}
	data, err := readStoreFile(filepath.Join(s.dir, recordName(sequence)), storeMaxRecordBytes)
	if err != nil {
		return StoredRecord{}, err
	}
	var envelope journalEnvelope
	if err := decodeCanonical(data, &envelope); err != nil {
		return StoredRecord{}, err
	}
	r := envelope.Record
	payload, _ := json.Marshal(r)
	if err := validateRecord(r); err != nil {
		return StoredRecord{}, err
	}
	if r.StoreID != status.StoreID || r.Sequence != sequence || r.PreviousDigest != previous || envelope.Digest != digestBytes(payload) || envelope.Digest != expected {
		return StoredRecord{}, ErrStoreEvidence
	}
	result := StoredRecord{Sequence: r.Sequence, Kind: r.Kind, Digest: envelope.Digest, Reasons: append([]string{}, r.Reasons...), Attribution: r.Attribution, RestoreUnknown: r.RestoreUnknown, TailUnknown: r.TailUnknown}
	if r.Bucket != nil {
		bucket := r.Bucket.memory()
		result.Bucket = &bucket
		result.LocalReceiptID = r.Receipt.ID
		result.BucketDigest = r.Receipt.BucketDigest
		result.Capture = &Status{Degraded: r.Capture.Degraded, Reason: r.Capture.Reason, Generation: r.Capture.Generation, NextSequence: r.Capture.Next, DroppedEvents: r.Capture.Dropped, FirstGap: r.Capture.FirstGap.memory(), VolatileTailUnknown: true}
		// Runtime stop metadata uses existing reason labels; the fixed disk
		// schema and every older record stay readable without rewriting hashes.
		for _, reason := range r.Reasons {
			if reason == "RETIRED_TAIL_UNKNOWN" || reason == "SHUTDOWN_TAIL_UNKNOWN" {
				result.Capture.Stopped = true
				result.Capture.StopReason = reason
			}
		}
	}
	return result, nil
}

// Close releases an unattached store. The coordinator alone closes an attached
// store after its worker stops; another caller cannot close a sync's live FD.
func (s *Store) Close() error {
	s.statusMu.Lock()
	attached := s.attached
	s.statusMu.Unlock()
	if attached {
		return ErrStoreOwner
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.owner != nil {
		return ErrStoreOwner
	}
	return s.closeLocked()
}

func (s *Store) closeLocked() error {
	if s.closed {
		return s.failed
	}
	var err error
	if s.failed == nil {
		err = s.appendControl("PROCESS_END", []string{"UNSEALED_TAIL_UNKNOWN", "RESTORE_NOT_EXTERNALLY_VERIFIED"})
	} else if !s.uncertain {
		err = s.appendControl("STORE_STOP", []string{"UNCOMMITTED_TAIL_UNKNOWN", storeErrorReason(s.failed)})
	}
	if err != nil && s.failed == nil {
		s.failed = err
	}
	s.closed = true
	if closeErr := s.lock.Close(); closeErr != nil && s.failed == nil {
		s.failed = closeErr
	}
	s.updateStatus()
	return s.failed
}
