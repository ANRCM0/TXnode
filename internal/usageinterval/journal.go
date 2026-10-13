package usageinterval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

const maxJournalFile = 1 << 20
const maxJournalRecords = 128

var collectorName = regexp.MustCompile(`^[a-f0-9]{32}$`)
var journalName = regexp.MustCompile(`^[a-f0-9]{32}-[0-9]{20}\.json$`)

type journalRecord struct {
	Version    int                `json:"version"`
	Collector  string             `json:"collector"`
	Interval   uint64             `json:"interval,string"`
	Session    usagev2.Session    `json:"session"`
	Submission usagev2.Submission `json:"submission"`
	Evidence   []Evidence         `json:"evidence"`
}
type envelope struct {
	Record journalRecord `json:"record"`
	Digest string        `json:"digest"`
}
type claim struct {
	Record  journalRecord
	encoded []byte
}

// Journal publishes immutable sealed evidence before exporting the original
// batch to the existing spool. It never acknowledges Core or deletes history.
type Journal struct {
	mu       sync.Mutex
	dir      string
	lock     *os.File
	spool    *usagev2.Spool
	current  usagev2.Session
	syncFile func(*os.File) error
	syncDir  func(string) error
	fault    func(string) error
}

func OpenJournal(dir string, session usagev2.Session, spool *usagev2.Spool) (*Journal, error) {
	if dir == "" || spool == nil || session.Validate() != nil || len(session.Grants) > MaxGrants {
		return nil, ErrUnknown
	}
	if err := durableJournalDirectory(filepath.Clean(dir)); err != nil {
		return nil, ErrUnknown
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnknown
	}
	lock, err := lockJournal(dir)
	if err != nil {
		return nil, ErrUnknown
	}
	frozen, _ := json.Marshal(session)
	var copy usagev2.Session
	_ = json.Unmarshal(frozen, &copy)
	j := &Journal{dir: dir, lock: lock, spool: spool, current: copy, syncFile: func(f *os.File) error { return f.Sync() }, syncDir: syncDirectory}
	if err := spool.BindSession(copy); err != nil {
		j.Close()
		return nil, err
	}
	if err := j.Recover(); err != nil {
		j.Close()
		return nil, err
	}
	return j, nil
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (j *Journal) hook(stage string) error {
	if j.fault != nil {
		return j.fault(stage)
	}
	return nil
}

func makeClaim(id string, sequence uint64, session usagev2.Session, submission usagev2.Submission, evidence []Evidence) (*claim, error) {
	record := journalRecord{1, id, sequence, session, submission, evidence}
	if validateRecord(record) != nil {
		return nil, ErrUnknown
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, ErrUnknown
	}
	digest := sha256.Sum256(raw)
	encoded, err := json.Marshal(envelope{record, hex.EncodeToString(digest[:])})
	if err != nil || len(encoded) > maxJournalFile {
		return nil, ErrUnknown
	}
	// Round-trip freezes all slices; caller-owned grant/evidence cannot drift.
	var frozen envelope
	if usagev2.StrictDecode(encoded, &frozen, maxJournalFile) != nil {
		return nil, ErrUnknown
	}
	return &claim{frozen.Record, encoded}, nil
}

func validateRecord(r journalRecord) error {
	if r.Version != 1 || !collectorName.MatchString(r.Collector) || r.Interval == 0 || len(r.Session.Grants) > MaxGrants || len(r.Evidence) == 0 || len(r.Evidence) > MaxOperations || r.Session.Validate() != nil {
		return ErrUnknown
	}
	if (usagev2.Record{SchemaVersion: 1, Session: r.Session, Submission: r.Submission}).Validate() != nil {
		return ErrUnknown
	}
	grants := map[string]usagev2.Grant{}
	for _, g := range r.Session.Grants {
		grants[g.UserID] = g
	}
	raw := map[int][2]int64{}
	seen := map[uint64]bool{}
	start, end := r.Submission.Payload.StartedAt, r.Submission.Payload.EndedAt
	if start > 9223372036 || end > 9223372036 {
		return ErrUnknown
	}
	for _, e := range r.Evidence {
		id, err := strconv.Atoi(e.UserID)
		g, exists := grants[e.UserID]
		if err != nil || id <= 0 || id > 2147483647 || strconv.Itoa(id) != e.UserID || !exists || e.Sequence == 0 || seen[e.Sequence] || !validStamp(e.Started) || !validStamp(e.Completed) || e.Started.Wall < start*int64(time.Second) || e.Completed.Wall >= end*int64(time.Second) || e.Completed.Wall < e.Started.Wall || e.Completed.Elapsed < e.Started.Elapsed || !insideGrant(g, e.Started.Wall) || !insideGrant(g, e.Completed.Wall) || e.Bytes < 0 || e.Bytes > int64(usagev2.MaxRawBytes) {
			return ErrUnknown
		}
		seen[e.Sequence] = true
		v := raw[id]
		index := 0
		if e.Direction == "download" {
			index = 1
		} else if e.Direction != "upload" {
			return ErrUnknown
		}
		if e.Bytes > int64(usagev2.MaxRawBytes)-v[index] {
			return ErrUnknown
		}
		v[index] += e.Bytes
		raw[id] = v
	}
	expected, err := r.Session.Build(start, end, raw)
	if err != nil {
		return ErrUnknown
	}
	expected.Payload.BatchID = r.Submission.Payload.BatchID
	left, _ := expected.Payload.Canonical()
	right, _ := r.Submission.Payload.Canonical()
	if !bytes.Equal(left, right) {
		return ErrUnknown
	}
	return nil
}

func decodeClaim(raw []byte) (*claim, error) {
	var e envelope
	if usagev2.StrictDecode(raw, &e, maxJournalFile) != nil || validateRecord(e.Record) != nil {
		return nil, ErrUnknown
	}
	encoded, err := json.Marshal(e)
	if err != nil || !bytes.Equal(encoded, raw) {
		return nil, ErrUnknown
	}
	payload, _ := json.Marshal(e.Record)
	hash := sha256.Sum256(payload)
	if e.Digest != hex.EncodeToString(hash[:]) {
		return nil, ErrUnknown
	}
	return &claim{e.Record, raw}, nil
}
func (j *Journal) path(c *claim) string {
	return filepath.Join(j.dir, fmt.Sprintf("%s-%020d.json", c.Record.Collector, c.Record.Interval))
}
func readClaimFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxJournalFile || info.Size() <= 0 {
		return nil, ErrUnknown
	}
	return os.ReadFile(path)
}
func (j *Journal) compatible(c *claim) bool {
	s := c.Record.Session
	return s.CoreInstanceID == j.current.CoreInstanceID && s.NodeID == j.current.NodeID && s.ReceiptGeneration == j.current.ReceiptGeneration && (len(s.SourceEpoch) < len(j.current.SourceEpoch) || len(s.SourceEpoch) == len(j.current.SourceEpoch) && s.SourceEpoch <= j.current.SourceEpoch)
}

func (j *Journal) commit(c *claim) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil || c == nil || !j.compatible(c) {
		return ErrUnknown
	}
	if err := j.persist(c); err != nil {
		return err
	}
	if err := j.hook("before_spool"); err != nil {
		return err
	}
	if err := j.export(c); err != nil {
		return err
	}
	return j.hook("after_spool")
}

func (j *Journal) persist(c *claim) error {
	path := j.path(c)
	raw, err := readClaimFile(path)
	if err == nil {
		if !bytes.Equal(raw, c.encoded) {
			return ErrUnknown
		}
		// A previous publication may have failed directory fsync. Confirm both
		// durable edges before considering a retry ready for spool export.
		f, err := os.Open(path)
		if err != nil {
			return ErrUnknown
		}
		err = j.syncFile(f)
		_ = f.Close()
		if err != nil {
			return err
		}
		return j.syncDir(j.dir)
	}
	if !os.IsNotExist(err) {
		return ErrUnknown
	}
	files, err := boundedDirectory(j.dir)
	if err != nil || len(files) > maxJournalRecords+4 {
		return ErrUnknown
	}
	count := 0
	for _, f := range files {
		if journalName.MatchString(f.Name()) {
			count++
		}
	}
	if count >= maxJournalRecords {
		return ErrUnknown
	}
	file, err := os.CreateTemp(j.dir, ".interval-intent-")
	if err != nil {
		return ErrUnknown
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(c.encoded)
	}
	if err == nil {
		err = j.hook("before_file_sync")
	}
	if err == nil {
		err = j.syncFile(file)
	}
	if err == nil {
		err = j.hook("after_file_sync")
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Link(name, path); err != nil {
		return ErrUnknown
	}
	if err = j.hook("after_publish"); err != nil {
		return err
	}
	if err = j.syncDir(j.dir); err != nil {
		return err
	}
	return j.hook("after_dir_sync")
}

func (j *Journal) export(c *claim) error {
	capture := usagev2.Record{SchemaVersion: 1, Session: c.Record.Session, Submission: c.Record.Submission}
	confirmed, err := j.spool.ConfirmCapture(capture)
	if err != nil {
		return err
	}
	existing, err := j.spool.Records()
	if err != nil {
		return err
	}
	for _, old := range existing {
		oldPayload, newPayload := old.Submission.Payload, c.Record.Submission.Payload
		sameBatch := oldPayload.NodeID == newPayload.NodeID && oldPayload.SourceEpoch == newPayload.SourceEpoch && oldPayload.BatchID == newPayload.BatchID
		if !sameBatch && oldPayload.NodeID == newPayload.NodeID && oldPayload.StartedAt < newPayload.EndedAt && newPayload.StartedAt < oldPayload.EndedAt {
			return ErrUnknown
		}

	}
	if confirmed {
		return nil
	}

	return j.spool.Save(usagev2.Record{SchemaVersion: 1, Session: c.Record.Session, Submission: c.Record.Submission})
}

// Recover re-exports only bounded complete sealed records. It does not resume a
// process timeline; absence of a record proves nothing about pre-crash traffic.
func (j *Journal) Recover() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return ErrUnknown
	}
	files, err := boundedDirectory(j.dir)
	if err != nil || len(files) > maxJournalRecords+4 {
		return ErrUnknown
	}
	var names []string
	for _, f := range files {
		if f.Name() == ".interval-lock" || f.Name() == ".interval-source" || len(f.Name()) > 17 && f.Name()[:17] == ".interval-intent-" {
			continue
		}
		if !journalName.MatchString(f.Name()) || f.IsDir() {
			return ErrUnknown
		}
		names = append(names, f.Name())
	}
	if len(names) > maxJournalRecords {
		return ErrUnknown
	}
	sort.Strings(names)
	type position struct {
		interval uint64
		end      int64
		sequence uint64
	}
	positions := map[string]position{}
	claims := make([]*claim, 0, len(names))
	for _, name := range names {
		raw, err := readClaimFile(filepath.Join(j.dir, name))
		if err != nil {
			return ErrUnknown
		}
		c, err := decodeClaim(raw)
		if err != nil || j.path(c) != filepath.Join(j.dir, name) || !j.compatible(c) {
			return ErrUnknown
		}
		previous := positions[c.Record.Collector]
		if c.Record.Interval != previous.interval+1 || previous.interval > 0 && c.Record.Submission.Payload.StartedAt < previous.end {
			return ErrUnknown
		}
		highest := previous.sequence
		for _, e := range c.Record.Evidence {
			if e.Sequence <= previous.sequence {
				return ErrUnknown
			}
			if e.Sequence > highest {
				highest = e.Sequence
			}
		}
		positions[c.Record.Collector] = position{c.Record.Interval, c.Record.Submission.Payload.EndedAt, highest}
		claims = append(claims, c)
	}
	// Validate the entire bounded journal before exporting the first record.
	for _, c := range claims {
		if err := j.persist(c); err != nil {
			return err
		}
		if err := j.export(c); err != nil {
			return err
		}
	}
	return nil
}
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return nil
	}
	err := unlockJournal(j.lock)
	j.lock = nil
	return err
}

type sourceMarker struct {
	Version     int    `json:"version"`
	Collector   string `json:"collector"`
	Core        string `json:"core"`
	Node        string `json:"node"`
	Epoch       string `json:"epoch"`
	Generation  string `json:"generation"`
	TailUnknown bool   `json:"tail_unknown"`
}

// A previously begun source epoch cannot start a new live collector after a
// restart, even when it had no sealed records. Only a fresh Core-issued epoch
// can start another timeline; historical records remain exportable unchanged.
func (j *Journal) startCollector(s usagev2.Session, id string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil || s.CoreInstanceID != j.current.CoreInstanceID || s.NodeID != j.current.NodeID || s.ReceiptGeneration != j.current.ReceiptGeneration || s.SourceEpoch != j.current.SourceEpoch {
		return ErrUnknown
	}
	path := filepath.Join(j.dir, ".interval-source")
	raw, err := readClaimFile(path)
	if err == nil {
		var old sourceMarker
		if usagev2.StrictDecode(raw, &old, 4096) != nil || old.Version != 1 || !collectorName.MatchString(old.Collector) || !old.TailUnknown || old.Core != s.CoreInstanceID || old.Node != s.NodeID || old.Generation != s.ReceiptGeneration || usagev2.Decimal(old.Epoch, false) != nil {
			return ErrUnknown
		}
		if len(s.SourceEpoch) < len(old.Epoch) || len(s.SourceEpoch) == len(old.Epoch) && s.SourceEpoch <= old.Epoch {
			return ErrUnknown
		}
	} else if !os.IsNotExist(err) {
		return ErrUnknown
	}
	encoded, _ := json.Marshal(sourceMarker{1, id, s.CoreInstanceID, s.NodeID, s.SourceEpoch, s.ReceiptGeneration, true})
	f, err := os.CreateTemp(j.dir, ".interval-intent-")
	if err != nil {
		return ErrUnknown
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(encoded)
	}
	if err == nil {
		err = j.syncFile(f)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return j.syncDir(j.dir)
}

func boundedDirectory(path string) ([]os.DirEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(maxJournalRecords + 5)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > maxJournalRecords+4 {
		return nil, ErrUnknown
	}
	return entries, nil
}

func durableJournalDirectory(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnknown
		}
		parent := filepath.Dir(path)
		if parent != path {
			return durableJournalDirectory(parent)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return ErrUnknown
	}
	if err := durableJournalDirectory(parent); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	return syncDirectory(parent)
}
