package usagebucket

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// The disk schema is restricted local evidence, not a Node Usage v2 payload or
// a Core receipt. Integers use decimal strings so offline readers cannot round.
type diskStamp struct {
	Wall    int64 `json:"wall_unix_nanos,string"`
	Elapsed int64 `json:"process_elapsed_nanos,string"`
}

type diskEvent struct {
	Sequence           uint64    `json:"sequence,string"`
	Connection         string    `json:"connection_id"`
	User               int       `json:"user_id,string"`
	Transport          string    `json:"transport"`
	Binding            uint64    `json:"binding_generation,string"`
	Generation         uint64    `json:"observation_generation,string"`
	ClockEra           uint64    `json:"clock_era,string"`
	Kind               string    `json:"kind"`
	Path               Path      `json:"path"`
	Physical           Direction `json:"physical_direction"`
	Legacy             Direction `json:"legacy_direction"`
	RawCount           int64     `json:"raw_count,string"`
	CountKnown         bool      `json:"count_known"`
	Completed          diskStamp `json:"completed"`
	HasIOStart         bool      `json:"has_io_start"`
	IOStarted          diskStamp `json:"io_started"`
	IOError            bool      `json:"io_error"`
	IntervalUnknown    bool      `json:"interval_unknown"`
	CrossedFence       bool      `json:"crossed_fence"`
	LateAfterClose     bool      `json:"late_after_close"`
	StartedAfterClose  bool      `json:"started_after_close"`
	CloseFenceSequence uint64    `json:"close_fence_sequence,string"`
	DirectionMismatch  bool      `json:"direction_mismatch"`
	Attribution        string    `json:"attribution"`
}

type diskBucket struct {
	Tracker             string      `json:"tracker_id"`
	Number              uint64      `json:"bucket_number,string"`
	Generation          uint64      `json:"local_generation,string"`
	ClockEra            uint64      `json:"clock_era,string"`
	Start               uint64      `json:"start_sequence,string"`
	End                 uint64      `json:"end_sequence_exclusive,string"`
	Started             diskStamp   `json:"started"`
	SealedAt            diskStamp   `json:"sealed_at"`
	Reason              SealReason  `json:"reason"`
	Sealed              bool        `json:"sealed"`
	Events              []diskEvent `json:"events"`
	PhysicalTotals      [2]string   `json:"physical_totals"`
	LegacyTotals        [2]string   `json:"legacy_totals"`
	Attribution         string      `json:"attribution"`
	VolatileTailUnknown bool        `json:"volatile_tail_unknown"`
}

type diskCapture struct {
	Degraded    bool      `json:"degraded"`
	Reason      string    `json:"reason"`
	Generation  uint64    `json:"generation,string"`
	Next        uint64    `json:"next_sequence,string"`
	Dropped     uint64    `json:"dropped_events,string"`
	FirstGap    diskEvent `json:"first_gap"`
	TailUnknown bool      `json:"tail_unknown"`
}

type localReceipt struct {
	Type           string `json:"type"`
	ID             string `json:"id"`
	Authorizes     bool   `json:"authorizes"`
	BucketDigest   string `json:"bucket_digest"`
	Attribution    string `json:"attribution"`
	RestoreUnknown bool   `json:"restore_unknown"`
}

type journalRecord struct {
	Version        int           `json:"version"`
	StoreID        string        `json:"store_id"`
	ProcessID      string        `json:"process_id"`
	Sequence       uint64        `json:"sequence,string"`
	PreviousDigest string        `json:"previous_digest"`
	Kind           string        `json:"kind"`
	Authorizes     bool          `json:"authorizes"`
	Attribution    string        `json:"attribution"`
	RestoreUnknown bool          `json:"restore_unknown"`
	TailUnknown    bool          `json:"tail_unknown"`
	Reasons        []string      `json:"reasons"`
	Bucket         *diskBucket   `json:"bucket"`
	Capture        *diskCapture  `json:"capture"`
	Receipt        *localReceipt `json:"local_receipt"`
}

type journalEnvelope struct {
	Record journalRecord `json:"record"`
	Digest string        `json:"digest"`
}

type journalHead struct {
	Version        int    `json:"version"`
	StoreID        string `json:"store_id"`
	Sequence       uint64 `json:"sequence,string"`
	Digest         string `json:"digest"`
	Authorizes     bool   `json:"authorizes"`
	Attribution    string `json:"attribution"`
	RestoreUnknown bool   `json:"restore_unknown"`
}

func diskTime(s Stamp) diskStamp   { return diskStamp{s.WallUnixNanos, s.ElapsedNanos} }
func memoryTime(s diskStamp) Stamp { return Stamp{s.Wall, s.Elapsed} }

func eventToDisk(e Event) diskEvent {
	return diskEvent{e.Sequence, e.ConnectionID, e.UserID, e.Transport, e.BindingGeneration, e.ObservationGeneration, e.ClockEra, e.Kind, e.Path, e.PhysicalDirection, e.LegacyDirection, e.RawCount, e.CountKnown, diskTime(e.Completed), e.HasIOStart, diskTime(e.IOStarted), e.IOError, e.IntervalUnknown, e.CrossedFence, e.LateAfterClose, e.StartedAfterClose, e.CloseFenceSequence, e.DirectionMismatch, e.Attribution}
}

func (e diskEvent) memory() Event {
	return Event{Sequence: e.Sequence, ConnectionID: e.Connection, UserID: e.User, Transport: e.Transport, BindingGeneration: e.Binding, ObservationGeneration: e.Generation, ClockEra: e.ClockEra, Kind: e.Kind, Path: e.Path, PhysicalDirection: e.Physical, LegacyDirection: e.Legacy, RawCount: e.RawCount, CountKnown: e.CountKnown, Completed: memoryTime(e.Completed), HasIOStart: e.HasIOStart, IOStarted: memoryTime(e.IOStarted), IOError: e.IOError, IntervalUnknown: e.IntervalUnknown, CrossedFence: e.CrossedFence, LateAfterClose: e.LateAfterClose, StartedAfterClose: e.StartedAfterClose, CloseFenceSequence: e.CloseFenceSequence, DirectionMismatch: e.DirectionMismatch, Attribution: e.Attribution}
}

func bucketToDisk(b Bucket) diskBucket {
	events := make([]diskEvent, len(b.Events))
	for i, event := range b.Events {
		events[i] = eventToDisk(event)
	}
	return diskBucket{b.TrackerID, b.Number, b.Generation, b.ClockEra, b.StartSequence, b.EndSequenceExclusive, diskTime(b.Started), diskTime(b.SealedAt), b.Reason, b.Sealed, events, [2]string{strconv.FormatInt(b.PhysicalTotals[0], 10), strconv.FormatInt(b.PhysicalTotals[1], 10)}, [2]string{strconv.FormatInt(b.LegacyTotals[0], 10), strconv.FormatInt(b.LegacyTotals[1], 10)}, b.Attribution, b.VolatileTailUnknown}
}

func (b diskBucket) memory() Bucket {
	events := make([]Event, len(b.Events))
	for i, event := range b.Events {
		events[i] = event.memory()
	}
	var physical, legacy [2]int64
	for i := range physical {
		physical[i], _ = strconv.ParseInt(b.PhysicalTotals[i], 10, 64)
		legacy[i], _ = strconv.ParseInt(b.LegacyTotals[i], 10, 64)
	}
	return Bucket{TrackerID: b.Tracker, Number: b.Number, Generation: b.Generation, ClockEra: b.ClockEra, StartSequence: b.Start, EndSequenceExclusive: b.End, Started: memoryTime(b.Started), SealedAt: memoryTime(b.SealedAt), Reason: b.Reason, Sealed: b.Sealed, Events: events, PhysicalTotals: physical, LegacyTotals: legacy, Attribution: b.Attribution, VolatileTailUnknown: b.VolatileTailUnknown}
}

func bucketKey(b Bucket) string          { return b.TrackerID + ":" + strconv.FormatUint(b.Number, 10) }
func diskBucketKey(b *diskBucket) string { return b.Tracker + ":" + strconv.FormatUint(b.Number, 10) }
func digestBytes(data []byte) string     { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func validHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
func safeLabel(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}

func decodeCanonical(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrStoreEvidence
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrStoreEvidence
	}
	return nil
}

func validateDiskBucket(b *diskBucket) error {
	if b == nil || !validHex(b.Tracker, 32) || b.Number == 0 || b.Generation == 0 || b.ClockEra == 0 || b.Start == 0 || b.End < b.Start || !b.Sealed || b.Attribution != "unattributable" || !b.VolatileTailUnknown || b.Started.Elapsed < 0 || b.SealedAt.Elapsed < b.Started.Elapsed || len(b.Events) > 4096 || b.End-b.Start != uint64(len(b.Events)) {
		return ErrStoreEvidence
	}
	switch b.Reason {
	case ManualFence, LifecycleFence, TimeBoundary, EventLimit, ClockBoundary:
	default:
		return ErrStoreEvidence
	}
	var physical, legacy [2]int64
	for i, e := range b.Events {
		if e.Sequence != b.Start+uint64(i) || !safeLabel(e.Connection, 80) || e.User <= 0 || (e.Transport != "tcp" && e.Transport != "udp") || e.Binding == 0 || e.Generation != b.Generation || e.Binding > e.Generation || e.ClockEra != b.ClockEra || e.Attribution != "unattributable" || e.RawCount < 0 || e.Completed.Elapsed < 0 || e.DirectionMismatch != (e.Physical != e.Legacy) {
			return ErrStoreEvidence
		}
		if e.HasIOStart && e.IOStarted.Elapsed < 0 {
			return ErrStoreEvidence
		}
		switch e.Kind {
		case "accounting_completion":
			if !validDirection(e.Physical) || !validDirection(e.Legacy) {
				return ErrStoreEvidence
			}
			switch e.Path {
			case TCPRead, TCPWrite, TCPReadCallback, TCPWriteCallback, UDPRead, UDPWrite, UDPReadCallback, UDPWriteCallback:
			default:
				return ErrStoreEvidence
			}
			if e.CountKnown {
				p, l := directionIndex(e.Physical), directionIndex(e.Legacy)
				if e.RawCount > math.MaxInt64-physical[p] || e.RawCount > math.MaxInt64-legacy[l] {
					return ErrStoreEvidence
				}
				physical[p] += e.RawCount
				legacy[l] += e.RawCount
			}
		case "close_fence":
			if e.RawCount != 0 || !e.CountKnown || e.Physical != "" || e.Legacy != "" || e.Path != "" {
				return ErrStoreEvidence
			}
		default:
			return ErrStoreEvidence
		}
	}
	for i := range physical {
		if b.PhysicalTotals[i] != strconv.FormatInt(physical[i], 10) || b.LegacyTotals[i] != strconv.FormatInt(legacy[i], 10) {
			return ErrStoreEvidence
		}
	}
	return nil
}

func validateRecord(r journalRecord) error {
	_, err := validateRecordBucketJSON(r)
	return err
}

// Return the same canonical bucket bytes used to validate the local receipt.
func validateRecordBucketJSON(r journalRecord) ([]byte, error) {
	if r.Version != 1 || !validHex(r.StoreID, 32) || !validHex(r.ProcessID, 32) || r.Sequence == 0 || (r.PreviousDigest != "" && !validHex(r.PreviousDigest, 64)) || r.Authorizes || r.Attribution != "unattributable" || !r.RestoreUnknown || !r.TailUnknown || len(r.Reasons) == 0 || len(r.Reasons) > 8 {
		return nil, ErrStoreEvidence
	}
	for _, reason := range r.Reasons {
		if !safeLabel(reason, 80) {
			return nil, ErrStoreEvidence
		}
	}
	if r.Kind != "BUCKET" {
		if r.Kind != "PROCESS_BEGIN" && r.Kind != "PROCESS_END" && r.Kind != "STORE_STOP" || r.Bucket != nil || r.Capture != nil || r.Receipt != nil {
			return nil, ErrStoreEvidence
		}
		return nil, nil
	}
	if err := validateDiskBucket(r.Bucket); err != nil {
		return nil, err
	}
	if r.Capture == nil || !r.Capture.TailUnknown || r.Capture.Generation == 0 || r.Capture.Next < r.Bucket.End || (r.Capture.Degraded && !safeLabel(r.Capture.Reason, 80)) || (!r.Capture.Degraded && r.Capture.Reason != "") {
		return nil, ErrStoreEvidence
	}
	data, _ := json.Marshal(r.Bucket)
	if r.Receipt == nil || r.Receipt.Type != "local_receipt" || r.Receipt.ID != "local:"+r.StoreID+":"+strconv.FormatUint(r.Sequence, 10) || r.Receipt.Authorizes || r.Receipt.Attribution != "unattributable" || !r.Receipt.RestoreUnknown || r.Receipt.BucketDigest != digestBytes(data) {
		return nil, ErrStoreEvidence
	}
	return data, nil
}
