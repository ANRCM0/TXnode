package usagebucket

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

func recordEncodingFixture(t testing.TB, count int) journalRecord {
	t.Helper()
	bucket := &diskBucket{
		Tracker: strings.Repeat("a", 32), Number: 1, Generation: 1, ClockEra: 1,
		Start: 1, End: uint64(count + 1), Started: diskStamp{1000, 0},
		SealedAt: diskStamp{2000, 1000}, Reason: ManualFence, Sealed: true,
		Events: make([]diskEvent, count), Attribution: "unattributable", VolatileTailUnknown: true,
	}
	var physical, legacy [2]int64
	for i := range bucket.Events {
		event := diskEvent{
			Sequence: uint64(i + 1), Connection: "tx-1", User: 7, Transport: "tcp",
			Binding: 1, Generation: 1, ClockEra: 1, Kind: "accounting_completion", Path: TCPRead,
			Physical: Upload, Legacy: Download, RawCount: int64(i + 1), CountKnown: true,
			Completed: diskStamp{1500 + int64(i), 500 + int64(i)}, HasIOStart: true,
			IOStarted: diskStamp{1400 + int64(i), 400 + int64(i)}, IOError: i%3 == 0,
			IntervalUnknown: i%5 == 0, CrossedFence: i%7 == 0, LateAfterClose: i%11 == 0,
			StartedAfterClose: i%13 == 0, CloseFenceSequence: uint64(i + 1),
			DirectionMismatch: true, Attribution: "unattributable",
		}
		if i%2 != 0 {
			event.Transport, event.Path = "udp", UDPWrite
			event.Physical, event.Legacy = Download, Upload
		}
		bucket.Events[i] = event
		physical[directionIndex(event.Physical)] += event.RawCount
		legacy[directionIndex(event.Legacy)] += event.RawCount
	}
	for i := range physical {
		bucket.PhysicalTotals[i] = strconv.FormatInt(physical[i], 10)
		bucket.LegacyTotals[i] = strconv.FormatInt(legacy[i], 10)
	}
	record := journalRecord{
		Version: 1, StoreID: strings.Repeat("b", 32), ProcessID: strings.Repeat("c", 32),
		Sequence: 1, PreviousDigest: strings.Repeat("d", 64), Kind: "BUCKET",
		Attribution: "unattributable", RestoreUnknown: true, TailUnknown: true,
		Reasons: []string{"AUTHORIZATION_BOUNDARY_UNKNOWN", "UNSYNCED_TAIL_UNKNOWN"}, Bucket: bucket,
		Capture: &diskCapture{Generation: 1, Next: bucket.End, TailUnknown: true},
		Receipt: &localReceipt{Type: "local_receipt", Attribution: "unattributable", RestoreUnknown: true},
	}
	refreshRecordEncodingReceipt(t, &record)
	return record
}

func refreshRecordEncodingReceipt(t testing.TB, record *journalRecord) {
	t.Helper()
	payload, err := json.Marshal(record.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	record.Receipt.ID = "local:" + record.StoreID + ":" + strconv.FormatUint(record.Sequence, 10)
	record.Receipt.BucketDigest = digestBytes(payload)
}

func TestJournalRecordPreparationKeepsCanonicalBytes(t *testing.T) {
	type testCase struct {
		name   string
		record journalRecord
	}
	var cases []testCase
	for _, reason := range []SealReason{ManualFence, LifecycleFence, TimeBoundary, EventLimit, ClockBoundary} {
		for _, count := range []int{0, 1, 128} {
			record := recordEncodingFixture(t, count)
			record.Bucket.Reason = reason
			refreshRecordEncodingReceipt(t, &record)
			cases = append(cases, testCase{fmt.Sprintf("%s/%d_events", reason, count), record})
		}
	}
	nullEvents := recordEncodingFixture(t, 0)
	nullEvents.Bucket.Events = nil
	refreshRecordEncodingReceipt(t, &nullEvents)
	cases = append(cases, testCase{"null-events", nullEvents})
	escaped := recordEncodingFixture(t, 1)
	escaped.Capture.FirstGap.Connection = "quotes\" slash\\ newline\n tab\t <>& \u2028\u2029 \u4e2d \"bucket\":null"
	cases = append(cases, testCase{"escaped-capture", escaped})
	large := recordEncodingFixture(t, 1)
	large.Sequence, large.Bucket.Number = math.MaxUint64, math.MaxUint64
	large.Bucket.Generation, large.Bucket.ClockEra = math.MaxUint64, math.MaxUint64
	large.Bucket.Start, large.Bucket.End = math.MaxUint64-1, math.MaxUint64
	large.Bucket.Started, large.Bucket.SealedAt = diskStamp{math.MaxInt64 - 2, math.MaxInt64 - 2}, diskStamp{math.MaxInt64, math.MaxInt64}
	event := &large.Bucket.Events[0]
	event.Sequence, event.Generation, event.ClockEra = math.MaxUint64-1, math.MaxUint64, math.MaxUint64
	event.RawCount, event.CloseFenceSequence = math.MaxInt64, math.MaxUint64
	event.Completed, event.IOStarted = diskStamp{math.MaxInt64 - 1, math.MaxInt64 - 1}, large.Bucket.Started
	large.Bucket.PhysicalTotals = [2]string{strconv.FormatInt(math.MaxInt64, 10), "0"}
	large.Bucket.LegacyTotals = [2]string{"0", strconv.FormatInt(math.MaxInt64, 10)}
	large.Capture.Generation, large.Capture.Next = math.MaxUint64, math.MaxUint64
	refreshRecordEncodingReceipt(t, &large)
	cases = append(cases, testCase{"large-integers", large})
	for _, kind := range []string{"PROCESS_BEGIN", "PROCESS_END", "STORE_STOP"} {
		record := recordEncodingFixture(t, 0)
		record.Kind, record.Bucket, record.Capture, record.Receipt = kind, nil, nil, nil
		cases = append(cases, testCase{kind, record})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateRecord(tc.record); err != nil {
				t.Fatalf("invalid fixture: %v", err)
			}
			want, err := json.Marshal(tc.record)
			if err != nil {
				t.Fatal(err)
			}
			got, err := prepareJournalRecord(tc.record)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("canonical record changed: %v\ngot  %s\nwant %s", err, got, want)
			}
			after, err := json.Marshal(tc.record)
			if err != nil || !bytes.Equal(after, want) {
				t.Fatal("record or shared bucket mutated")
			}
			var decoded journalRecord
			if err := decodeCanonical(got, &decoded); err != nil || validateRecord(decoded) != nil {
				t.Fatalf("original canonical reader rejected prepared record: %v", err)
			}
			if digestBytes(got) != digestBytes(want) {
				t.Fatal("record digest changed")
			}
		})
	}
}

func TestJournalRecordPreparationRejectsInvalidEvidence(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*journalRecord)
	}{
		{"version", func(r *journalRecord) { r.Version = 2 }},
		{"sequence", func(r *journalRecord) { r.Sequence = 0 }},
		{"previous-digest", func(r *journalRecord) { r.PreviousDigest = strings.Repeat("A", 64) }},
		{"authorization", func(r *journalRecord) { r.Authorizes = true }},
		{"restore", func(r *journalRecord) { r.RestoreUnknown = false }},
		{"tail", func(r *journalRecord) { r.TailUnknown = false }},
		{"reason", func(r *journalRecord) { r.Reasons = []string{"unsafe\"reason"} }},
		{"control-payload", func(r *journalRecord) { r.Kind = "PROCESS_END" }},
		{"missing-bucket", func(r *journalRecord) { r.Bucket = nil }},
		{"rehashed-total", func(r *journalRecord) {
			r.Bucket.PhysicalTotals[0] = "999"
			refreshRecordEncodingReceipt(t, r)
		}},
		{"direction", func(r *journalRecord) { r.Bucket.Events[0].DirectionMismatch = false }},
		{"capture-tail", func(r *journalRecord) { r.Capture.TailUnknown = false }},
		{"capture-end", func(r *journalRecord) { r.Capture.Next = r.Bucket.End - 1 }},
		{"capture-reason", func(r *journalRecord) { r.Capture.Reason = "unexpected" }},
		{"receipt-id", func(r *journalRecord) { r.Receipt.ID = "local:other:1" }},
		{"receipt-digest", func(r *journalRecord) { r.Receipt.BucketDigest = strings.Repeat("0", 64) }},
		{"receipt-authorization", func(r *journalRecord) { r.Receipt.Authorizes = true }},
		{"receipt-restore", func(r *journalRecord) { r.Receipt.RestoreUnknown = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := recordEncodingFixture(t, 4)
			tc.mutate(&record)
			payload, err := prepareJournalRecord(record)
			if !errors.Is(err, ErrStoreEvidence) || payload != nil {
				t.Fatalf("invalid evidence produced a write payload: %v", err)
			}
		})
	}
}

func BenchmarkJournalRecordPreparation(b *testing.B) {
	for _, count := range []int{1, 128} {
		record := recordEncodingFixture(b, count)
		want, err := json.Marshal(record)
		if err != nil {
			b.Fatal(err)
		}
		pipelines := []struct {
			name string
			run  func(journalRecord) ([]byte, error)
		}{
			{"reference", func(record journalRecord) ([]byte, error) {
				if err := validateRecord(record); err != nil {
					return nil, err
				}
				return json.Marshal(record)
			}},
			{"reuse", prepareJournalRecord},
		}
		for _, pipeline := range pipelines {
			b.Run(fmt.Sprintf("%d_events/%s", count, pipeline.name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(want)))
				for b.Loop() {
					payload, err := pipeline.run(record)
					if err != nil || len(payload) != len(want) {
						b.Fatalf("record preparation failed: %v", err)
					}
				}
			})
		}
	}
}
