//go:build linux

package usagebucket

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJournalEnvelopeReusesCanonicalRecordBytes(t *testing.T) {
	bucket := bucketToDisk(storeMeter(t).Snapshot().Sealed[0])
	bucketPayload, err := json.Marshal(bucket)
	if err != nil {
		t.Fatal(err)
	}
	base := journalRecord{
		Version: 1, StoreID: strings.Repeat("a", 32), ProcessID: strings.Repeat("b", 32),
		Sequence: 1, Attribution: "unattributable", RestoreUnknown: true, TailUnknown: true,
		Reasons: []string{"UNSYNCED_TAIL_UNKNOWN"},
	}
	bucketRecord := base
	bucketRecord.Kind, bucketRecord.Bucket = "BUCKET", &bucket
	bucketRecord.Capture = &diskCapture{Generation: bucket.Generation, Next: bucket.End, TailUnknown: true}
	bucketRecord.Receipt = &localReceipt{
		Type: "local_receipt", ID: "local:" + base.StoreID + ":1", BucketDigest: digestBytes(bucketPayload),
		Attribution: "unattributable", RestoreUnknown: true,
	}
	type testCase struct {
		name   string
		record journalRecord
		valid  bool
	}
	cases := []testCase{{"bucket", bucketRecord, true}}
	for _, kind := range []string{"PROCESS_BEGIN", "PROCESS_END", "STORE_STOP"} {
		record := base
		record.Kind = kind
		cases = append(cases, testCase{kind, record, true})
	}
	// These exercise encoding behavior independently of the restricted evidence
	// vocabulary, including null slices and characters json.Marshal must escape.
	escaped := base
	escaped.Kind = "quotes\" slash\\ newline\n tab\t <>& \u2028\u2029 \u4e2d"
	escaped.Reasons = []string{"", "\x00"}
	cases = append(cases, testCase{"escaped-strings", escaped, false}, testCase{"null-fields", journalRecord{}, false})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.valid {
				if err := validateRecord(tc.record); err != nil {
					t.Fatalf("invalid fixture: %v", err)
				}
			}
			payload, err := json.Marshal(tc.record)
			if err != nil {
				t.Fatal(err)
			}
			original := append([]byte(nil), payload...)
			digest := digestBytes(payload)
			want, err := json.Marshal(journalEnvelope{Record: tc.record, Digest: digest})
			if err != nil {
				t.Fatal(err)
			}
			got := encodeJournalEnvelope(payload, digest)
			if !bytes.Equal(got, want) {
				t.Fatalf("canonical envelope changed:\ngot  %s\nwant %s", got, want)
			}
			if !bytes.Equal(payload, original) {
				t.Fatal("record payload mutated")
			}
			var decoded journalEnvelope
			if err := decodeCanonical(got, &decoded); err != nil || decoded.Digest != digest {
				t.Fatalf("canonical decoder/digest mismatch: %v", err)
			}
		})
	}
}
