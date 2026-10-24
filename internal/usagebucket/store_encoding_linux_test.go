//go:build linux

package usagebucket

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStorePreparedRecordPreservesCanonicalRecovery(t *testing.T) {
	store, directory := newStore(t, nil)
	meter := storeMeter(t)
	owner, claim := manualOwner(t, store, meter)
	receipt, err := store.persistClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(store.dir, recordName(receipt.sequence)))
	if err != nil {
		t.Fatal(err)
	}
	var envelope journalEnvelope
	if err := decodeCanonical(data, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(envelope.Record)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(journalEnvelope{Record: envelope.Record, Digest: digestBytes(payload)})
	if err != nil || !bytes.Equal(data, want) || envelope.Digest != digestBytes(payload) {
		t.Fatalf("persisted bytes differ from original envelope encoding: %v", err)
	}
	if len(meter.Snapshot().Sealed) != 1 || !meter.acknowledge(owner, receipt) || meter.acknowledge(owner, receipt) {
		t.Fatal("canonical preparation changed the private durable ACK")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(directory, StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	stored, err := reopened.Read(receipt.sequence)
	wantBucket := envelope.Record.Bucket.memory()
	if err != nil || stored.Digest != envelope.Digest || stored.BucketDigest != envelope.Record.Receipt.BucketDigest ||
		stored.LocalReceiptID != envelope.Record.Receipt.ID || !reflect.DeepEqual(stored.Bucket, &wantBucket) {
		t.Fatalf("canonical recovery changed the original bucket or receipt: %v", err)
	}
}
