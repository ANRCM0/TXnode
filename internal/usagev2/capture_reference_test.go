package usagev2

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

func TestConfirmCaptureReconfirmsFailedPublicationWithoutOverwritingReceipt(t *testing.T) {
	spool := linuxSpool(t)
	submission, err := session().Build(1791770400, 1791770460, map[int][2]int64{7: {11, 23}})
	if err != nil {
		t.Fatal(err)
	}
	capture := Record{SchemaVersion: 1, Session: session(), Submission: submission}
	syncDir := spool.syncDir
	spool.syncDir = func(string) error { return errors.New("synthetic failed directory sync") }
	if err := spool.Save(capture); err == nil {
		t.Fatal("spool publication fault hidden")
	}
	if confirmed, err := spool.ConfirmCapture(capture); confirmed || err == nil {
		t.Fatal("unconfirmed publication claimed durable")
	}
	spool.syncDir = syncDir
	if confirmed, err := spool.ConfirmCapture(capture); !confirmed || err != nil {
		t.Fatal("original publication not reconfirmed")
	}
	receipt := receiptFor(submission, "pending")
	saved := capture
	saved.Receipt = &receipt
	if err := spool.Save(saved); err != nil {
		t.Fatal(err)
	}
	if confirmed, err := spool.ConfirmCapture(capture); !confirmed || err != nil {
		t.Fatal("accepted receipt lost")
	}
	records, err := spool.Records()
	if err != nil || len(records) != 1 || records[0].Receipt == nil {
		t.Fatal("capture confirmation removed receipt")
	}
	syncFile := spool.syncFile
	spool.syncFile = func(*os.File) error { return errors.New("synthetic failed file sync") }
	if confirmed, err := spool.ConfirmCapture(capture); confirmed || err == nil {
		t.Fatal("file sync confirmation bypassed")
	}
	spool.syncFile = syncFile
	spool.Close()
	if confirmed, err := spool.ConfirmCapture(capture); confirmed || err == nil {
		t.Fatal("closed spool confirmed writer ownership")
	}
}
func TestConfirmCaptureRejectsPayloadOrSessionConflict(t *testing.T) {
	spool := linuxSpool(t)
	submission, err := session().Build(1791770400, 1791770460, map[int][2]int64{7: {11, 23}})
	if err != nil {
		t.Fatal(err)
	}
	capture := Record{SchemaVersion: 1, Session: session(), Submission: submission}
	if found, err := spool.ConfirmCapture(capture); found || err != nil {
		t.Fatal("missing record confirmation wrong")
	}
	if err := spool.Save(capture); err != nil {
		t.Fatal(err)
	}
	changed := capture
	changed.Session.IssuedAt++
	if found, err := spool.ConfirmCapture(changed); found || err != ErrReceiptMismatch {
		t.Fatal("changed immutable Session accepted")
	}
	changed = capture
	changed.Submission.Payload.Entries = append([]Entry{}, capture.Submission.Payload.Entries...)
	changed.Submission.Payload.Entries[0].RawUpBytes = "99"
	encoded, err := changed.Submission.Payload.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	changed.Submission.PayloadDigest = "sha256:" + hex.EncodeToString(digest[:])
	if found, err := spool.ConfirmCapture(changed); found || err != ErrPayloadConflict {
		t.Fatal("changed immutable payload accepted")
	}
	var absent *Spool
	if found, err := absent.ConfirmCapture(capture); found || err == nil {
		t.Fatal("missing owner accepted")
	}
}
