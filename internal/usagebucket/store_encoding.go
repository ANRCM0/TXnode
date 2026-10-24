package usagebucket

import (
	"bytes"
	"encoding/json"
)

func prepareJournalRecord(record journalRecord) ([]byte, error) {
	bucketJSON, err := validateRecordBucketJSON(record)
	if err != nil {
		return nil, err
	}
	if record.Kind != "BUCKET" {
		return json.Marshal(record)
	}
	// Keep the original schema and field order, then fill its one null bucket
	// slot with the bytes just validated. No callback or mutation intervenes.
	record.Bucket = nil
	shell, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	const marker = `"bucket":null`
	if len(bucketJSON) == 0 || bytes.Count(shell, []byte(marker)) != 1 {
		return nil, ErrStoreEvidence
	}
	start := bytes.Index(shell, []byte(marker)) + len(`"bucket":`)
	payload := make([]byte, 0, len(shell)-len("null")+len(bucketJSON))
	payload = append(payload, shell[:start]...)
	payload = append(payload, bucketJSON...)
	return append(payload, shell[start+len("null"):]...), nil
}
