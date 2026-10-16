package usagev2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const NativeCutoffCode = "USAGE_NATIVE_AUTHORIZATION_CUTOFF"

// LocalQuarantine is a local refusal record, never a Core receipt. The immutable
// capture digest also binds the original Session, not only its wire payload.
type LocalQuarantine struct {
	Reason        string `json:"reason"`
	HTTPStatus    int    `json:"http_status"`
	ObservedAt    int64  `json:"observed_at"`
	CaptureDigest string `json:"capture_digest"`
}

func immutableCaptureDigest(record Record) string {
	record.Receipt, record.LocalQuarantine = nil, nil
	raw, _ := json.Marshal(record)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateLocalQuarantine(record Record) error {
	marker := record.LocalQuarantine
	if marker == nil {
		return nil
	}
	if marker.Reason != NativeCutoffCode || marker.HTTPStatus != 422 ||
		marker.ObservedAt < 0 || marker.ObservedAt > MaxSafeTime ||
		marker.CaptureDigest != immutableCaptureDigest(record) {
		return ErrRecoveryRequired
	}
	return nil
}

// QuarantinedCount excludes records subsequently confirmed by a real receipt.
func (s *Spool) QuarantinedCount() (int, error) {
	records, err := s.Records()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, record := range records {
		if record.LocalQuarantine != nil && record.Receipt == nil {
			count++
		}
	}
	return count, nil
}
