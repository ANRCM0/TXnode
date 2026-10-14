package reporting

import (
	"errors"
	"math"
	"unicode/utf8"
)

func validateSpoolTrafficSegments(batch Batch) error {
	segments := batch.Payload.TrafficSegments
	if len(segments) == 0 {
		return nil
	} // Historical v1 body retains original semantics.
	if len(segments) > 10000 {
		return errors.New("REPORTING_PERIOD_SEGMENTS_INVALID")
	}
	sums := make(map[int][2]int64, len(batch.Payload.Traffic))
	previousID := 0
	previousPeriod := ""
	for i, segment := range segments {
		if segment.UserID <= 0 || segment.Period == "" || segment.Upload < 0 || segment.Download < 0 || len(segment.Period) > 130 || !utf8.ValidString(segment.Period) {
			return errors.New("REPORTING_PERIOD_SEGMENTS_INVALID")
		}
		if i > 0 && (segment.UserID < previousID || segment.UserID == previousID && segment.Period <= previousPeriod) {
			return errors.New("REPORTING_PERIOD_SEGMENTS_INVALID")
		}
		if _, exists := batch.Payload.Traffic[segment.UserID]; !exists {
			return errors.New("REPORTING_PERIOD_SEGMENTS_INVALID")
		}
		previousID, previousPeriod = segment.UserID, segment.Period
		sum := sums[segment.UserID]
		if sum[0] > math.MaxInt64-segment.Upload || sum[1] > math.MaxInt64-segment.Download {
			return errors.New("REPORTING_PERIOD_SEGMENTS_INVALID")
		}
		sum[0] += segment.Upload
		sum[1] += segment.Download
		sums[segment.UserID] = sum
	}
	if len(sums) != len(batch.Payload.Traffic) {
		return errors.New("REPORTING_PERIOD_SEGMENTS_INVALID")
	}
	for id, value := range batch.Payload.Traffic {
		if sums[id] != value {
			return errors.New("REPORTING_PERIOD_SEGMENTS_INVALID")
		}
	}
	return nil
}
