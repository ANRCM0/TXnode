package reporting

import (
	"encoding/json"
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPeriodSpoolLoadAcceptsHistoricalV1AndExactCanonicalSegments(t *testing.T) {
	for _, segments := range [][]model.TrafficSegment{nil, {{UserID: 7, Period: "opaque-old", Upload: 13, Download: 17}}} {
		path := filepath.Join(t.TempDir(), "old-pending.json")
		body, e := json.Marshal(Batch{Payload: controlplane.ReportPayload{BatchID: "original-durable-id", Traffic: map[int][2]int64{7: {13, 17}}, TrafficSegments: segments}})
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, body, 0600); e != nil {
			t.Fatal(e)
		}
		_, batch, e := openBatchSpool(path)
		if e != nil || batch == nil || batch.Payload.BatchID != "original-durable-id" {
			t.Fatal("historical/exact period batch rejected", e)
		}
	}
}
func TestPeriodSpoolLoadRejectsBrokenAggregationDuplicateAndUnknownScope(t *testing.T) {
	cases := [][]model.TrafficSegment{
		{{UserID: 7, Period: "", Upload: 13, Download: 17}},
		{{UserID: 7, Period: "old", Upload: 12, Download: 17}}, {{UserID: 8, Period: "old", Upload: 13, Download: 17}},
		{{UserID: 7, Period: "old", Upload: 5, Download: 8}, {UserID: 7, Period: "old", Upload: 8, Download: 9}},
		{{UserID: 7, Period: "z", Upload: 5, Download: 8}, {UserID: 7, Period: "a", Upload: 8, Download: 9}},
		{{UserID: 7, Period: "old", Upload: -1, Download: 17}}, {{UserID: 7, Period: "a", Upload: math.MaxInt64, Download: 8}, {UserID: 7, Period: "b", Upload: 1, Download: 9}},
	}
	for _, segments := range cases {
		path := filepath.Join(t.TempDir(), "broken.json")
		body, _ := json.Marshal(Batch{Payload: controlplane.ReportPayload{BatchID: "stable-pending-id", Traffic: map[int][2]int64{7: {13, 17}}, TrafficSegments: segments}})
		if e := os.WriteFile(path, body, 0600); e != nil {
			t.Fatal(e)
		}
		if _, _, e := openBatchSpool(path); e == nil {
			t.Fatal("broken period spool accepted", segments)
		}
	}
}

func TestPeriodAwareRetainedPendingFailureNoticeRestoresNeitherRawNorSegments(t *testing.T) {
	sink := &fakeSink{supported: true, err: errors.New("lost ack")}
	controller, e := NewDurable(sink, filepath.Join(t.TempDir(), "pending.json"))
	if e != nil {
		t.Fatal(e)
	}
	notice := make(chan Batch, 1)
	original := Batch{Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{7: {13, 17}}, TrafficSegments: []model.TrafficSegment{{UserID: 7, Period: "opaque-old", Upload: 13, Download: 17}}}}
	if !controller.PushAsync(func() Batch { return original }, func(batch Batch, _ error) { notice <- batch }, nil) {
		t.Fatal("period-aware send not started")
	}
	select {
	case batch := <-notice:
		if len(batch.Payload.Traffic) != 0 || len(batch.Payload.TrafficSegments) != 0 {
			t.Fatal("retained pending duplicated through failure notice", batch.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("failure notice missing")
	}
	replay, e := controller.nextBatch(func() Batch { t.Fatal("pending lost"); return Batch{} })
	if e != nil || len(replay.Payload.TrafficSegments) != 1 || replay.Payload.TrafficSegments[0] != original.Payload.TrafficSegments[0] {
		t.Fatal("retained attribution mutated", replay, e)
	}
}
