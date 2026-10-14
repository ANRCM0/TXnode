package tracker

import (
	"encoding/json"
	"fmt"
	"github.com/ANRCM0/TX-Node/internal/model"
	"reflect"
	"strings"
	"testing"
)

func TestObservedPeriodsAtomicFlushRestoreRetainsLateOldAndFreshCurrent(t *testing.T) {
	tr := New()
	tr.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "opaque-old"}})
	tr.Process(map[int][2]int64{7: {13, 17}}, nil, 0)
	// Stop final sample adds unsampled old bytes before observed binding changes.
	tr.Process(map[int][2]int64{7: {19, 26}}, nil, 0)
	tr.BeginCumulativeGeneration()
	tr.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "opaque-current"}})
	tr.Process(map[int][2]int64{7: {57, 79}}, nil, 0)
	traffic, segments := tr.FlushBatch()
	want := []model.TrafficSegment{{UserID: 7, Period: "opaque-current", Upload: 57, Download: 79}, {UserID: 7, Period: "opaque-old", Upload: 19, Download: 26}}
	if traffic[7] != [2]int64{76, 105} || !reflect.DeepEqual(segments, want) {
		t.Fatal("periods crossed reset boundary", traffic, segments)
	}
	tr.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "opaque-later"}})
	tr.RestoreBatch(traffic, segments)
	again, retained := tr.FlushBatch()
	if !reflect.DeepEqual(again, traffic) || !reflect.DeepEqual(retained, segments) {
		t.Fatal("restore relabelled immutable periods", again, retained)
	}
}
func TestObservedLegacyAndMixedPeriodsNeverInventCurrentToken(t *testing.T) {
	tr := New()
	tr.Process(map[int][2]int64{7: {5, 8}}, nil, 0)
	legacy, segments := tr.FlushBatch()
	if segments != nil || legacy[7] != [2]int64{5, 8} {
		t.Fatal("legacy path fabricated period")
	}
	tr.RestoreTraffic(legacy)
	tr.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "opaque-current"}})
	tr.BeginCumulativeGeneration()
	tr.Process(map[int][2]int64{7: {3, 4}}, nil, 0)
	traffic, mixed := tr.FlushBatch()
	if traffic[7] != [2]int64{5, 8} || mixed != nil || !tr.HasTraffic() {
		t.Fatal("legacy cohort not independently drained", traffic, mixed)
	}
	aware, signed := tr.FlushBatch()
	if aware[7] != [2]int64{3, 4} || len(signed) != 1 || signed[0].Period != "opaque-current" || signed[0].Upload != 3 || tr.HasTraffic() {
		t.Fatal("signed cohort lost/relabelled after legacy batch", aware, signed)
	}
}
func TestObservedRemovedUsersKeepOldBindingUntilFinalSample(t *testing.T) {
	tr := New()
	tr.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "opaque-old"}, {ID: 8, TrafficPeriod: "opaque-sibling"}})
	tr.Process(map[int][2]int64{7: {13, 17}}, nil, 0)
	tr.BindPeriods([]model.UserSpec{{ID: 8, TrafficPeriod: "opaque-sibling"}})
	tr.Process(map[int][2]int64{7: {19, 26}}, nil, 0)
	_, segments := tr.FlushBatch()
	if len(segments) != 1 || segments[0].Period != "opaque-old" || segments[0].Upload != 19 {
		t.Fatal("removed user's final meter rebound", segments)
	}
}

func TestObservedFailedAdmissionBindingRollsBackWithoutChangingPendingAttribution(t *testing.T) {
	tr := New()
	tr.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "old"}})
	tr.Process(map[int][2]int64{7: {13, 17}}, nil, 0)
	previous := tr.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "new"}})
	tr.RestorePeriodBindings(previous)
	tr.Process(map[int][2]int64{7: {20, 26}}, nil, 0)
	traffic, segments := tr.FlushBatch()
	if traffic[7] != [2]int64{20, 26} || len(segments) != 1 || segments[0].Period != "old" {
		t.Fatal("failed admission rebound old pending bytes", traffic, segments)
	}
}

func TestObservedPeriodSegmentBoundSplitsOnlyAboveTenThousandAndRetainsEveryByte(t *testing.T) {
	tr := New()
	for i := 0; i < 10001; i++ {
		tr.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: fmt.Sprintf("opaque-%05d", i)}})
		tr.Process(map[int][2]int64{7: {int64(i + 1), int64(i + 1)}}, nil, 0)
	}
	first, segments := tr.FlushBatch()
	if len(segments) == 0 || len(segments) > 10000 || first[7] != [2]int64{int64(len(segments)), int64(len(segments))} || !tr.HasTraffic() {
		t.Fatal("bounded first segment cohort wrong", len(segments), first)
	}
	last, remainder := tr.FlushBatch()
	if len(remainder) == 0 || last[7] != [2]int64{int64(len(remainder)), int64(len(remainder))} || remainder[len(remainder)-1].Period != "opaque-10000" || len(segments)+len(remainder) != 10001 || tr.HasTraffic() {
		t.Fatal("bounded remaining attribution lost", last, remainder)
	}
}
func TestObservedGlobalModeChangeAcrossDifferentUIDRequiresDrain(t *testing.T) {
	tr := New()
	tr.BindPeriods([]model.UserSpec{{ID: 7}})
	tr.Process(map[int][2]int64{7: {5, 8}}, nil, 0)
	current := []model.UserSpec{{ID: 8, TrafficPeriod: "signed"}}
	if !tr.PeriodModeChanged(current) {
		t.Fatal("differentUID legacy->signed bypassed mode boundary")
	}
	traffic, segments := tr.FlushBatch()
	if traffic[7] != [2]int64{5, 8} || segments != nil {
		t.Fatal("legacy cohort relabelled")
	}
	tr.BindPeriods(current)
	if tr.PeriodModeChanged(current) {
		t.Fatal("retiredUID old binding causes repeated mode switch")
	}
	if !tr.PeriodModeChanged([]model.UserSpec{{ID: 9}}) {
		t.Fatal("signed->legacy downgrade bypassed mode boundary")
	}
}

func TestObservedSignedChunkAlsoBoundsCanonicalWireBytesForLongTokens(t *testing.T) {
	tr := New()
	for i := 0; i < 10001; i++ {
		tr.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: fmt.Sprintf("p1.7.%05d.%s", i, strings.Repeat("a", 64))}})
		tr.Process(map[int][2]int64{7: {int64(i + 1), int64(i + 1)}}, nil, 0)
	}
	var total int64
	chunks := 0
	for tr.HasTraffic() {
		traffic, segments := tr.FlushBatch()
		body, e := json.Marshal(map[string]any{"traffic": traffic, "traffic_segments": segments})
		if e != nil || len(body) > 512<<10 || len(segments) > 10000 || len(segments) == 0 {
			t.Fatal("chunk cannot fit native request limits", len(body), len(segments), e)
		}
		total += traffic[7][0]
		chunks++
	}
	if total != 10001 || chunks < 2 {
		t.Fatal("byte bounded chunks lost segment bytes", total, chunks)
	}
}
