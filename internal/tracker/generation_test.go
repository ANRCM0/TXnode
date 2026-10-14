package tracker

import "testing"

func TestExplicitCumulativeGenerationCountsLargerFirstSampleAndKeepsPending(t *testing.T) {
	tr := New()
	tr.Process(map[int][2]int64{7: {13, 17}}, nil, 0)
	tr.BeginCumulativeGeneration()
	tr.Process(map[int][2]int64{7: {57, 79}}, nil, 0)
	if got := tr.FlushTraffic()[7]; got != [2]int64{70, 96} {
		t.Fatal("new producer baseline inferred incorrectly", got)
	}
	tr.Process(map[int][2]int64{7: {57, 79}}, nil, 0)
	if tr.HasTraffic() {
		t.Fatal("repeat sample duplicated")
	}
	tr.RestoreTraffic(map[int][2]int64{7: {11, 19}})
	tr.BeginCumulativeGeneration()
	tr.Process(map[int][2]int64{7: {5, 8}}, nil, 0)
	if got := tr.FlushTraffic()[7]; got != [2]int64{16, 27} {
		t.Fatal("new producer lost restored/pending report", got)
	}
}
func TestPersistentCumulativeProducerDoesNotNeedGenerationReset(t *testing.T) {
	tr := New()
	tr.Process(map[int][2]int64{7: {13, 17}}, nil, 0)
	if got := tr.FlushTraffic()[7]; got != [2]int64{13, 17} {
		t.Fatal(got)
	}
	// Xray's new instance retains its old cumulative ownership.
	tr.Process(map[int][2]int64{7: {70, 96}}, nil, 0)
	if got := tr.FlushTraffic()[7]; got != [2]int64{57, 79} {
		t.Fatal("persistent cumulative double billed", got)
	}
}
