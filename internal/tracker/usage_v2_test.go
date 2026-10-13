package tracker

import "testing"

func TestUsageV2MetricsRetainsOnlineAndCumulativeWithoutSecondBillingQueue(t *testing.T) {
	tracker := New()
	if !tracker.EmptyForUsageHandoff() {
		t.Fatal("new tracker not empty")
	}
	if !tracker.ProcessUsageV2Metrics(map[int][2]int64{7: {11, 7}}, map[int]map[string]bool{7: {"127.0.0.1": true}}, 1) {
		t.Fatal("metrics refused")
	}
	if tracker.HasTraffic() || len(tracker.FlushTraffic()) != 0 || tracker.CurrentOnline()[7] != 1 || tracker.ActiveConnections() != 1 || tracker.EmptyForUsageHandoff() {
		t.Fatal("metrics became billing or lost connection state")
	}
	if tracker.ProcessUsageV2Metrics(map[int][2]int64{7: {10, 7}}, nil, 0) {
		t.Fatal("cumulative reset hidden")
	}
	if !tracker.ProcessUsageV2Metrics(map[int][2]int64{7: {13, 12}}, nil, 0) {
		t.Fatal("metrics did not advance")
	}
	tracker.RestoreTraffic(map[int][2]int64{7: {1, 2}})
	if tracker.ProcessUsageV2Metrics(map[int][2]int64{7: {14, 13}}, nil, 0) {
		t.Fatal("pending v1 state discarded")
	}
	if tracker.FlushTraffic()[7] != ([2]int64{1, 2}) {
		t.Fatal("pending v1 state altered")
	}
}
