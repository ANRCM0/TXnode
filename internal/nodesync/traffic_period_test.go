package nodesync

import (
	"github.com/ANRCM0/TX-Node/internal/model"
	"testing"
)

func TestObservedPeriodChangesUserSnapshotHashWithoutOtherIdentityChanges(t *testing.T) {
	old := []model.UserSpec{{ID: 7, UUID: "same", TrafficPeriod: "old"}}
	current := []model.UserSpec{{ID: 7, UUID: "same", TrafficPeriod: "current"}}
	if UserHash(old) == UserHash(current) {
		t.Fatal("observed period update suppressed as unchanged users")
	}
}
