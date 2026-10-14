package model

import (
	"encoding/json"
	"github.com/ANRCM0/TX-Node/internal/panel"
	"reflect"
	"testing"
)

func TestObservedPeriodSurvivesNativeUserJSONAndProviderTranslation(t *testing.T) {
	var users []panel.User
	if e := json.Unmarshal([]byte(`[{"id":7,"uuid":"synthetic","traffic_period":"p1.7.0.opaque"}]`), &users); e != nil {
		t.Fatal(e)
	}
	spec := UserSpecsFromPanel(users)
	if spec[0].TrafficPeriod != "p1.7.0.opaque" || !reflect.DeepEqual(users, UserSpecsToPanel(spec)) {
		t.Fatal("native period lost across panel/model DTO")
	}
	var legacy []panel.User
	if e := json.Unmarshal([]byte(`[{"id":7,"uuid":"synthetic"}]`), &legacy); e != nil {
		t.Fatal(e)
	}
	if UserSpecsFromPanel(legacy)[0].TrafficPeriod != "" {
		t.Fatal("legacy provider fabricated period")
	}
}
