package controlplane

import (
	"encoding/json"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/model"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPeriodAwareNativeReportForwardsExactSegmentsAndLegacyOmitsField(t *testing.T) {
	payloads := make(chan map[string]json.RawMessage, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/txapi/node/v1/report" {
			t.Error("unexpected native path")
		}
		var body map[string]json.RawMessage
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Error(e)
		}
		payloads <- body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"data":{"protocol_version":1,"accepted":true,"traffic_batch_id":"immutable-period-id","settlement":"queued","receipt_status":"persisted","receipt_id":"1"}}`))
	}))
	defer server.Close()
	cp := NewTXBoardControlPlane(config.PanelConfig{URL: server.URL, Token: "synthetic", NodeID: 7}, config.WSConfig{}, config.KernelConfig{})
	payload := ReportPayload{BatchID: "immutable-period-id", Traffic: map[int][2]int64{7: {13, 17}}, TrafficSegments: []model.TrafficSegment{{UserID: 7, Period: "opaque-old", Upload: 13, Download: 17}}}
	if e := cp.Report(payload); e != nil {
		t.Fatal(e)
	}
	body := <-payloads
	var segments []model.TrafficSegment
	if e := json.Unmarshal(body["traffic_segments"], &segments); e != nil || len(segments) != 1 || segments[0] != payload.TrafficSegments[0] {
		t.Fatal("native period segment wire mismatch", segments, e)
	}
	payload.TrafficSegments = nil
	if e := cp.Report(payload); e != nil {
		t.Fatal(e)
	}
	legacy := <-payloads
	if _, exists := legacy["traffic_segments"]; exists {
		t.Fatal("historical batch re-labelled with period field")
	}
}
