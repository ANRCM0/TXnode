package txboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/config"
)

func TestAttributedReportRequiresDurableAcceptanceBeforeDroppingPendingIdentity(t *testing.T) {
	for _, test := range []struct {
		name, status, id string
		accepted         bool
	}{
		{"persisted", "persisted", "12", true},
		{"queued only", "queued_only", "12", false},
		{"missing receipt", "persisted", "", false},
		{"zero receipt", "persisted", "0", false},
		{"noncanonical receipt", "persisted", "012", false},
		{"unknown status", "settled", "12", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(202)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
					"protocol_version": 1, "accepted": true, "traffic_batch_id": "attributed-batch-001",
					"settlement": "queued", "receipt_status": test.status, "receipt_id": test.id,
				}})
			}))
			defer server.Close()
			client := NewClient(config.PanelConfig{URL: server.URL, Token: "synthetic-native", NodeID: 42})
			err := client.PostReport(map[string]any{"traffic_batch_id": "attributed-batch-001",
				"traffic": map[int][2]int64{7: {5, 9}}, "traffic_segments": []map[string]any{
					{"user_id": 7, "period": "opaque", "upload": 5, "download": 9},
				}})
			if (err == nil) != test.accepted {
				t.Fatalf("durable ack accepted=%v: %v", err == nil, err)
			}
		})
	}
}
