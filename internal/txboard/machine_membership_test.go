package txboard

import (
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMachineMembershipRequiresExplicitArrayAndPositiveUniqueNodeIDs(t *testing.T) {
	cases := []struct {
		name, payload string
		valid         bool
		count         int
	}{
		{"explicit-empty", `{"protocol_version":1,"nodes":[]}`, true, 0},
		{"two-nodes", `{"protocol_version":1,"nodes":[{"id":1,"type":"vless"},{"id":2,"type":"vmess"}]}`, true, 2},
		{"missing", `{"protocol_version":1}`, false, 0},
		{"null", `{"protocol_version":1,"nodes":null}`, false, 0},
		{"object", `{"protocol_version":1,"nodes":{}}`, false, 0},
		{"string", `{"protocol_version":1,"nodes":"private-untrusted-input"}`, false, 0},
		{"null-member", `{"protocol_version":1,"nodes":[null]}`, false, 0},
		{"missing-id", `{"protocol_version":1,"nodes":[{"type":"vless"}]}`, false, 0},
		{"zero-id", `{"protocol_version":1,"nodes":[{"id":0}]}`, false, 0},
		{"negative-id", `{"protocol_version":1,"nodes":[{"id":-1}]}`, false, 0},
		{"duplicate-id", `{"protocol_version":1,"nodes":[{"id":3},{"id":3}]}`, false, 0},
		{"fractional-id", `{"protocol_version":1,"nodes":[{"id":1.5}]}`, false, 0},
		{"wrong-version", `{"protocol_version":2,"nodes":[]}`, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != prefix+"/machine/nodes" || r.Header.Get("X-TX-Machine-ID") != "7" || r.Header.Get("Authorization") != "Bearer synthetic-membership" {
					t.Error("configured Machine identity missing")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":` + tc.payload + `}`))
			}))
			defer server.Close()
			client := NewClient(config.PanelConfig{URL: server.URL, MachineID: 7, Token: "synthetic-membership"})
			snapshot, err := client.GetMachineNodes()
			if tc.valid {
				if err != nil || snapshot == nil || snapshot.Nodes == nil || len(snapshot.Nodes) != tc.count {
					t.Fatal("valid explicit membership rejected", snapshot, err)
				}
			} else {
				if err == nil || snapshot != nil {
					t.Fatal("invalid successful response invented empty membership", snapshot, err)
				}
				if _, ok := controlerror.AsAuthorityDenial(err); ok {
					t.Fatal("malformed200 classified as authority denial")
				}
			}
		})
	}
}
