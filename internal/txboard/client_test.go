package txboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/config"
)

func TestNativeAuthEnvelopeAndETags(t *testing.T) {
	var configCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer native-secret" || r.Header.Get("X-TX-Node-ID") != "42" {
			t.Errorf("missing native headers: %v", r.Header)
			w.WriteHeader(401)
			return
		}
		if strings.Contains(r.URL.RawQuery, "token") {
			t.Fatal("native request leaked credentials in query")
		}
		switch r.URL.Path {
		case prefix + "/handshake":
			if r.Method != "POST" {
				t.Error("invalid handshake method")
			}
			_, _ = w.Write([]byte(`{"data":{"protocol_version":1,"mode":"node","node_id":42,"websocket":{"enabled":false},"settings":{"push_interval":60,"pull_interval":75}},"request_id":"test"}`))
		case prefix + "/config":
			configCalls++
			if r.Header.Get("If-None-Match") == `"cfg-1"` {
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"cfg-1"`)
			_, _ = w.Write([]byte(`{"data":{"protocol_version":1,"node_id":42,"config":{"protocol":"vmess","listen_ip":"0.0.0.0","server_port":443}}}`))
		case prefix + "/report":
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if string(body["protocol_version"]) != "1" {
				t.Error("missing native protocol version")
			}
			if _, exists := body["token"]; exists {
				t.Error("legacy credential leaked in body")
			}
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"data":{"protocol_version":1,"accepted":true,"traffic_batch_id":"stable-batch-0001","settlement":"queued"}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := NewClient(config.PanelConfig{URL: server.URL, Token: "native-secret", NodeID: 42})
	hs, err := c.Handshake()
	if err != nil || hs.Settings.PullInterval != 75 {
		t.Fatalf("handshake: %+v %v", hs, err)
	}
	cfg, err := c.GetConfig()
	if err != nil || cfg == nil || cfg.ServerPort != 443 {
		t.Fatalf("config: %+v %v", cfg, err)
	}
	cfg, err = c.GetConfig()
	if err != nil || cfg != nil {
		t.Fatalf("304 config: %+v %v", cfg, err)
	}
	if configCalls != 2 {
		t.Fatal("missing ETag requests")
	}
	if err := c.PostReport(map[string]any{"traffic_batch_id": "stable-batch-0001", "traffic": map[int][2]int64{1: {100, 200}}}); err != nil {
		t.Fatal(err)
	}
	c.ResetETags()
	if cfg, err = c.GetConfig(); err != nil || cfg == nil {
		t.Fatalf("reset ETag failed: %v", err)
	}
}
func TestMachineHeadersAndVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer machine-secret" || r.Header.Get("X-TX-Machine-ID") != "7" {
			t.Fatalf("machine identity missing")
		}
		if r.URL.Path == prefix+"/machine/nodes" {
			if r.Method != "GET" {
				t.Fatal("machine discovery must be GET")
			}
			_, _ = w.Write([]byte(`{"data":{"protocol_version":1,"nodes":[{"id":42,"type":"vless","name":"A"}],"base_config":{"pull_interval":60}}}`))
			return
		}
		if r.URL.Path == prefix+"/machine/status" {
			if r.Method != "POST" {
				t.Fatal("machine status must be POST")
			}
			var body map[string]json.RawMessage
			_ = json.NewDecoder(r.Body).Decode(&body)
			if string(body["protocol_version"]) != "1" {
				t.Fatal("version not included")
			}
			_, _ = w.Write([]byte(`{"data":{"protocol_version":1,"accepted":true}}`))
		}
	}))
	defer server.Close()
	c := NewClient(config.PanelConfig{URL: server.URL, Token: "machine-secret", MachineID: 7})
	nodes, err := c.GetMachineNodes()
	if err != nil || len(nodes.Nodes) != 1 || nodes.Nodes[0].ID != 42 {
		t.Fatalf("discovery: %+v %v", nodes, err)
	}
	if err := c.ReportMachineStatus(map[string]any{"cpu": 5, "mem": map[string]any{"total": 100, "used": 20}}); err != nil {
		t.Fatal(err)
	}
}
func TestNativeWebSocketURLIsRestricted(t *testing.T) {
	c := NewClient(config.PanelConfig{URL: "https://example.test"})
	u, err := c.WSSURL(prefix + "/ws")
	if err != nil || u != "wss://example.test/txapi/node/v1/ws" {
		t.Fatalf("%s %v", u, err)
	}
	if _, err = c.WSSURL("//other.test/ws"); err == nil {
		t.Fatal("accepted untrusted WS path")
	}
}
