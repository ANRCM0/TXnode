package txboard

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

func writeSnapshotConfig(t *testing.T, w http.ResponseWriter, id int, etag string, cfg any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	if err := json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"protocol_version": 1, "node_id": id, "config": cfg}}); err != nil {
		t.Errorf("write config: %v", err)
	}
}

func TestNativeCachedConfigCloneFailureRemainsExplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(304) }))
	defer server.Close()
	client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
	client.cachedConfig = &panel.NodeConfig{Protocol: "vless", NetworkSettings: map[string]any{"invalid": math.NaN()}}
	client.configETag = `"body"`
	if got, err := client.ConfigSnapshot(); err == nil || got != nil || !strings.Contains(err.Error(), "cannot clone") {
		t.Fatalf("clone failure hidden: %+v %v", got, err)
	}
}

func TestNativeSnapshotClonesAllMutableConfigContent(t *testing.T) {
	configBody := `{"protocol":"vless","server_port":23456,"networkSettings":{"headers":{"path":["one","two"]}},"tls_settings":{"names":["fixture.test"]},"routes":[{"id":1,"match":["original"],"action":"block"}],"custom_outbounds":[{"tag":"proxy","protocol":"socks","settings":{"nested":{"ports":[1080]}}}],"custom_routes":[{"domains":["original.test"]}],"custom_route_rules":[{"name":"rule","match":{"domains":["original.test"]},"action":{"type":"reject"}}],"cert_config":{"cert_mode":"dns","dns_env":{"KEY":"fixture"}},"multiplex":{"enabled":true,"brutal":{"up_mbps":10}}}`
	var cfg panel.NodeConfig
	if err := json.Unmarshal([]byte(configBody), &cfg); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.URL.Path == prefix+"/config" {
			writeSnapshotConfig(t, w, 42, `"config"`, &cfg)
			return
		}
		t.Error("unexpected non-config request")
	}))
	defer server.Close()
	client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
	first, err := client.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	first.NetworkSettings["headers"].(map[string]any)["path"].([]any)[0] = "changed"
	first.TLSSettings["names"].([]any)[0] = "changed"
	first.Routes[0].Match[0] = "changed"
	first.CustomOutbounds[0].Settings["nested"].(map[string]any)["ports"].([]any)[0] = float64(999)
	first.CustomRoutes[0]["domains"].([]any)[0] = "changed"
	first.CustomRouteRules[0].Match.Domains[0] = "changed"
	first.CertConfig.DNSEnv["KEY"] = "changed"
	first.Multiplex.Brutal.UpMbps = 999
	first, err = client.ConfigSnapshot()
	if err != nil || !reflect.DeepEqual(first, &cfg) {
		t.Fatalf("200 consumer mutated cache: %+v %v", first, err)
	}
	first.NetworkSettings["headers"].(map[string]any)["path"].([]any)[0] = "changed-again"
	first.CertConfig.DNSEnv["KEY"] = "changed-again"
	second, err := client.ConfigSnapshot()
	if err != nil || !reflect.DeepEqual(second, &cfg) {
		t.Fatalf("304 consumer mutated cache: %+v %v", second, err)
	}
}

func TestNativeConfigUncached304RetriesUnconditionally(t *testing.T) {
	for _, recover := range []bool{false, true} {
		t.Run(fmt.Sprint(recover), func(t *testing.T) {
			var headers []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers = append(headers, r.Header.Get("If-None-Match"))
				if len(headers) == 1 || !recover {
					w.WriteHeader(304)
					return
				}
				writeSnapshotConfig(t, w, 42, `"fresh"`, &panel.NodeConfig{Protocol: "vless", ServerPort: 24443})
			}))
			defer server.Close()
			client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
			client.configETag = `"orphan"`
			cfg, err := client.ConfigSnapshot()
			if (err == nil) != recover || recover && cfg == nil || len(headers) != 2 || headers[0] != `"orphan"` || headers[1] != "" {
				t.Fatalf("retry sequence=%v config=%+v err=%v", headers, cfg, err)
			}
		})
	}
}

func TestNativeConfigResetInvalidatesInFlightRead(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started); <-release })
		writeSnapshotConfig(t, w, 42, `"body"`, &panel.NodeConfig{Protocol: "vless", ServerPort: 24443})
	}))
	defer server.Close()
	client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
	result := make(chan error, 1)
	go func() { _, err := client.ConfigSnapshot(); result <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("read did not start")
	}
	client.ResetETags()
	close(release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("stale read survived cache reset")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read did not stop")
	}
	if cfg, err := client.ConfigSnapshot(); err != nil || cfg == nil {
		t.Fatal("fresh read failed", err)
	}
}
