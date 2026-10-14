package txboard

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
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
func writeSnapshotUsers(t *testing.T, w http.ResponseWriter, id int, etag string, users any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	if err := json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"protocol_version": 1, "node_id": id, "users": users}}); err != nil {
		t.Errorf("write users: %v", err)
	}
}

func TestNativeCompleteSnapshotsRedeliverAfterOtherEndpointFailure(t *testing.T) {
	var configCalls, usersCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case prefix + "/config":
			configCalls++
			if configCalls == 1 {
				writeSnapshotConfig(t, w, 42, `"new-config"`, &panel.NodeConfig{Protocol: "vless", ServerPort: 24443})
				return
			}
			if r.Header.Get("If-None-Match") != `"new-config"` {
				t.Errorf("config tag=%q", r.Header.Get("If-None-Match"))
			}
			w.WriteHeader(http.StatusNotModified)
		case prefix + "/users":
			usersCalls++
			if usersCalls == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			writeSnapshotUsers(t, w, 42, `"users"`, []panel.User{{ID: 7, UUID: "fixture-uuid"}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
	cfg, err := client.ConfigSnapshot()
	if err != nil || cfg == nil || cfg.ServerPort != 24443 {
		t.Fatalf("first config: %+v %v", cfg, err)
	}
	if users, err := client.UsersSnapshot(); err == nil || users != nil {
		t.Fatalf("users failure invented snapshot: %+v %v", users, err)
	}
	cfg, err = client.ConfigSnapshot()
	if err != nil || cfg == nil || cfg.ServerPort != 24443 {
		t.Fatalf("304 lost config: %+v %v", cfg, err)
	}
	users, err := client.UsersSnapshot()
	if err != nil || len(users) != 1 || users[0].ID != 7 {
		t.Fatalf("restored users: %+v %v", users, err)
	}
	if configCalls != 2 || usersCalls != 2 {
		t.Fatal("unexpected retry sequence")
	}
}

func TestNativeSnapshotClonesAllMutableConfigAndUserContent(t *testing.T) {
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
		writeSnapshotUsers(t, w, 42, `"users"`, []panel.User{{ID: 7, UUID: "original", SpeedLimit: 5, DeviceLimit: 2}})
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
	users, err := client.GetUsers()
	if err != nil {
		t.Fatal(err)
	}
	users[0].UUID = "changed"
	users, err = client.UsersSnapshot()
	if err != nil || users[0].UUID != "original" {
		t.Fatalf("200 users aliased: %+v %v", users, err)
	}
	users[0].ID = 999
	users, err = client.UsersSnapshot()
	if err != nil || users[0].ID != 7 {
		t.Fatalf("304 users aliased: %+v %v", users, err)
	}
}

func TestNativeEmptyUserSnapshotAndLegacy304RemainDistinct(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.URL.Path == prefix+"/config" {
			writeSnapshotConfig(t, w, 42, `"config"`, &panel.NodeConfig{Protocol: "vless", ServerPort: 24443})
			return
		}
		writeSnapshotUsers(t, w, 42, `"empty"`, []panel.User{})
	}))
	defer server.Close()
	client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
	for i := 0; i < 2; i++ {
		users, err := client.UsersSnapshot()
		if err != nil || users == nil || len(users) != 0 {
			t.Fatalf("empty snapshot %d: %+v %v", i, users, err)
		}
	}
	if users, err := client.GetUsers(); err != nil || users != nil {
		t.Fatalf("legacy users304 changed: %+v %v", users, err)
	}
	if cfg, err := client.ConfigSnapshot(); err != nil || cfg == nil {
		t.Fatalf("first config: %+v %v", cfg, err)
	}
	if cfg, err := client.GetConfig(); err != nil || cfg != nil {
		t.Fatalf("legacy config304 changed: %+v %v", cfg, err)
	}
}

func TestNativeUncached304RetriesOnceUnconditionally(t *testing.T) {
	for _, endpoint := range []string{"config", "users"} {
		for _, recover := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recover=%v", endpoint, recover), func(t *testing.T) {
				var headers []string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					headers = append(headers, r.Header.Get("If-None-Match"))
					if len(headers) == 1 || !recover {
						w.WriteHeader(http.StatusNotModified)
						return
					}
					if endpoint == "config" {
						writeSnapshotConfig(t, w, 42, `"fresh"`, &panel.NodeConfig{Protocol: "vless", ServerPort: 24443})
						return
					}
					writeSnapshotUsers(t, w, 42, `"fresh"`, []panel.User{})
				}))
				defer server.Close()
				client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
				client.configETag, client.usersETag = `"orphan"`, `"orphan"`
				var err error
				if endpoint == "config" {
					var cfg *panel.NodeConfig
					cfg, err = client.ConfigSnapshot()
					if recover && cfg == nil {
						t.Fatal("recovery config missing")
					}
					if !recover && cfg != nil {
						t.Fatal("invented config")
					}
				} else {
					var users []panel.User
					users, err = client.UsersSnapshot()
					if recover && users == nil {
						t.Fatal("recovery empty users lost")
					}
					if !recover && users != nil {
						t.Fatal("invented empty users")
					}
				}
				if (err == nil) != recover || len(headers) != 2 || headers[0] != `"orphan"` || headers[1] != "" {
					t.Fatalf("retry sequence=%v err=%v", headers, err)
				}
			})
		}
	}
}

func TestNativeInvalid200CannotAdvanceSnapshotETag(t *testing.T) {
	for _, endpoint := range []string{"config", "users"} {
		for _, kind := range []string{"wrong-node", "wrong-version", "missing-content", "null-content", "invalid-content"} {
			t.Run(endpoint+"/"+kind, func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if calls == 3 {
						if r.Header.Get("If-None-Match") != `"confirmed"` {
							t.Errorf("invalid200 advanced tag %q", r.Header.Get("If-None-Match"))
						}
						w.WriteHeader(http.StatusNotModified)
						return
					}
					payload := map[string]any{"protocol_version": 1, "node_id": 42}
					if endpoint == "config" {
						payload["config"] = &panel.NodeConfig{Protocol: "vless", ServerPort: 24443}
					} else {
						payload["users"] = []panel.User{{ID: 7, UUID: "original"}}
					}
					w.Header().Set("ETag", `"confirmed"`)
					if calls == 2 {
						w.Header().Set("ETag", `"invalid"`)
						switch kind {
						case "wrong-node":
							payload["node_id"] = 99
						case "wrong-version":
							payload["protocol_version"] = 2
						case "missing-content":
							delete(payload, endpoint)
						case "null-content":
							payload[endpoint] = nil
						case "invalid-content":
							payload[endpoint] = "not-a-body"
						}
					}
					json.NewEncoder(w).Encode(map[string]any{"data": payload})
				}))
				defer server.Close()
				client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
				if endpoint == "config" {
					if _, err := client.ConfigSnapshot(); err != nil {
						t.Fatal(err)
					}
					if got, err := client.ConfigSnapshot(); err == nil || got != nil {
						t.Fatalf("invalid config accepted: %+v %v", got, err)
					}
					if got, err := client.ConfigSnapshot(); err != nil || got == nil || got.ServerPort != 24443 {
						t.Fatalf("valid cache lost: %+v %v", got, err)
					}
				} else {
					if _, err := client.UsersSnapshot(); err != nil {
						t.Fatal(err)
					}
					if got, err := client.UsersSnapshot(); err == nil || got != nil {
						t.Fatalf("invalid users accepted/invented: %+v %v", got, err)
					}
					if got, err := client.UsersSnapshot(); err != nil || len(got) != 1 || got[0].ID != 7 {
						t.Fatalf("valid cache lost: %+v %v", got, err)
					}
				}
			})
		}
	}
}

func TestNativeSnapshotResetClearsOnlyCorrespondingScope(t *testing.T) {
	var configHeaders, userHeaders []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := r.Header.Get("If-None-Match")
		if r.URL.Path == prefix+"/config" {
			configHeaders = append(configHeaders, tag)
			if tag != "" {
				w.WriteHeader(304)
				return
			}
			writeSnapshotConfig(t, w, 42, `"config"`, &panel.NodeConfig{Protocol: "vless", ServerPort: 24443})
			return
		}
		userHeaders = append(userHeaders, tag)
		if tag != "" {
			w.WriteHeader(304)
			return
		}
		writeSnapshotUsers(t, w, 42, `"users"`, []panel.User{})
	}))
	defer server.Close()
	client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
	pull := func() {
		t.Helper()
		if _, err := client.ConfigSnapshot(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.UsersSnapshot(); err != nil {
			t.Fatal(err)
		}
	}
	pull()
	client.ResetConfigETag()
	pull()
	client.ResetETags()
	pull()
	if !reflect.DeepEqual(configHeaders, []string{"", "", ""}) || !reflect.DeepEqual(userHeaders, []string{"", `"users"`, ""}) {
		t.Fatalf("reset scopes config=%v users=%v", configHeaders, userHeaders)
	}
}

func TestNativeForNodeAndConcurrentReadersHaveIndependentSnapshots(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.Header.Get("X-TX-Node-ID"))
		if err != nil {
			t.Error(err)
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(304)
			return
		}
		if r.URL.Path == prefix+"/config" {
			writeSnapshotConfig(t, w, id, `"same-tag"`, &panel.NodeConfig{Protocol: "vless", ServerPort: 24000 + id})
			return
		}
		writeSnapshotUsers(t, w, id, `"same-tag"`, []panel.User{{ID: id, UUID: strconv.Itoa(id)}})
	}))
	defer server.Close()
	parent := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", MachineID: 7, NodeID: 42})
	if _, err := parent.ConfigSnapshot(); err != nil {
		t.Fatal(err)
	}
	if _, err := parent.UsersSnapshot(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		id := 42 + i
		client := parent.ForNode(id)
		for j := 0; j < 2; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 3; k++ {
					cfg, err := client.ConfigSnapshot()
					if err != nil || cfg == nil || cfg.ServerPort != 24000+id {
						t.Errorf("node%d config=%+v err=%v", id, cfg, err)
						return
					}
					users, err := client.UsersSnapshot()
					if err != nil || len(users) != 1 || users[0].ID != id {
						t.Errorf("node%d users=%+v err=%v", id, users, err)
						return
					}
					cfg.ServerPort = 1
					users[0].ID = 1
				}
			}()
		}
	}
	wg.Wait()
}

func TestNativeResetInvalidatesInFlightReadWithoutBlocking(t *testing.T) {
	for _, endpoint := range []string{"config", "users"} {
		t.Run(endpoint, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				once.Do(func() { close(started); <-release })
				if r.Header.Get("If-None-Match") != "" {
					t.Errorf("invalidated tag survived: %q", r.Header.Get("If-None-Match"))
				}
				if endpoint == "config" {
					writeSnapshotConfig(t, w, 42, `"body"`, &panel.NodeConfig{Protocol: "vless", ServerPort: 24443})
					return
				}
				writeSnapshotUsers(t, w, 42, `"body"`, []panel.User{})
			}))
			defer server.Close()
			client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42})
			read := func() error {
				if endpoint == "config" {
					_, err := client.ConfigSnapshot()
					return err
				}
				_, err := client.UsersSnapshot()
				return err
			}
			result := make(chan error, 1)
			go func() { result <- read() }()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("request did not start")
			}
			resetDone := make(chan struct{})
			go func() { client.ResetETags(); close(resetDone) }()
			select {
			case <-resetDone:
			case <-time.After(2 * time.Second):
				close(release)
				t.Fatal("reset blocked on HTTP")
			}
			close(release)
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("stale read survived reset")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("read did not terminate")
			}
			if err := read(); err != nil {
				t.Fatal(err)
			}
		})
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

func TestNativeCompleteSnapshotPreservesTypedAuthorityDenial(t *testing.T) {
	for _, endpoint := range []string{"config", "users"} {
		t.Run(endpoint, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(401)
				fmt.Fprint(w, validDenial)
			}))
			defer server.Close()
			client := NewClient(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42, MachineID: 7})
			var err error
			if endpoint == "config" {
				_, err = client.ConfigSnapshot()
			} else {
				_, err = client.UsersSnapshot()
			}
			denial, ok := controlerror.AsAuthorityDenial(err)
			if !ok || denial.Scope != controlerror.MachineScope || denial.NodeID != 42 || denial.MachineID != 7 {
				t.Fatalf("typed denial lost: %v", err)
			}
		})
	}
}
