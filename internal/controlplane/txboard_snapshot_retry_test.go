package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
)

func TestTXBoardPollRetriesConfig200Users503WithComplete304Config(t *testing.T) {
	var configCalls, usersCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/txapi/node/v1/config":
			configCalls++
			if configCalls == 1 {
				w.Header().Set("ETag", `"new-port"`)
				fmt.Fprint(w, `{"data":{"protocol_version":1,"node_id":42,"config":{"protocol":"vless","server_port":24443,"network":"tcp"}}}`)
				return
			}
			if r.Header.Get("If-None-Match") != `"new-port"` {
				t.Errorf("configETag=%q", r.Header.Get("If-None-Match"))
			}
			w.WriteHeader(304)
		case "/txapi/node/v1/users":
			usersCalls++
			if usersCalls == 1 {
				w.WriteHeader(503)
				return
			}
			if usersCalls > 2 {
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"users"`)
			fmt.Fprint(w, `{"data":{"protocol_version":1,"node_id":42,"users":[{"id":7,"uuid":"fixture-user"}]}}`)
		default:
			t.Errorf("unexpected native request %s", r.URL.Path)
		}
	}))
	defer server.Close()
	cp := NewTXBoardControlPlane(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42}, config.WSConfig{}, config.KernelConfig{Type: "singbox"})
	if snapshot, err := cp.Poll(context.Background()); err == nil || snapshot.Config != nil || snapshot.Users != nil {
		t.Fatalf("failed snapshot accepted: %+v %v", snapshot, err)
	}
	for i := 0; i < 2; i++ {
		snapshot, err := cp.Poll(context.Background())
		if err != nil || snapshot.Config == nil || snapshot.Config.ServerPort != 24443 || len(snapshot.Users) != 1 || snapshot.Users[0].ID != 7 {
			t.Fatalf("retry%d lost desired body: %+v %v", i, snapshot, err)
		}
		snapshot.Config.ServerPort = 1
		snapshot.Users[0].ID = 999
	}
	if configCalls != 3 || usersCalls != 3 {
		t.Fatalf("unexpected config/userscalls %d/%d", configCalls, usersCalls)
	}
}

func TestTXBoardSnapshotCacheResetForcesFreshReadsAndRetainsEmptyUsers(t *testing.T) {
	var configHeaders, userHeaders []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := r.Header.Get("If-None-Match")
		switch r.URL.Path {
		case "/txapi/node/v1/config":
			configHeaders = append(configHeaders, tag)
			if tag != "" {
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"config"`)
			fmt.Fprint(w, `{"data":{"protocol_version":1,"node_id":42,"config":{"protocol":"vless","server_port":24443}}}`)
		case "/txapi/node/v1/users":
			userHeaders = append(userHeaders, tag)
			if tag != "" {
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"users"`)
			fmt.Fprint(w, `{"data":{"protocol_version":1,"node_id":42,"users":[]}}`)
		default:
			t.Errorf("unexpected request")
		}
	}))
	defer server.Close()
	cp := NewTXBoardControlPlane(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42}, config.WSConfig{}, config.KernelConfig{Type: "singbox"})
	var reset interface{ ResetSnapshotCache() } = cp
	for i := 0; i < 3; i++ {
		if i == 2 {
			reset.ResetSnapshotCache()
		}
		got, err := cp.Poll(context.Background())
		if err != nil || got.Config == nil || got.Users == nil || len(got.Users) != 0 {
			t.Fatalf("poll%d empty/full semantics: %+v %v", i, got, err)
		}
	}
	if strings.Join(configHeaders, ",") != `,"config",` || strings.Join(userHeaders, ",") != `,"users",` {
		t.Fatalf("reset did not force read: config=%v users=%v", configHeaders, userHeaders)
	}
}

func TestTXBoardNormalizationFailureKeepsCachedDesiredConfigRetryable(t *testing.T) {
	configCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/txapi/node/v1/config" {
			configCalls++
			if configCalls > 1 {
				if r.Header.Get("If-None-Match") != `"invalid-runtime"` {
					t.Errorf("desired cache missing")
				}
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"invalid-runtime"`)
			fmt.Fprint(w, `{"data":{"protocol_version":1,"node_id":42,"config":{"protocol":"vless","server_port":24443,"network":"xhttp"}}}`)
			return
		}
		fmt.Fprint(w, `{"data":{"protocol_version":1,"node_id":42,"users":[]}}`)
	}))
	defer server.Close()
	cp := NewTXBoardControlPlane(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42}, config.WSConfig{}, config.KernelConfig{Type: "singbox"})
	for i := 0; i < 2; i++ {
		got, err := cp.Poll(context.Background())
		if err == nil || got.Config != nil || !strings.Contains(err.Error(), "xhttp") {
			t.Fatalf("normalization failure lost on retry%d: %+v %v", i, got, err)
		}
	}
	// The transport caches the desired body, not a kernel-specific success.
	// Changing the explicit validator lets the same304 body be processed again.
	cp.kernel.Type = "xray"
	got, err := cp.Poll(context.Background())
	if err != nil || got.Config == nil || got.Config.Network != "xhttp" {
		t.Fatalf("cached desired config could not retry: %+v %v", got, err)
	}
}

func TestTXBoardCachedSnapshotFailurePreservesAuthorityDenial(t *testing.T) {
	usersCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/txapi/node/v1/config" {
			w.Header().Set("ETag", `"config"`)
			if r.Header.Get("If-None-Match") != "" {
				w.WriteHeader(304)
				return
			}
			fmt.Fprint(w, `{"data":{"protocol_version":1,"node_id":42,"config":{"protocol":"vless","server_port":24443}}}`)
			return
		}
		usersCalls++
		if usersCalls == 1 {
			fmt.Fprint(w, `{"data":{"protocol_version":1,"node_id":42,"users":[]}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "NODE_NOT_FOUND", "message": "fixture"}, "request_id": "fixture"})
	}))
	defer server.Close()
	cp := NewTXBoardControlPlane(config.PanelConfig{URL: server.URL, Token: "fixture", NodeID: 42, MachineID: 7}, config.WSConfig{}, config.KernelConfig{Type: "singbox"})
	if _, err := cp.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := cp.Poll(context.Background())
	denial, ok := controlerror.AsAuthorityDenial(err)
	if !ok || denial.Scope != controlerror.NodeScope || denial.NodeID != 42 || denial.MachineID != 7 || got.Config != nil || got.Users != nil {
		t.Fatalf("denial hidden by cache: %+v %v", got, err)
	}
}
