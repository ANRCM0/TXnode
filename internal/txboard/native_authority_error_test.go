package txboard

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
)

const validDenial = `{"error":{"code":"NODE_UNAUTHORIZED","message":"secret-response-message"},"request_id":"fixture-request"}`

func TestNativeAuthorityDenialClosedStatusPathAndScope(t *testing.T) {
	cases := []struct {
		name, method, path, code string
		status, node, machine    int
		want                     controlerror.Scope
	}{
		{"standalone config", "GET", "/config", "NODE_UNAUTHORIZED", 401, 42, 0, controlerror.NodeScope},
		{"standalone users", "GET", "/users", "NODE_UNAUTHORIZED", 401, 42, 0, controlerror.NodeScope},
		{"standalone handshake", "POST", "/handshake", "NODE_UNAUTHORIZED", 401, 42, 0, controlerror.NodeScope},
		{"machine handshake", "POST", "/handshake", "NODE_UNAUTHORIZED", 401, 0, 7, controlerror.MachineScope},
		{"machine discovery", "GET", "/machine/nodes", "NODE_UNAUTHORIZED", 401, 0, 7, controlerror.MachineScope},
		{"machine node config", "GET", "/config", "NODE_UNAUTHORIZED", 401, 42, 7, controlerror.MachineScope},
		{"machine node users", "GET", "/users", "NODE_UNAUTHORIZED", 401, 42, 7, controlerror.MachineScope},
		{"standalone node missing", "GET", "/config", "NODE_NOT_FOUND", 404, 42, 0, controlerror.NodeScope},
		{"machine node missing", "GET", "/users", "NODE_NOT_FOUND", 404, 42, 7, controlerror.NodeScope},
		{"machine node handshake missing", "POST", "/handshake", "NODE_NOT_FOUND", 404, 42, 7, controlerror.NodeScope},
		{"machine discovery missing", "GET", "/machine/nodes", "NODE_NOT_FOUND", 404, 0, 7, 0},
		{"discovery with node header missing", "GET", "/machine/nodes", "NODE_NOT_FOUND", 404, 42, 7, 0},
		{"no identity", "POST", "/handshake", "NODE_UNAUTHORIZED", 401, 0, 0, 0},
		{"discovery without machine identity", "GET", "/machine/nodes", "NODE_UNAUTHORIZED", 401, 42, 0, 0},
		{"config without node identity", "GET", "/config", "NODE_UNAUTHORIZED", 401, 0, 7, 0},
		{"users without node identity", "GET", "/users", "NODE_UNAUTHORIZED", 401, 0, 7, 0},
		{"node missing without node id", "POST", "/handshake", "NODE_NOT_FOUND", 404, 0, 7, 0},
		{"forbidden", "GET", "/users", "NODE_UNAUTHORIZED", 403, 42, 7, 0},
		{"unavailable", "GET", "/config", "NODE_UNAUTHORIZED", 503, 42, 7, 0},
		{"wrong status unauthorized", "GET", "/config", "NODE_UNAUTHORIZED", 404, 42, 7, 0},
		{"wrong status not found", "GET", "/config", "NODE_NOT_FOUND", 401, 42, 7, 0},
		{"unknown code", "GET", "/config", "AUTH_FORBIDDEN", 401, 42, 7, 0},
		{"report rejection", "POST", "/report", "NODE_UNAUTHORIZED", 401, 42, 7, 0},
		{"audit read rejection", "GET", "/audit/rules", "NODE_UNAUTHORIZED", 401, 42, 7, 0},
		{"audit write rejection", "POST", "/audit/report", "NODE_UNAUTHORIZED", 401, 42, 7, 0},
		{"status write rejection", "POST", "/machine/status", "NODE_UNAUTHORIZED", 401, 42, 7, 0},
		{"wrong method", "POST", "/config", "NODE_UNAUTHORIZED", 401, 42, 7, 0},
		{"unknown suffix", "GET", "/users/", "NODE_UNAUTHORIZED", 401, 42, 7, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != prefix+tc.path {
					t.Errorf("wrong native request")
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"error":{"code":%q,"message":"secret-response-message"},"request_id":"fixture","machine_id":999,"node_id":999}`, tc.code)
			}))
			defer server.Close()
			client := NewClient(config.PanelConfig{URL: server.URL, Token: "secret-credential", NodeID: tc.node, MachineID: tc.machine})
			resp, err := client.request(tc.method, tc.path, nil, "")
			if err == nil {
				err = decode(resp, new(any), 200)
			}
			denial, ok := controlerror.AsAuthorityDenial(err)
			if ok != (tc.want != 0) {
				t.Fatalf("classified=%v want=%v err=%v", ok, tc.want != 0, err)
			}
			if ok && (denial.Scope != tc.want || denial.NodeID != tc.node || denial.MachineID != tc.machine || denial.HTTPStatus != tc.status || denial.Code != tc.code) {
				t.Fatalf("wrong bound identity: %+v", denial)
			}
			if err == nil || strings.Contains(err.Error(), "secret-") || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("unsafe/missing error %v", err)
			}
		})
	}
}

func TestNativeAuthorityDenialRejectsAmbiguousOrIncompleteEnvelopes(t *testing.T) {
	exactLimit := validDenial + strings.Repeat(" ", maxAuthorityError-len(validDenial))
	cases := []struct {
		name, contentType, body string
		want                    bool
	}{
		{"valid", "application/json", validDenial, true},
		{"complete whitespace at size limit", "application/json", exactLimit, true},
		{"over size limit", "application/json", exactLimit + " ", false},
		{"html", "text/html", validDenial, false},
		{"missing media type", "", validDenial, false},
		{"unsupported json type", "application/problem+json", validDenial, false},
		{"invalid media type", "application/json; charset", validDenial, false},
		{"proxy page", "application/json", `<h1>404</h1>`, false},
		{"truncated", "application/json", validDenial[:len(validDenial)-1], false},
		{"second json", "application/json", validDenial + `{}`, false},
		{"tail garbage", "application/json", validDenial + `secret-tail`, false},
		{"duplicate code", "application/json", `{"error":{"code":"OTHER","code":"NODE_UNAUTHORIZED","message":"x"},"request_id":"r"}`, false},
		{"escaped duplicate code", "application/json", `{"error":{"code":"OTHER","\u0063ode":"NODE_UNAUTHORIZED","message":"x"},"request_id":"r"}`, false},
		{"duplicate request id", "application/json", `{"error":{"code":"NODE_UNAUTHORIZED","message":"x"},"request_id":"x","request_id":"r"}`, false},
		{"duplicate optional nested key", "application/json", `{"error":{"code":"NODE_UNAUTHORIZED","message":"x","fields":{"nested":[{"a":1,"a":2}]}},"request_id":"r"}`, false},
		{"success data null", "application/json", `{"error":{"code":"NODE_UNAUTHORIZED","message":"x"},"request_id":"r","data":null}`, false},
		{"missing request id", "application/json", `{"error":{"code":"NODE_UNAUTHORIZED","message":"x"}}`, false},
		{"empty request id", "application/json", `{"error":{"code":"NODE_UNAUTHORIZED","message":"x"},"request_id":" "}`, false},
		{"numeric request id", "application/json", `{"error":{"code":"NODE_UNAUTHORIZED","message":"x"},"request_id":1}`, false},
		{"large request id", "application/json", strings.Replace(validDenial, "fixture-request", strings.Repeat("a", 257), 1), false},
		{"missing message", "application/json", `{"error":{"code":"NODE_UNAUTHORIZED"},"request_id":"r"}`, false},
		{"non string message", "application/json", `{"error":{"code":"NODE_UNAUTHORIZED","message":null},"request_id":"r"}`, false},
		{"non object error", "application/json", `{"error":"NODE_UNAUTHORIZED","request_id":"r"}`, false},
		{"non string code", "application/json", `{"error":{"code":401,"message":"x"},"request_id":"r"}`, false},
		{"top array", "application/json", `[` + validDenial + `]`, false},
		{"invalid utf8", "application/json", strings.Replace(validDenial, "secret-response-message", string([]byte{0xff}), 1), false},
		{"over nesting limit", "application/json", strings.TrimSuffix(validDenial, "}") + `,"nested":` + strings.Repeat("[", 130) + `0` + strings.Repeat("]", 130) + `}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(401)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := NewClient(config.PanelConfig{URL: server.URL, Token: "secret-credential", NodeID: 42})
			_, err := client.GetConfig()
			_, ok := controlerror.AsAuthorityDenial(err)
			if ok != tc.want {
				t.Fatalf("classified=%v want=%v err=%v", ok, tc.want, err)
			}
			if err == nil || strings.Contains(err.Error(), "secret-") {
				t.Fatalf("unsafe/missing error %v", err)
			}
		})
	}
}

type authorityRoundTripper func(*http.Request) (*http.Response, error)

func (f authorityRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type interruptedAuthorityBody struct {
	delivered bool
	closed    bool
}

func (b *interruptedAuthorityBody) Read(p []byte) (int, error) {
	if b.delivered {
		return 0, errors.New("secret-body-read-error")
	}
	b.delivered = true
	return copy(p, validDenial), errors.New("secret-body-read-error")
}
func (b *interruptedAuthorityBody) Close() error { b.closed = true; return nil }

func TestNativeAuthorityDenialRequiresCompletedBodyAndKeepsTransportFailuresSafe(t *testing.T) {
	body := &interruptedAuthorityBody{}
	client := NewClient(config.PanelConfig{URL: "https://configured.test", Token: "secret-token", NodeID: 42})
	client.http.Transport = authorityRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body, Request: r}, nil
	})
	_, err := client.GetConfig()
	if _, ok := controlerror.AsAuthorityDenial(err); ok || err == nil || !body.closed || strings.Contains(err.Error(), "secret-") {
		t.Fatalf("incomplete body unsafe/classified: %v", err)
	}
	client.http.Transport = authorityRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret-token transport error") })
	_, err = client.GetConfig()
	if _, ok := controlerror.AsAuthorityDenial(err); ok || err == nil || strings.Contains(err.Error(), "secret-") || strings.Contains(err.Error(), "configured.test") {
		t.Fatalf("transport error unsafe/classified: %v", err)
	}
}

func TestNativeAuthorityDenialDoesNotFollowRedirectsOrMutateSharedTLSClient(t *testing.T) {
	var redirected, configuredPolicy atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == prefix+"/config" {
			http.Redirect(w, r, prefix+"/redirect-target", http.StatusFound)
			return
		}
		redirected.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		io.WriteString(w, validDenial)
	}))
	defer server.Close()
	client := NewClient(config.PanelConfig{URL: server.URL, Token: "secret-token", MachineID: 7})
	client.http = server.Client()
	client.http.CheckRedirect = func(*http.Request, []*http.Request) error { configuredPolicy.Add(1); return nil }
	transport := client.http.Transport
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			child := client.ForNode(42 + i)
			_, err := child.GetConfig()
			if _, ok := controlerror.AsAuthorityDenial(err); ok || err == nil {
				t.Errorf("redirect classified/missing error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if redirected.Load() != 0 || configuredPolicy.Load() != 0 || client.http.Transport != transport {
		t.Fatal("redirect followed or configured TLS transport changed")
	}
	if client.http.CheckRedirect == nil {
		t.Fatal("shared redirect policy changed")
	}
	client.http.CheckRedirect(nil, nil)
	if configuredPolicy.Load() != 1 {
		t.Fatal("shared redirect policy replaced")
	}
}

func TestNativeOrdinaryErrorDiagnosticNeverIncludesResponseBody(t *testing.T) {
	for _, status := range []int{401, 403, 404, 500} {
		response := &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("secret-response-token"))}
		err := decode(response, new(any), 200)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("HTTP%d leaked body: %v", status, err)
		}
	}
}

func TestNativeTLSFailureIsNotAuthorityDenial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		io.WriteString(w, validDenial)
	}))
	defer server.Close()
	client := NewClient(config.PanelConfig{URL: server.URL, Token: "secret-token", NodeID: 42})
	_, err := client.GetConfig()
	if _, ok := controlerror.AsAuthorityDenial(err); ok || err == nil || strings.Contains(err.Error(), "secret-") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("TLS failure classified or leaked: %v", err)
	}
}
