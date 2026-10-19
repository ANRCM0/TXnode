package credentialprovider

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserRenderCanonicalOriginConfiguration(t *testing.T) {
	for _, origin := range []string{"https://panel.example", "https://panel.example:8443", "https://127.0.0.1", "https://[::1]:8443"} {
		if _, err := newRenderCORS([]string{origin}); err != nil {
			t.Errorf("valid canonical origin rejected: %s", origin)
		}
	}
	for _, origin := range []string{"", "null", "*", "http://panel.example", "HTTPS://panel.example", "https://Panel.example", " https://panel.example", "https://panel.example ", "https://panel.example/", "https://panel.example/path", "https://panel.example?", "https://panel.example#", "https://u@panel.example", "https://*.example", "https://panel.example,https://other.example", "https://panel.example:443", "https://panel.example:0", "https://panel.example:65536", "https://panel.example:08443", "https://panel.example:", "https://panel.example.", "https://-panel.example", "https://panel_.example", "https://127.1", "https://2130706433", "https://0x7f000001", "https://[0:0::1]", "https://[fe80::1%25eth0]"} {
		if _, err := newRenderCORS([]string{origin}); err == nil {
			t.Errorf("noncanonical origin accepted: %s", origin)
		}
	}
	if _, err := newRenderCORS([]string{"https://panel.example", "https://panel.example"}); err == nil {
		t.Fatal("duplicate origins accepted")
	}
	if _, err := newRenderCORS(make([]string, 17)); err == nil {
		t.Fatal("unbounded allowlist accepted")
	}
	if err := Run(context.Background(), Config{SubscriptionOrigins: []string{"https://panel.example"}}, nil); err == nil || err.Error() != "RENDER_CONFIG_INVALID" {
		t.Fatal("origins without public listener were not rejected before opening resources")
	}
}

func browserRenderRequest(method string) *http.Request {
	r := httptest.NewRequest(method, "https://provider.example/subscription-render", strings.NewReader(`{"contract_version":"credential-render/1","request_id":"browser-render-1","authorization":{"payload":"","signature":""},"proof":""}`))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.Header.Set("Origin", "https://panel.example")
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestBrowserRenderCORSPreflightsAreBoundedAndDoNotReadState(t *testing.T) {
	allowed, err := newRenderCORS([]string{"https://panel.example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"allow", func(*http.Request) {}, 204},
		{"accept", func(r *http.Request) { r.Header.Set("Access-Control-Request-Headers", "content-type, Accept") }, 204},
		{"deny-origin", func(r *http.Request) { r.Header.Set("Origin", "https://other.example") }, 403},
		{"null", func(r *http.Request) { r.Header.Set("Origin", "null") }, 403},
		{"wildcard", func(r *http.Request) { r.Header.Set("Origin", "*") }, 403},
		{"empty-origin", func(r *http.Request) { r.Header.Set("Origin", "") }, 403},
		{"duplicate-origin", func(r *http.Request) { r.Header.Add("Origin", "https://panel.example") }, 403},
		{"joined-origin", func(r *http.Request) { r.Header.Set("Origin", "https://panel.example, https://other.example") }, 403},
		{"method", func(r *http.Request) { r.Header.Set("Access-Control-Request-Method", "GET") }, 403},
		{"duplicate-method", func(r *http.Request) { r.Header.Add("Access-Control-Request-Method", "POST") }, 403},
		{"empty-method", func(r *http.Request) { r.Header.Set("Access-Control-Request-Method", "") }, 403},
		{"authorization", func(r *http.Request) { r.Header.Set("Access-Control-Request-Headers", "content-type, authorization") }, 403},
		{"custom-header", func(r *http.Request) { r.Header.Set("Access-Control-Request-Headers", "content-type, x-custom") }, 403},
		{"duplicate-header", func(r *http.Request) { r.Header.Set("Access-Control-Request-Headers", "content-type, Content-Type") }, 403},
		{"multiple-header-lines", func(r *http.Request) { r.Header.Add("Access-Control-Request-Headers", "accept") }, 403},
		{"empty-header", func(r *http.Request) { r.Header.Set("Access-Control-Request-Headers", "") }, 403},
		{"empty-token", func(r *http.Request) { r.Header.Set("Access-Control-Request-Headers", "content-type,") }, 403},
		{"missing-header", func(r *http.Request) { r.Header.Del("Access-Control-Request-Headers") }, 403},
		{"cookie", func(r *http.Request) { r.Header.Set("Cookie", "session=value") }, 403},
	} {
		t.Run(item.name, func(t *testing.T) {
			r := browserRenderRequest(http.MethodOptions)
			r.Header.Set("Access-Control-Request-Method", "POST")
			r.Header.Set("Access-Control-Request-Headers", "content-type")
			item.change(r)
			w := httptest.NewRecorder()
			// This policy has no store or trust reference to consult.
			if !allowed.handle(w, r) || w.Code != item.status {
				t.Fatalf("preflight status %d, expected %d", w.Code, item.status)
			}
			if w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Access-Control-Max-Age") != "" {
				t.Fatal("credentialed or cached preflight enabled")
			}
			if item.status == 204 {
				if w.Header().Get("Access-Control-Allow-Origin") != "https://panel.example" || w.Body.Len() != 0 {
					t.Fatal("preflight reflected an incorrect origin or body")
				}
			} else if w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("rejected preflight exposed policy")
			}
		})
	}
}

func TestBrowserRenderHandlerKeepsTLSPathAndProofBoundaries(t *testing.T) {
	store, _ := testStore(t)
	trust, _ := deliveryKey(t)
	handler, err := NewBrowserRenderHandler(store, trust, []string{"https://panel.example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name   string
		change func(*http.Request)
		status int
		cors   bool
	}{
		{"no-proof", func(*http.Request) {}, 403, true},
		{"cli-still-requires-proof", func(r *http.Request) { r.Header.Del("Origin") }, 403, false},
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer value") }, 403, false},
		{"proxy-authorization", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Basic value") }, 403, false},
		{"cookie", func(r *http.Request) { r.Header.Set("Cookie", "session=value") }, 403, false},
		{"control-route", func(r *http.Request) { r.URL.Path = "/operations" }, 404, false},
		{"raw-path", func(r *http.Request) { r.URL.RawPath = "/subscription%2drender" }, 404, false},
		{"query", func(r *http.Request) { r.URL.RawQuery = "x=1" }, 404, false},
		{"empty-query", func(r *http.Request) { r.URL.ForceQuery = true }, 404, false},
		{"tls12", func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 }, 403, false},
		{"no-tls", func(r *http.Request) { r.TLS = nil }, 403, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			r := browserRenderRequest(http.MethodPost)
			item.change(r)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != item.status || (w.Header().Get("Access-Control-Allow-Origin") != "") != item.cors || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unexpected response: %d %v", w.Code, w.Header())
			}
		})
	}
	defaultHandler, err := NewRenderHandler(store, trust)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	defaultHandler.ServeHTTP(w, browserRenderRequest(http.MethodPost))
	if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("browser rendering enabled by default")
	}
	control, err := NewHandler(store, []string{strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	control.ServeHTTP(w, browserRenderRequest(http.MethodOptions))
	if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("control listener adopted public CORS policy")
	}
}
