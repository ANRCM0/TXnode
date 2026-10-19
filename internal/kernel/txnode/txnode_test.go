package txnode

import (
	"testing"

	"github.com/ANRCM0/TX-Node/internal/model"
)

func TestNormalizeProtocolAliases(t *testing.T) {
	cases := map[string]string{
		"vless":       "vless",
		"vmess":       "vmess",
		"trojan":      "trojan",
		"shadowsocks": "shadowsocks",
		"socks":       "socks5",
		"socks5":      "socks5",
		"http":        "httpproxy",
		"anytls":      "anytls",
		"naive":       "naive",
		"mieru":       "mieru",
		"snell":       "snell",
		"hysteria":    "hysteria",
		"hysteria2":   "hysteria",
		"tuic":        "tuic",
	}
	for in, want := range cases {
		got, err := normalizeProtocol(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Fatalf("%s -> %s, want %s", in, got, want)
		}
	}
	if _, err := normalizeProtocol("nope"); err == nil {
		t.Fatal("unknown protocol accepted")
	}
}

func TestSpecFromNodeFlattensSettings(t *testing.T) {
	ns := &model.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: 8443,
		Network:    "tcp",
		TLS:        2,
		NetworkSettings: map[string]any{
			"path": "/ray",
			"host": "example.com",
		},
		TLSSettings: map[string]any{
			"private_key": "priv",
			"short_id":    []any{"01", "02"},
			"dest":        "www.example.com:443",
			"server_name": "www.example.com",
		},
	}
	sp, err := specFromNode(ns)
	if err != nil {
		t.Fatal(err)
	}
	if sp.Path != "/ray" || sp.Host != "example.com" {
		t.Fatalf("transport settings: %+v", sp)
	}
	if sp.TLS != 2 || sp.RealityPrivateKey != "priv" || len(sp.RealityShortIDs) != 2 {
		t.Fatalf("reality settings: %+v", sp)
	}
	if sp.Addr() != "127.0.0.1:8443" {
		t.Fatalf("addr = %s", sp.Addr())
	}
}

func TestSpecRejectsHysteriaV1(t *testing.T) {
	ns := &model.NodeSpec{Protocol: "hysteria", ServerPort: 443, TLS: 1, Version: 1}
	if _, err := specFromNode(ns); err == nil {
		t.Fatal("hysteria v1 accepted")
	}
	ns.Version = 2
	if _, err := specFromNode(ns); err != nil {
		t.Fatalf("hysteria v2 rejected: %v", err)
	}
}

func TestCompileRouterPanelAndCustomRules(t *testing.T) {
	ns := &model.NodeSpec{
		Routes: []model.RouteRule{
			{ID: 1, Match: []string{"example.com"}, Action: "block"},
			{ID: 2, Match: []string{"10.0.0.0/8"}, Action: "direct"},
		},
		CustomOutbounds: []model.OutboundConfig{
			{Tag: "up", Protocol: "socks", Settings: map[string]any{"server": "127.0.0.1", "server_port": 1080}},
		},
		CustomRouteRules: []model.CustomRouteRule{
			{Name: "ad", Match: model.RouteMatch{DomainSuffixes: []string{"ads.example"}}, Action: model.RouteAction{Type: "block"}},
			{Name: "jp", Match: model.RouteMatch{IPCIDRs: []string{"203.0.113.0/24"}}, Action: model.RouteAction{Type: "route", Target: "up"}},
		},
	}
	r, err := compileRouter(ns, RuntimeConfig{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rules) != 4 {
		t.Fatalf("rules = %d, want 4", len(r.Rules))
	}
	if _, ok := r.Outbounds["up"]; !ok {
		t.Fatal("custom outbound missing")
	}
}

func TestCompileRouterRejectsSourceMatch(t *testing.T) {
	ns := &model.NodeSpec{
		CustomRouteRules: []model.CustomRouteRule{
			{Name: "src", Match: model.RouteMatch{SourceCIDRs: []string{"192.0.2.0/24"}}, Action: model.RouteAction{Type: "block"}},
		},
	}
	if _, err := compileRouter(ns, RuntimeConfig{}, testLogger()); err == nil {
		t.Fatal("source_cidrs silently accepted")
	}
}

func TestDeviceGateLexicographicSelection(t *testing.T) {
	g := newDeviceGate()
	g.setLimitFunc(func(string) (int, bool) { return 2, true })
	g.setUsers([]model.UserSpec{{ID: 1, UUID: "u"}})
	// Fresh (no panel snapshot): local-only decision, lexicographic.
	local := map[string]int{"198.51.100.1": 1, "198.51.100.2": 1}
	if !g.Allow(1, mustAddr("198.51.100.1"), local) {
		t.Fatal("known address refused")
	}
	if g.Allow(1, mustAddr("198.51.100.3"), local) {
		t.Fatal("third address admitted over the limit")
	}
}
