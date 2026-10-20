package txnode

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/model"
)

// spec is the normalised node shape the builders below consume. It mirrors the
// panel semantics TX-Node stores in model.NodeSpec, but with the aliases
// resolved and the settings maps flattened, so protocol/transport code never
// touches a map.
type spec struct {
	Protocol string // factory name: vless/vmess/trojan/shadowsocks/socks5/httpproxy/.../hysteria/tuic
	ListenIP string
	Port     int

	Network     string // tcp/ws/httpupgrade/grpc/h2/xhttp
	Path        string
	Host        string
	ServiceName string
	XHTTP       map[string]any

	TLS        int // 0 none, 1 tls, 2 reality
	ServerName string
	ALPN       []string

	Flow       string
	Decryption string
	Cipher     string
	ServerKey  string

	Version int

	Plugin       string
	PluginOpts   string
	Obfs         string
	ObfsPassword string

	RealityPrivateKey  string
	RealityShortIDs    []string
	RealityDest        string
	RealityServerNames []string
	RealityMaxTimeDiff int

	MieruTransport      string
	MieruTrafficPattern string
	MieruHintRequired   bool

	PaddingScheme string
	Congestion    string
	UpMbps        int
	DownMbps      int
	BrutalSend    int
	BrutalReceive int

	ProxyProtocol        bool
	RequireProxyProtocol bool
}

// specFromNode flattens a panel node into the builder shape.
func specFromNode(nc *model.NodeSpec) (*spec, error) {
	if nc == nil {
		return nil, fmt.Errorf("node spec is nil")
	}
	factory, err := normalizeProtocol(nc.Protocol)
	if err != nil {
		return nil, err
	}
	sp := &spec{
		Protocol:     factory,
		ListenIP:     strings.TrimSpace(nc.ListenIP),
		Port:         nc.ServerPort,
		Network:      strings.ToLower(strings.TrimSpace(nc.Network)),
		ServerName:   strings.TrimSpace(nc.ServerName),
		TLS:          nc.TLS,
		Flow:         strings.TrimSpace(nc.Flow),
		Decryption:   strings.TrimSpace(nc.Decryption),
		Cipher:       strings.TrimSpace(nc.Cipher),
		ServerKey:    strings.TrimSpace(nc.ServerKey),
		Version:      nc.Version,
		Plugin:       strings.TrimSpace(nc.Plugin),
		PluginOpts:   strings.TrimSpace(nc.PluginOpt),
		Obfs:         strings.TrimSpace(nc.Obfs),
		ObfsPassword: strings.TrimSpace(nc.ObfsPassword),

		MieruTransport:      strings.TrimSpace(nc.Transport),
		MieruTrafficPattern: strings.TrimSpace(nc.TrafficPattern),
		MieruHintRequired:   mapBool(nc.NetworkSettings, "user_hint_mandatory"),

		PaddingScheme: strings.TrimSpace(nc.PaddingScheme),
		Congestion:    strings.TrimSpace(nc.CongestionControl),
		UpMbps:        nc.UpMbps,
		DownMbps:      nc.DownMbps,
	}
	if sp.Network == "" {
		sp.Network = "tcp"
	}
	if sp.ListenIP == "" {
		sp.ListenIP = "0.0.0.0"
	}
	if sp.Port <= 0 || sp.Port > 65535 {
		return nil, fmt.Errorf("node port %d is out of range", sp.Port)
	}

	// Transport settings shared by every stream network.
	sp.Path = mapString(nc.NetworkSettings, "path")
	if sp.Path == "" {
		sp.Path = strings.TrimSpace(nc.Host)
	}
	sp.Host = firstNonEmpty(mapString(nc.NetworkSettings, "host"), sp.ServerName)
	sp.ServiceName = firstNonEmpty(
		mapString(nc.NetworkSettings, "serviceName"),
		mapString(nc.NetworkSettings, "service_name"),
	)
	if strings.EqualFold(sp.Network, "xhttp") {
		sp.XHTTP = mapAny(nc.NetworkSettings, "xhttp")
		if sp.XHTTP == nil {
			sp.XHTTP = map[string]any{}
		}
	}

	// TLS / REALITY settings.
	sp.ALPN = mapStringList(nc.TLSSettings, "alpn")
	sp.RealityPrivateKey = mapString(nc.TLSSettings, "private_key")
	sp.RealityShortIDs = mapStringList(nc.TLSSettings, "short_id")
	sp.RealityDest = mapString(nc.TLSSettings, "dest")
	sp.RealityServerNames = mapStringList(nc.TLSSettings, "server_name")
	sp.RealityMaxTimeDiff = mapInt(nc.TLSSettings, "max_time_diff")

	if nc.Multiplex != nil && nc.Multiplex.Brutal != nil && nc.Multiplex.Brutal.Enabled {
		sp.BrutalSend = nc.Multiplex.Brutal.UpMbps
		sp.BrutalReceive = nc.Multiplex.Brutal.DownMbps
	}

	sp.ProxyProtocol = nc.GetProxyProtocol()
	sp.RequireProxyProtocol = mapBool(nc.NetworkSettings, "force_proxy_protocol")

	if err := sp.validate(); err != nil {
		return nil, err
	}
	return sp, nil
}

func (sp *spec) validate() error {
	switch sp.Protocol {
	case "hysteria":
		if sp.Version != 2 {
			return fmt.Errorf("hysteria: only version 2 is supported, got %d", sp.Version)
		}
		if sp.TLS != 1 {
			return fmt.Errorf("hysteria requires TLS")
		}
	case "tuic":
		if sp.TLS != 1 {
			return fmt.Errorf("tuic requires TLS")
		}
	case "naive":
		if sp.TLS != 1 {
			return fmt.Errorf("naive requires TLS")
		}
		if sp.Network != "tcp" && sp.Network != "h2" {
			return fmt.Errorf("naive works on tcp or h2, got %q", sp.Network)
		}
	case "shadowsocks":
		if sp.Cipher == "" {
			return fmt.Errorf("shadowsocks: cipher is required")
		}
	}
	if sp.TLS == 2 {
		switch sp.Network {
		case "tcp", "grpc", "h2", "xhttp":
		default:
			return fmt.Errorf("REALITY works on tcp, gRPC, H2 or XHTTP; got %q", sp.Network)
		}
		if sp.RealityPrivateKey == "" {
			return fmt.Errorf("REALITY requires tls_settings.private_key")
		}
		if len(sp.RealityShortIDs) == 0 {
			return fmt.Errorf("REALITY requires tls_settings.short_id")
		}
		if sp.RealityDest == "" && len(sp.RealityServerNames) == 0 {
			return fmt.Errorf("REALITY requires tls_settings.dest or server_name")
		}
	}
	return nil
}

// normalizeProtocol maps the panel vocabulary onto the data plane factories.
// Panel names are the ones validateNodeRuntime checks, so Protocols() and this
// table must stay in sync.
func normalizeProtocol(p string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "vless":
		return "vless", nil
	case "vmess":
		return "vmess", nil
	case "trojan":
		return "trojan", nil
	case "shadowsocks", "ss":
		return "shadowsocks", nil
	case "socks", "socks5":
		return "socks5", nil
	case "http":
		return "httpproxy", nil
	case "anytls":
		return "anytls", nil
	case "naive":
		return "naive", nil
	case "mieru":
		return "mieru", nil
	case "snell":
		return "snell", nil
	case "hysteria", "hysteria2":
		return "hysteria", nil
	case "tuic":
		return "tuic", nil
	default:
		return "", fmt.Errorf("protocol %q is not supported by kernel \"txnode\"", p)
	}
}

// Addr renders the listener address.
func (sp *spec) Addr() string {
	return net.JoinHostPort(sp.ListenIP, strconv.Itoa(sp.Port))
}

// quicOnly reports the protocols that never bind a TCP listener.
func quicOnly(proto string) bool {
	return proto == "hysteria" || proto == "tuic"
}

// needsUDP reports the protocols that open a datagram side (either their own
// QUIC socket or a PacketHandler socket).
func needsUDP(proto string) bool {
	switch proto {
	case "hysteria", "tuic", "shadowsocks", "socks5", "snell", "mieru":
		return true
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func mapString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

func mapBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	switch t := m[key].(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func mapInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch t := m[key].(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	}
	return 0
}

func mapAny(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

// mapStringList accepts a scalar or a list of scalars.
func mapStringList(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		var out []string
		for _, part := range strings.Split(t, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(t))
		for _, part := range t {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

// sortStringsCopy is a small helper for deterministic logs and tests.
func sortStringsCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
