package model

import (
	"strings"

	"github.com/ANRCM0/TX-Node/internal/config"
)

type NodeSpec struct {
	Protocol        string
	ListenIP        string
	ServerPort      int
	Network         string
	NetworkSettings map[string]any
	Routes          []RouteRule

	KernelType       string
	KernelLogLevel   string
	CustomOutbounds  []OutboundConfig
	CustomRoutes     []map[string]any
	CustomRouteRules []CustomRouteRule
	CertConfig       *config.CertConfig
	AutoTLS          bool
	Domain           string

	Cipher    string
	Plugin    string
	PluginOpt string
	ServerKey string

	TLS         int
	Flow        string
	Decryption  string
	TLSSettings map[string]any

	Host       string
	ServerName string

	Version      int
	UpMbps       int
	DownMbps     int
	Obfs         string
	ObfsPassword string

	CongestionControl string
	PaddingScheme     string
	Transport         string
	TrafficPattern    string

	Multiplex           *MultiplexConfig
	AcceptProxyProtocol bool
}

type OutboundConfig struct {
	Tag      string
	Protocol string
	Settings map[string]any
	ProxyTag string
}

type RouteRule struct {
	ID          int
	Match       []string
	Action      string
	ActionValue string
}

type MultiplexConfig struct {
	Enabled        bool
	Protocol       string
	MaxConnections int
	MinStreams     int
	MaxStreams     int
	Padding        bool
	Brutal         *BrutalConfig
}

type BrutalConfig struct {
	Enabled  bool
	UpMbps   int
	DownMbps int
}

type UserSpec struct {
	TrafficPeriod string
	ID            int
	UUID          string
	SpeedLimit    int
	DeviceLimit   int
}

// TrafficSegment retains the opaque Core authorization period observed by the
// meter owner; a zero-length period denotes explicit legacy/unbound bytes.
type TrafficSegment struct {
	UserID   int    `json:"user_id"`
	Period   string `json:"period"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

func (n *NodeSpec) GetProxyProtocol() bool {
	if n == nil {
		return false
	}
	if n.AcceptProxyProtocol {
		return true
	}
	if n.NetworkSettings != nil {
		if v, ok := n.NetworkSettings["acceptProxyProtocol"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return false
}

func (n *NodeSpec) GetProxyProtocolTrustedCIDRs() []string {
	if n == nil || n.NetworkSettings == nil {
		return nil
	}
	for _, key := range []string{"proxyProtocolTrustedCIDRs", "trustedProxyCIDRs", "proxy_protocol_trusted_cidrs"} {
		if values := stringListSetting(n.NetworkSettings[key]); len(values) > 0 {
			return values
		}
	}
	return nil
}

func (n *NodeSpec) GetProxyProtocolAcceptNoHeader() bool {
	if n == nil || n.NetworkSettings == nil {
		return false
	}
	for _, key := range []string{"proxyProtocolAcceptNoHeader", "proxy_protocol_accept_no_header"} {
		if value, ok := n.NetworkSettings[key].(bool); ok {
			return value
		}
	}
	return false
}

func stringListSetting(value any) []string {
	appendValue := func(out []string, value string) []string {
		for _, item := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\r'
		}) {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	}

	var out []string
	switch values := value.(type) {
	case string:
		out = appendValue(out, values)
	case []string:
		for _, item := range values {
			out = appendValue(out, item)
		}
	case []any:
		for _, item := range values {
			if text, ok := item.(string); ok {
				out = appendValue(out, text)
			}
		}
	}
	return out
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneMapSlice(src []map[string]any) []map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(src))
	for _, item := range src {
		out = append(out, cloneAnyMap(item))
	}
	return out
}

func cloneStringSlice(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}
