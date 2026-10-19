package credentialdelivery

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	RenderClash        = "clash/v1"
	RenderClashMeta    = "clash-meta/v1"
	RenderSingBox      = "sing-box/v1"
	RenderShadowrocket = "shadowrocket/v1"
	RenderSurgeIOS     = "surge-ios/v1"
	RenderSurgeMac     = "surge-mac/v1"
)

var clientVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)

// These ranges are admission rules for this finite renderer revision. They do
// not select a format from a caller-controlled user-agent or widen node policy.
func ValidRenderFormat(format, version string) bool {
	if format == RenderFormat {
		return version == ""
	}
	if !clientVersionRE.MatchString(version) {
		return false
	}
	parts := strings.Split(version, ".")
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	switch format {
	case RenderClash, RenderClashMeta:
		return major == 1 && minor >= 18
	case RenderSingBox:
		return major == 1 && minor >= 10 && minor < 13
	case RenderShadowrocket:
		return major == 2 && minor >= 2
	case RenderSurgeIOS:
		return major == 5 && minor >= 20
	case RenderSurgeMac:
		return major == 6 && minor >= 7
	default:
		return false
	}
}

func ValidRenderProfile(format, profile string) bool {
	switch format {
	case RenderClash, RenderSurgeIOS, RenderSurgeMac:
		return profile == "vmess-uuid/v1"
	case RenderFormat, RenderClashMeta, RenderSingBox, RenderShadowrocket:
		return profile == "vless-uuid/v1" || profile == "vmess-uuid/v1"
	default:
		return false
	}
}

func CompatibleRenderNode(format string, node ConnectionNode) bool {
	return validNode(node, node.Protocol+"-uuid/v1") && ValidRenderProfile(format, node.Protocol+"-uuid/v1") &&
		(format != RenderClash || node.TLS == nil || len(node.TLS.ALPN) == 0)
}
