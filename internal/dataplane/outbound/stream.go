package outbound

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
)

// stream is the transport half of one outbound: the subset of Xray's
// streamSettings and sing-box's outbound transport object that kaze's client
// implements. It is the shape readStream produces (outbound.readStream
// @0xb78d80, 0x41e0 bytes) and the option set ctransport.DialTCP expects
// (REPLICATION.md §3.3).
type stream struct {
	network  string // tcp, ws, httpupgrade, h2, grpc, xhttp
	security string // none, tls, reality
	tls      tlsSettings
	reality  realitySettings
	ws       wsSettings
	h2       h2Settings
	grpc     grpcSettings
	tcp      tcpSettings
	xhttp    opt.Opt
	plugin   *pluginSettings
	// udpOverTCP is 0 (native datagram), 2 (UDP-over-TCP v2) or 1 (rejected).
	udpOverTCP int
	strict     bool
	// raw keeps the original merged settings for the transport hook.
	raw opt.Opt
}

type tlsSettings struct {
	enabled     bool
	serverName  string
	insecure    bool
	alpn        []string
	fingerprint string
	pinned      []byte // SHA-256 of the peer certificate, from pinned_cert_sha256
	ech         string
}

type realitySettings struct {
	publicKey   string
	shortID     string
	serverName  string
	fingerprint string
}

type wsSettings struct {
	path                string
	host                string
	headers             map[string]string
	maxEarlyData        int
	earlyDataHeaderName string
}

type h2Settings struct {
	path    string
	host    string
	headers map[string]string
}

type grpcSettings struct {
	serviceName string
	multiMode   bool
}

type tcpSettings struct {
	header string
}

type pluginSettings struct {
	name string
	opts map[string]string
}

// network names the client understands. kcp/quic/… are server-only in kaze:
// the sample's error names the supported set.
var outboundNetworks = map[string]string{
	"":            "tcp",
	"tcp":         "tcp",
	"raw":         "tcp",
	"none":        "tcp",
	"ws":          "ws",
	"websocket":   "ws",
	"httpupgrade": "httpupgrade",
	"h2":          "h2",
	"http":        "h2",
	"grpc":        "grpc",
	"gun":         "grpc",
	"xhttp":       "xhttp",
	"splithttp":   "xhttp",
}

// readStream folds streamSettings and the transport dial into one description.
// It accepts both dialect spellings: Xray nests everything under
// streamSettings and uses wsSettings/grpcSettings/xhttpSettings/tlsSettings,
// sing-box uses a flat transport object with server_name/insecure/alpn and a
// nested tls object. node.mergeStream already merged StreamSettings into
// Settings (§19.3); readStream is called on that merged map and additionally
// merges a nested "streamSettings" if a caller passed the raw spec.
func readStream(o opt.Opt) (*stream, error) {
	if o == nil {
		o = opt.Opt{}
	}
	if sub := settings(o).sub("streamSettings", "stream_settings", "stream-settings"); sub != nil {
		o = opt.Merge(o, opt.Opt(sub))
	}
	s := settings(o)

	st := &stream{raw: o, network: "tcp"}
	netName := s.str(keysNetwork...)
	// sing-box nests the transport: {"transport": {"type": "ws", ...}}.
	var transport settings
	if m := s.sub("transport", "transportSettings", "transport_settings"); m != nil {
		transport = m
		if v := m.str("type"); v != "" {
			netName = v
		}
		if m.sub("headers") != nil {
			// path/host/headers/service_name live on the transport object.
			if st.ws.path == "" {
				st.ws.path = m.str("path")
			}
			if st.ws.host == "" {
				st.ws.host = m.str("host", "Host")
			}
			st.ws.headers = m.headers("headers")
			st.grpc.serviceName = m.str("service_name", "serviceName")
		}
	}
	if v := strings.ToLower(strings.TrimSpace(netName)); v != "" {
		n, ok := outboundNetworks[v]
		if !ok {
			return nil, fmt.Errorf("transport %q is not supported for outbounds; use tcp, ws, httpupgrade, h2, grpc or xhttp", v)
		}
		st.network = n
	}

	// TLS: Xray's `security` plus tlsSettings, or sing-box's `tls` object.
	tlsObj := s.sub("tls")
	var tlsMap settings
	if m := s.sub("tlsSettings", "tls_settings"); m != nil {
		tlsMap = m
	} else if tlsObj != nil {
		tlsMap = tlsObj
	}
	tlsEnabled := s.flag(keysTLS...)
	if tlsObj != nil {
		tlsEnabled = tlsObj.flag("enabled") || tlsObj.flag("true")
	}
	st.security = strings.ToLower(strings.TrimSpace(s.str(keysSecurity...)))
	if st.security == "" {
		if tlsEnabled {
			st.security = "tls"
		} else {
			st.security = "none"
		}
	}
	switch st.security {
	case "none", "tls", "reality":
	default:
		return nil, fmt.Errorf("security %q is not supported for outbounds; use none, tls or reality", st.security)
	}
	st.tls.enabled = st.security == "tls"
	if tlsMap != nil {
		st.tls.serverName = tlsMap.str(keysServerName...)
		st.tls.insecure = tlsMap.flag(keysAllowInsecure...)
		st.tls.alpn = tlsMap.list(keysALPN...)
		st.tls.fingerprint = tlsMap.str(keysFingerprint...)
		st.tls.ech = tlsMap.str("ech_config", "ech-config", "echConfigList", "ech")
		if u := tlsMap.sub("utls"); u != nil {
			if fp := u.str(keysFingerprint...); fp != "" {
				st.tls.fingerprint = fp
			}
		}
		if e := tlsMap.sub("ech"); e != nil && (e.flag("enabled") || e.flag("true")) {
			st.tls.ech = e.str("config", "ech_config", "ech-config", "echConfigList")
			if st.tls.ech == "" {
				return nil, errEchNoConfig()
			}
		}
	}
	if v := s.str(keysServerName...); v != "" && st.tls.serverName == "" {
		st.tls.serverName = v
	}
	if s.flag(keysAllowInsecure...) {
		st.tls.insecure = true
	}
	if v := s.list(keysALPN...); len(v) > 0 && len(st.tls.alpn) == 0 {
		st.tls.alpn = v
	}
	if v := s.str(keysFingerprint...); v != "" && st.tls.fingerprint == "" {
		st.tls.fingerprint = v
	}
	if v := s.str("ech_config", "ech-config", "echConfigList", "ech_opts", "ech-opts", "echOpts"); v != "" {
		st.tls.ech = v
	}
	if v := s.str(keysPinnedCert...); v != "" {
		pin, err := parsePin(v)
		if err != nil {
			return nil, err
		}
		st.tls.pinned = pin
	}
	if st.tls.fingerprint != "" && st.security == "none" {
		return nil, errors.New("fingerprint is for TLS, and this outbound has none: set tls=true (or security to tls), or remove the fingerprint")
	}
	if st.tls.ech != "" {
		if st.security != "tls" {
			return nil, errors.New("ECH is for TLS, and this outbound is REALITY or has no TLS: remove the ECH config, or set security to tls")
		}
	}

	// REALITY.
	if rs := s.sub("realitySettings", "reality_settings", "reality"); rs != nil {
		st.reality.publicKey = rs.str("public_key", "publicKey", "public-key")
		st.reality.shortID = rs.str("short_id", "shortId", "short-id")
		st.reality.serverName = rs.str(keysServerName...)
		st.reality.fingerprint = rs.str(keysFingerprint...)
	}
	if v := s.str("reality_public_key", "realityPublicKey"); v != "" {
		st.reality.publicKey = v
	}
	if v := s.str("public_key", "publicKey", "public-key"); v != "" && st.reality.publicKey == "" && st.security == "reality" {
		st.reality.publicKey = v
	}
	if v := s.str("reality_short_id", "realityShortID", "short_id", "shortId"); v != "" && st.reality.shortID == "" {
		st.reality.shortID = v
	}
	if st.reality.serverName == "" {
		st.reality.serverName = st.tls.serverName
	}
	if st.security == "reality" {
		if st.reality.serverName == "" {
			return nil, errors.New("REALITY needs sni: one of the server names (serverNames) the far end's REALITY is configured with")
		}
		if err := checkReality(st.reality); err != nil {
			return nil, err
		}
	} else if st.reality.publicKey != "" {
		return nil, fmt.Errorf("a REALITY public key is given but security is %q; set security to reality, or remove the key", st.security)
	}

	// Per-transport settings.
	if m := s.sub("wsSettings", "ws_settings", "ws"); m != nil {
		st.ws.path = m.str("path")
		st.ws.host = m.str("host", "Host")
		st.ws.headers = m.headers("headers")
		st.ws.maxEarlyData = m.int("maxEarlyData", "max_early_data")
		st.ws.earlyDataHeaderName = m.str("earlyDataHeaderName", "early_data_header_name")
	}
	if transport != nil {
		if st.ws.path == "" {
			st.ws.path = transport.str("path")
		}
		if st.ws.host == "" {
			st.ws.host = transport.str("host", "Host")
		}
		if len(st.ws.headers) == 0 {
			st.ws.headers = transport.headers("headers")
		}
		if st.grpc.serviceName == "" {
			st.grpc.serviceName = transport.str("service_name", "serviceName")
		}
	}
	if m := s.sub("h2Settings", "h2_settings", "httpSettings", "http_settings"); m != nil {
		st.h2.path = m.str("path")
		st.h2.host = m.str("host", "Host")
		st.h2.headers = m.headers("headers")
	}
	if m := s.sub("grpcSettings", "grpc_settings", "grpc"); m != nil {
		st.grpc.serviceName = m.str("serviceName", "service_name")
		st.grpc.multiMode = m.flag("multiMode", "multi_mode")
	}
	if m := s.sub("xhttpSettings", "xhttp_settings", "splithttpSettings", "splithttp_settings", "xhttp"); m != nil {
		st.xhttp = opt.Opt(m)
	}
	if m := s.sub("tcpSettings", "tcp_settings", "rawSettings", "raw_settings"); m != nil {
		if h := m.sub("header"); h != nil {
			st.tcp.header = h.str("type")
		} else {
			st.tcp.header = m.str("headerType", "header_type")
		}
	}
	if v := s.str("headerType", "header_type"); v != "" && st.tcp.header == "" {
		st.tcp.header = v
	}
	switch st.tcp.header {
	case "", "none":
	default:
		return nil, fmt.Errorf("TCP header obfuscation %q is not supported for outbounds; set the header type to none", st.tcp.header)
	}

	// XHTTP mode outside xhttp transport is a configuration mistake.
	if st.network != "xhttp" {
		if m := strOrEmpty(st.xhttp.Str("mode")); m != "" && m != "auto" {
			return nil, fmt.Errorf("mode %q is an XHTTP setting, and this outbound's network is %s; remove it", m, st.network)
		}
	} else if m := strOrEmpty(st.xhttp.Str("mode")); m != "" {
		switch m {
		case "auto", "stream-one", "stream-up", "packet-up":
		default:
			return nil, fmt.Errorf("mode %q is an XHTTP setting, and this outbound's network is %s; remove it", m, st.network)
		}
	}

	if st.network == "h2" && st.security == "none" {
		return nil, errors.New(`sing-box's "http" transport without TLS is HTTP/1.1, which is not supported for outbounds; set tls=true (or security to tls)`)
	}
	if st.network == "grpc" {
		if st.grpc.multiMode {
			return nil, errors.New("gRPC multiMode is not supported for outbounds; turn it off (servers take the plain mode)")
		}
		if m := s.str("mode"); m != "" && m != "gun" && m != "multi" {
			return nil, fmt.Errorf("gRPC mode %q is not supported for outbounds; use gun, which every server takes", m)
		}
	}

	// UDP carriage.
	if v, ok := s.get(keysUDPOverTCP...); ok {
		switch t := v.(type) {
		case bool:
			if t {
				st.udpOverTCP = 2
			}
		default:
			n := s.int(keysUDPOverTCP...)
			switch n {
			case 0:
			case 1:
				return nil, errors.New("udp_over_tcp version 1 is not supported; use version 2 (the default of every current client)")
			default:
				st.udpOverTCP = 2
			}
		}
	}
	st.strict = s.flag(keysStrict...)
	return st, nil
}

func strOrEmpty(s string) string { return strings.TrimSpace(s) }

// checkReality is outbound.checkReality @0xb7d1e0: it validates the client's
// REALITY parameters, not the handshake (which lives in ctransport).
func checkReality(r realitySettings) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(r.publicKey))
	if err != nil || len(raw) != 32 {
		return errors.New("the REALITY public_key is not a public key: it must be 32 bytes in base64 (43 characters)")
	}
	if len(r.shortID) > 16 {
		return fmt.Errorf("the REALITY short_id %q must be up to 16 hex digits, one of the far end's shortIDs", r.shortID)
	}
	if r.shortID != "" {
		for _, c := range r.shortID {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return fmt.Errorf("the REALITY short_id %q must be up to 16 hex digits, one of the far end's shortIDs", r.shortID)
			}
		}
	}
	return nil
}

// parsePin accepts a hex SHA-256 digest, with optional colons.
func parsePin(v string) ([]byte, error) {
	clean := strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(v))
	if len(clean) != 64 {
		return nil, fmt.Errorf("pinned_cert_sha256 %q must be a SHA-256 digest in hex (64 characters)", v)
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi := hexVal(clean[2*i])
		lo := hexVal(clean[2*i+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("pinned_cert_sha256 %q must be a SHA-256 digest in hex (64 characters)", v)
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// readPlugin reads a Shadowsocks SIP003 plugin block (outbound.readPlugin
// @0xb7da60). Only the three plugins the sample names are accepted
// (notes/rev-ops.md §2.4).
func readPlugin(s settings, o opt.Opt, conf *stream) (*pluginSettings, error) {
	name := strings.ToLower(strings.TrimSpace(s.str(keysPlugin...)))
	if name == "" {
		return nil, nil
	}
	if conf != nil && conf.network != "tcp" {
		return nil, fmt.Errorf("a shadowsocks outbound takes a plugin or a transport, not both: remove plugin=%s, or remove the transport", name)
	}
	opts := pluginOptions(s)
	switch name {
	case "obfs", "simple-obfs":
		mode := strings.ToLower(opts["obfs"])
		if mode == "" {
			mode = strings.ToLower(opts["mode"])
		}
		if mode == "" {
			mode = "http"
		}
		if mode != "http" && mode != "tls" {
			return nil, fmt.Errorf("obfs mode %q is not supported; set obfs=http or obfs=tls in plugin_opts", mode)
		}
		return &pluginSettings{name: "obfs", opts: opts}, nil
	case "v2ray-plugin":
		mode := strings.ToLower(opts["mode"])
		if mode == "" {
			mode = "websocket"
		}
		if mode != "websocket" {
			return nil, fmt.Errorf("v2ray-plugin mode %q is not supported; only websocket is", mode)
		}
		return &pluginSettings{name: "v2ray-plugin", opts: opts}, nil
	case "shadow-tls":
		if opts["host"] == "" || opts["password"] == "" {
			return nil, errors.New("shadow-tls needs host= and password= in plugin_opts: host is the site the server pretends to be")
		}
		switch opts["version"] {
		case "", "3", "2":
		default:
			return nil, fmt.Errorf("shadow-tls version %q is not supported; set version=3, or version=2 for an old server", opts["version"])
		}
		return &pluginSettings{name: "shadow-tls", opts: opts}, nil
	}
	return nil, fmt.Errorf("shadowsocks plugin %q is not supported for outbounds; obfs, v2ray-plugin and shadow-tls are", name)
}

// pluginOptions normalizes "a=b;c=d" / JSON object / separate pluginOpts map
// into a flat map (outbound.pluginOptions @0xb7f880). Hyphen and underscore
// spellings are both stored.
func pluginOptions(s settings) map[string]string {
	out := map[string]string{}
	add := func(k, v string) {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			return
		}
		out[k] = strings.TrimSpace(v)
		out[strings.ReplaceAll(k, "_", "-")] = strings.TrimSpace(v)
	}
	if v, ok := s.get(keysPluginOpts...); ok {
		switch t := v.(type) {
		case string:
			for _, part := range strings.FieldsFunc(t, func(r rune) bool { return r == ';' || r == ',' || r == '&' }) {
				if i := strings.IndexByte(part, '='); i > 0 {
					add(part[:i], part[i+1:])
				}
			}
		case map[string]any:
			for k, val := range t {
				add(k, toStr(val))
			}
		case map[string]string:
			for k, val := range t {
				add(k, val)
			}
		}
	}
	return out
}
