package outbound

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
)

// settings is the typed reader over opt.Opt used by outbound.New and
// readStream. The sample has the same family: outbound.settings.str @0xb74c60,
// .flag @0xb74d80, .list @0xb785c0, .headers @0xb78a60 (notes/funcs/outbound.txt),
// plus outbound.kebab @0xb7d460 / kebabValue @0xb7d7a0, which normalize
// foo_bar <-> foo-bar because the panels mix Clash/kebab, Xray/camel and
// sing-box/snake spellings (notes/rev-ops.md §2.2).
type settings opt.Opt

// key candidates. Each reader accepts every spelling a panel may emit; the
// first present key wins (opt.Opt.Str semantics, REPORT.md §17.2.3).
var (
	keysAddress       = []string{"address", "server", "server_address", "serverAddress", "addr", "host", "remote"}
	keysPort          = []string{"port", "server_port", "serverPort", "remote_port", "remotePort"}
	keysUUID          = []string{"uuid", "id", "user_id", "userID"}
	keysPassword      = []string{"password", "passwd", "secret"}
	keysMethod        = []string{"method", "cipher", "encrypt_method", "encryptMethod"}
	keysSecurity      = []string{"security"}
	keysNetwork       = []string{"network", "net", "transport", "type"}
	keysFlow          = []string{"flow"}
	keysAlterID       = []string{"alterId", "alter_id", "aid"}
	keysUser          = []string{"username", "user"}
	keysTLS           = []string{"tls"}
	keysServerName    = []string{"server_name", "serverName", "servername", "sni", "peer"}
	keysAllowInsecure = []string{"allowInsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify", "insecure", "insecure_skip_verify"}
	keysALPN          = []string{"alpn"}
	keysFingerprint   = []string{"client-fingerprint", "client_fingerprint", "fingerprint", "utls", "clientFingerprint"}
	keysPinnedCert    = []string{"pinned_cert_sha256", "pinnedPeerCertSha256", "cert_sha256", "certificate_sha256", "pinnedCertSha256"}
	keysPlugin        = []string{"plugin"}
	keysPluginOpts    = []string{"plugin-opts", "pluginOpts", "plugin_opts"}
	keysUDPOverTCP    = []string{"udp_over_tcp", "udp-over-tcp", "udpOverTCP"}
	keysStrict        = []string{"strict", "strict_mode", "strictMode"}
	keysServerKey     = []string{"server_key", "serverKey"}
	keysPSK           = []string{"preshared_key", "presharedKey", "pre_shared_key", "preSharedKey"}
)

// kebab converts foo_bar / fooBar style identifiers to foo-bar.
func kebab(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == '_':
			b.WriteByte('-')
		case r >= 'A' && r <= 'Z':
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// snake converts foo-bar / fooBar to foo_bar.
func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == '-':
			b.WriteByte('_')
		case r >= 'A' && r <= 'Z':
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// get returns the first present key, trying the literal spelling and its
// kebab/snake normalizations (kebabValue).
func (s settings) get(keys ...string) (any, bool) {
	for _, k := range keys {
		for _, cand := range [...]string{k, kebab(k), snake(k)} {
			if v, ok := s[cand]; ok && v != nil {
				return v, true
			}
		}
	}
	return nil, false
}

func (s settings) str(keys ...string) string {
	v, ok := s.get(keys...)
	if !ok {
		return ""
	}
	return toStr(v)
}

func (s settings) flag(keys ...string) bool {
	v, ok := s.get(keys...)
	if !ok {
		return false
	}
	return toBool(v)
}

func (s settings) int(keys ...string) int {
	v, ok := s.get(keys...)
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(toStr(v)))
	return n
}

// list reads a string list from either a JSON array, a []string or a
// comma/space separated string.
func (s settings) list(keys ...string) []string {
	v, ok := s.get(keys...)
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return append([]string(nil), t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, toStr(e))
		}
		return out
	case string:
		var out []string
		for _, f := range strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			if f = strings.TrimSpace(f); f != "" {
				out = append(out, f)
			}
		}
		return out
	}
	return nil
}

// headers reads an HTTP header table from a JSON object or a list of
// "Name: value" strings (settings.headers).
func (s settings) headers(keys ...string) map[string]string {
	v, ok := s.get(keys...)
	if !ok {
		return nil
	}
	out := map[string]string{}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			out[k] = toStr(val)
		}
	case map[string]string:
		for k, val := range t {
			out[k] = val
		}
	case []any:
		for _, e := range t {
			addHeaderLine(out, toStr(e))
		}
	case []string:
		for _, e := range t {
			addHeaderLine(out, e)
		}
	case string:
		for _, line := range strings.Split(t, "\n") {
			addHeaderLine(out, line)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func addHeaderLine(dst map[string]string, line string) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return
	}
	dst[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
}

// sub returns a nested object.
func (s settings) sub(keys ...string) settings {
	if v, ok := s.get(keys...); ok {
		if m, ok := v.(map[string]any); ok {
			return settings(m)
		}
	}
	return nil
}

// toStr renders a JSON scalar the way opt.Opt.Str does.
func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "on", "enabled":
			return true
		}
	case int:
		return t != 0
	case float64:
		return t != 0
	}
	return false
}
