// Package ctransport is the client side of kaze's stream transports. It
// mirrors ctransport.(*Transport).Dial @0xb4fe40 (notes/rev-transport.md
// §1.1):
//
//	if xhttp != nil   -> xhttp dial
//	if muxPool != nil -> mux pool dial
//	c = secure(t)     (TLS / REALITY, ALPN per network)
//	switch network { "http": http obfs; "ws": ws or httpupgrade; default: raw }
package ctransport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/mux"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Transport is one client configuration assembled from the outbound's stream
// settings (opt.Opt). The field names follow the sample's struct: network,
// security, tlsSettings, wsSettings, grpcSettings, xhttpSettings,
// realitySettings and the mux pool.
type Transport struct {
	Network  string
	Security string // none, tls, reality
	Settings opt.Opt
	TLS      opt.Opt
	Reality  opt.Opt
	WS       opt.Opt
	GRPC     opt.Opt
	XHTTP    opt.Opt

	Dialer  *net.Dialer
	MuxPool *mux.Pool
	Logger  *slog.Logger

	dest socks.Addr
	sni  string

	httpUpgradeMode bool
}

// DialTCP connects to dest and applies the transport named by network.
//
// Evidence for the option keys: REPORT.md §7.1-§7.4 and notes/rev-transport.md
// §1-§3 (security, tlsSettings, realitySettings, wsSettings, grpcSettings,
// xhttpSettings, client-fingerprint).
func DialTCP(ctx context.Context, network string, o opt.Opt, dest socks.Addr) (net.Conn, error) {
	t, err := FromOpt(network, o)
	if err != nil {
		return nil, err
	}
	return t.Dial(ctx, dest)
}

// FromOpt builds the Transport from the merged stream settings.
func FromOpt(network string, o opt.Opt) (*Transport, error) {
	if o == nil {
		o = opt.Opt{}
	}
	t := &Transport{
		Network:  strings.ToLower(strings.TrimSpace(firstNonEmpty(network, o.Str("network")))),
		Security: strings.ToLower(strings.TrimSpace(o.Str("security"))),
		Settings: o,
		TLS:      subOpt(o, "tlsSettings", "tls_settings"),
		Reality:  subOpt(o, "realitySettings", "reality_settings", "reality-opts", "reality_opts"),
		WS:       subOpt(o, "wsSettings", "ws_settings"),
		GRPC:     subOpt(o, "grpcSettings", "grpc_settings"),
		XHTTP:    subOpt(o, "xhttpSettings", "xhttp_settings", "splithttpSettings"),
		Logger:   slog.Default(),
	}
	if t.Network == "" {
		t.Network = "tcp"
	}
	if t.Security == "" {
		if o.Bool("tls") {
			if len(t.Reality) > 0 {
				t.Security = "reality"
			} else {
				t.Security = "tls"
			}
		} else {
			t.Security = "none"
		}
	}
	switch t.Security {
	case "none", "tls", "reality":
	default:
		return nil, fmt.Errorf("security %q is not supported for outbounds; use none, tls or reality", t.Security)
	}
	if t.Network == "httpupgrade" {
		t.Network = "ws"
		t.httpUpgradeMode = true
	}
	// Mux pool: REPORT.md §7.1/§7.6 (muxPool_dial 0xb54880, (*muxPool).conn
	// 0xb53440). The client asks for it with mux.enabled / muxEnabled.
	if m := subOpt(o, "mux", "muxSettings", "mux_settings"); len(m) > 0 {
		if m.Bool("enabled") {
			kind := byte(0)
			if strings.EqualFold(m.Str("protocol"), "yamux") {
				kind = 1
			}
			t.MuxPool = mux.NewPool(kind)
			if b := m.Map("brutal"); b != nil && b.Bool("enabled") {
				if mbps := b.Int("down_mbps", "receive_mbps", "rx"); mbps > 0 {
					t.MuxPool.Brutal = uint64(mbps) * 1_000_000 / 8
				}
			}
		}
	} else if o.Bool("mux.enabled", "muxEnabled") {
		t.MuxPool = mux.NewPool(0)
	}
	return t, nil
}

func (t *Transport) httpUpgrade() bool {
	return t.httpUpgradeMode || t.Settings.Bool("httpupgrade")
}

// Dial opens the TCP connection and applies TLS/REALITY and the transport.
func (t *Transport) Dial(ctx context.Context, dest socks.Addr) (net.Conn, error) {
	t.dest = dest
	t.sni = t.serverName(dest)
	dial := t.dialTransport
	if t.MuxPool != nil && t.Network != "xhttp" {
		return t.MuxPool.Dial(ctx, dest, func(ctx context.Context) (net.Conn, error) {
			return dial(ctx, dest)
		})
	}
	conn, err := dial(ctx, dest)
	if err != nil {
		return nil, err
	}
	switch t.Network {
	case "tcp", "":
		return conn, nil
	case "http":
		return t.dialHTTPObfs(ctx, conn)
	case "ws":
		if t.httpUpgrade() {
			return t.dialHTTPUpgrade(ctx, conn)
		}
		return t.dialWebSocket(ctx, conn)
	case "grpc":
		return t.dialGRPC(ctx, conn)
	case "h2":
		return t.dialH2(ctx, conn)
	case "xhttp":
		return t.dialXHTTP(ctx, conn)
	}
	conn.Close()
	return nil, fmt.Errorf("transport %q is not supported for %s outbounds (TCP only); ws, grpc and the like work with trojan, vless, vmess and shadowsocks", t.Network, t.Network)
}

// dialTransport opens the TCP connection and applies TLS/REALITY without the
// stream transport (the mux pool and the network switch use it).
func (t *Transport) dialTransport(ctx context.Context, dest socks.Addr) (net.Conn, error) {
	d := t.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: 10 * time.Second}
	}
	raw, err := d.DialContext(ctx, "tcp", dest.String())
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	} else {
		_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	}
	conn, err := t.secure(ctx, raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// secure applies TLS or REALITY. Evidence: (*Transport).secure 0xb4ffe0.
func (t *Transport) secure(ctx context.Context, c net.Conn) (net.Conn, error) {
	switch t.Security {
	case "none":
		return c, nil
	case "tls":
		return t.tlsClient(ctx, c)
	case "reality":
		return t.realityClient(ctx, c)
	}
	return nil, fmt.Errorf("security %q is not supported for outbounds; use none, tls or reality", t.Security)
}

// clientALPN is the client-side ALPN decision of (*Transport).secure
// (notes/rev-transport.md §1.2): h2/grpc -> h2; http/ws -> http/1.1; xhttp ->
// h2 without a mux pool, http/1.1 with one; otherwise the configured list.
func (t *Transport) clientALPN() []string {
	switch t.Network {
	case "h2", "grpc":
		return []string{"h2"}
	case "http", "ws":
		return []string{"http/1.1"}
	case "xhttp":
		if t.MuxPool == nil {
			return []string{"h2"}
		}
		return []string{"http/1.1"}
	}
	if a := alpnList(t.Settings, "alpn"); len(a) > 0 {
		return a
	}
	if a := alpnList(t.TLS, "alpn"); len(a) > 0 {
		return a
	}
	return nil
}

// alpnList accepts both the comma/space separated form and the []any form a
// panel JSON leaves in the settings map.
func alpnList(o opt.Opt, key string) []string {
	v, ok := o[key]
	if !ok || v == nil {
		return nil
	}
	switch a := v.(type) {
	case []string:
		return a
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			if s := strings.TrimSpace(fmt.Sprint(e)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return splitList(a)
	}
	return nil
}

func (t *Transport) alpnProtocol() string {
	if a := t.clientALPN(); len(a) > 0 {
		return a[0]
	}
	return ""
}

func (t *Transport) useTLS() bool { return t.Security == "tls" || t.Security == "reality" }

func (t *Transport) serverName(dest socks.Addr) string {
	if v := firstNonEmpty(
		t.TLS.Str("serverName", "server_name", "sni"),
		t.Reality.Str("serverName", "server_name", "sni"),
		t.Settings.Str("serverName", "server_name", "sni"),
	); v != "" {
		return v
	}
	return dest.Host
}

func (t *Transport) hostHeader(dest socks.Addr) string {
	transport := subOpt(t.Settings, "transport", "transportSettings", "transport_settings")
	if v := firstNonEmpty(t.WS.Str("headers.Host", "host"), t.Settings.Str("host"), t.GRPC.Str("host"), transport.Str("host", "Host")); v != "" {
		return v
	}
	if t.useTLS() || t.sni != "" {
		return t.sni
	}
	return dest.String()
}

func (t *Transport) wsPath() string {
	transport := subOpt(t.Settings, "transport", "transportSettings", "transport_settings")
	if v := firstNonEmpty(t.WS.Str("path"), t.Settings.Str("path"), transport.Str("path")); v != "" {
		return v
	}
	return "/"
}

// grpcServiceName is xray's grpcSettings.serviceName, or sing-box's
// transport.service_name.
func (t *Transport) grpcServiceName() string {
	transport := subOpt(t.Settings, "transport", "transportSettings", "transport_settings")
	return firstNonEmpty(t.GRPC.Str("serviceName", "service_name"), transport.Str("service_name", "serviceName"))
}

func (t *Transport) insecure() bool {
	return t.TLS.Bool("allowInsecure", "allow_insecure", "skip_cert_verify", "skip-cert-verify", "insecure") ||
		t.Reality.Bool("allowInsecure") ||
		t.Settings.Bool("allowInsecure", "allow_insecure", "skip-cert-verify", "insecure")
}

// subOpt returns a nested settings map. It accepts the JSON lowerCamel and the
// INI/panel snake spellings.
func subOpt(o opt.Opt, keys ...string) opt.Opt {
	for _, k := range keys {
		if m := o.Map(k); m != nil {
			return m
		}
	}
	return opt.Opt{}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// decodeHexFingerprint parses the "pinned_cert_sha256" value (hex, optional
// colons).
func decodeHexFingerprint(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s)%2 != 0 || len(s) == 0 {
		return nil, errors.New("pinned_cert_sha256 must be a hex fingerprint")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var b int
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &b); err != nil {
			return nil, err
		}
		out[i] = byte(b)
	}
	return out, nil
}

// handshakeTimeout mirrors the node's transport handshake deadline.
const handshakeTimeout = 15 * time.Second

// socksReader returns a destination address for dialing helpers.
func (t *Transport) socksAddr() socks.Addr { return t.dest }
