// Package txnode is TX-Node's native data plane adapter: it translates the
// panel-facing model.NodeSpec onto internal/dataplane and implements
// kernel.Kernel.
//
// The package owns no panel, certificate, authorization or reporting policy;
// those stay in TX-Node. It only decides how a node is built, bound, metered and
// admitted.
package txnode

import (
	"context"
	"log/slog"
	"time"

	"github.com/ANRCM0/TX-Node/internal/nlog"
)

// RuntimeConfig is the behaviour knobs the data plane needs. They are process
// configuration, not panel configuration; defaults keep the historical node
// behaviour (no private-address blocking, no connection cap, brute-force guard
// off).
type RuntimeConfig struct {
	// TrustedProxies is core.ParseTrust's value ("private,cloudflare" default,
	// empty string installs that default).
	TrustedProxies string
	// ProxyProtocol / RequireProxyProtocol mirror the panel's proxy protocol
	// flags; per-node values override them.
	ProxyProtocol        bool
	RequireProxyProtocol bool
	// AutoOutIP exposes the node-side egress address (auto_out_ip).
	AutoOutIP bool
	// MaxFresh bounds unauthenticated concurrent connections. 0 uses 4096.
	MaxFresh int
	// DrainTimeout is how long Stop waits for live sessions.
	DrainTimeout time.Duration
	// InvalidAccess* is the brute-force brake (disabled by default).
	InvalidAccessEnable    bool
	InvalidAccessCount     int
	InvalidAccessDuration  int
	InvalidAccessForbidden int
	// Timeouts. Zero keeps the data plane defaults.
	HandshakeTimeout time.Duration
	TCPTimeout       time.Duration
	UDPTimeout       time.Duration
	// ForbiddenPrivateIP / ForbiddenBitTorrent install the router's default
	// blocks. Both default to false so a panel-driven node keeps working.
	ForbiddenPrivateIP  bool
	ForbiddenBitTorrent bool
	// ForbiddenPorts is a comma separated port specification blocked by a
	// synthetic "forbidden_ports" rule.
	ForbiddenPorts string
	// GeoDataDir holds geosite.dat / geoip.dat. Empty disables geo terms.
	GeoDataDir string
	// DNSStrategy / DNSCacheTTL feed core.NewResolver for "dns" actions.
	DNSStrategy string
	DNSCacheTTL time.Duration
	// StrictALPN rejects TLS clients that do not offer the expected ALPN.
	StrictALPN bool
	// Admission ceilings. Zero keeps the data plane defaults (unlimited).
	UserTCPLimit     int
	DeviceLimit      int
	DeviceIPv6Prefix int
	// Logger receives data plane logs. nil forwards to nlog.
	Logger *slog.Logger
}

func (r RuntimeConfig) normalized() RuntimeConfig {
	if r.MaxFresh <= 0 {
		r.MaxFresh = 4096
	}
	if r.HandshakeTimeout <= 0 {
		r.HandshakeTimeout = 10 * time.Second
	}
	if r.DrainTimeout <= 0 {
		r.DrainTimeout = 5 * time.Second
	}
	if r.DNSStrategy == "" {
		r.DNSStrategy = "auto"
	}
	return r
}

func (r RuntimeConfig) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.New(&nodeLogHandler{})
}

// nodeLogHandler forwards slog records to TX-Node's nlog so the native data
// plane shares the process log format instead of writing a second stream.
type nodeLogHandler struct {
	attrs []slog.Attr
}

func (h *nodeLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *nodeLogHandler) Handle(_ context.Context, rec slog.Record) error {
	args := make([]any, 0, len(h.attrs)*2+rec.NumAttrs()*2)
	for _, a := range h.attrs {
		args = append(args, a.Key, a.Value.Any())
	}
	rec.Attrs(func(a slog.Attr) bool {
		args = append(args, a.Key, a.Value.Any())
		return true
	})
	nl := nlog.Core()
	switch {
	case rec.Level >= slog.LevelError:
		nl.Error(rec.Message, args...)
	case rec.Level >= slog.LevelWarn:
		nl.Warn(rec.Message, args...)
	case rec.Level >= slog.LevelInfo:
		nl.Info(rec.Message, args...)
	default:
		nl.Debug(rec.Message, args...)
	}
	return nil
}

func (h *nodeLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &nodeLogHandler{attrs: make([]slog.Attr, 0, len(h.attrs)+len(attrs))}
	next.attrs = append(next.attrs, h.attrs...)
	next.attrs = append(next.attrs, attrs...)
	return next
}

func (h *nodeLogHandler) WithGroup(string) slog.Handler { return h }
