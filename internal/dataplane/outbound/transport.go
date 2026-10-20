package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// DialTransport is the seam to internal/ctransport, whose client dialer has the
// signature in REPLICATION.md §3.3:
//
//	ctransport.DialTCP(ctx, network string, o opt.Opt, dest socks.Addr) (net.Conn, error)
//
// node assigns it once during assembly:
//
//	outbound.DialTransport = ctransport.DialTCP
//
// Until then the built-in fallback below handles plain TCP and TLS; REALITY,
// websocket, h2, gRPC, HTTPUpgrade and XHTTP need the real transport and fail
// with an explicit message instead of silently downgrading.
var DialTransport func(ctx context.Context, network string, o opt.Opt, dest socks.Addr) (net.Conn, error)

// SetTransport installs the shared client transport (same effect as assigning
// DialTransport; exported for tests and for node's dependency injection).
func SetTransport(fn func(ctx context.Context, network string, o opt.Opt, dest socks.Addr) (net.Conn, error)) {
	DialTransport = fn
}

// openStream dials the proxy server and applies the stream settings.
func (p *Proxy) openStream(ctx context.Context) (net.Conn, error) {
	s := p.stream
	if s == nil {
		return p.dialServer(ctx)
	}
	// SIP003 plugins wrap (or replace) the stream transport themselves.
	if s.plugin != nil {
		return p.pluginStream(ctx, s)
	}
	if DialTransport != nil {
		return DialTransport(ctx, s.network, s.raw, p.addr)
	}
	return p.builtinStream(ctx, s)
}

// builtinStream is the fallback used when ctransport is not wired: bare TCP and
// TLS (with the pinned-certificate and ALPN options), plus the SIP003 obfs=http
// header. Everything else needs ctransport.
func (p *Proxy) builtinStream(ctx context.Context, s *stream) (net.Conn, error) {
	if s.plugin != nil {
		return p.pluginStream(ctx, s)
	}
	switch s.network {
	case "tcp", "":
	case "ws", "httpupgrade", "h2", "grpc", "xhttp":
		return nil, fmt.Errorf("transport %q needs the transport dialer: wire outbound.DialTransport", s.network)
	default:
		return nil, fmt.Errorf("transport %q needs the transport dialer: wire outbound.DialTransport", s.network)
	}
	c, err := p.dialServer(ctx)
	if err != nil {
		return nil, err
	}
	if s.security == "reality" {
		c.Close()
		return nil, errors.New("REALITY needs the transport dialer: wire outbound.DialTransport")
	}
	if s.security != "tls" {
		return c, nil
	}
	tc, err := clientTLS(ctx, c, s, p.addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

// clientTLS performs the fallback TLS handshake. uTLS fingerprints are applied
// by ctransport (REPORT.md §7.4); here client-fingerprint is only carried in
// the config so a wired transport sees the same settings.
func clientTLS(ctx context.Context, c net.Conn, s *stream, server socks.Addr) (*tls.Conn, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: s.tls.insecure, //nolint:gosec // allowInsecure is the panel's explicit choice
		ServerName:         tlsServerName(s, server),
		NextProtos:         alpnFor(s),
		MinVersion:         tls.VersionTLS12,
	}
	if s.security == "tls" && len(cfg.NextProtos) == 0 && (s.network == "h2" || s.network == "grpc") {
		cfg.NextProtos = []string{"h2"}
	}
	raw := c
	tc := tls.Client(raw, cfg)
	if deadline, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(deadline)
	} else {
		_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	if len(s.tls.pinned) > 0 {
		if err := checkPinned(tc, s.tls.pinned); err != nil {
			return nil, err
		}
	}
	return tc, nil
}

// tlsServerName picks the SNI: server_name/serverName from the settings, else
// the server's domain (never an IP literal, which TLS forbids as SNI).
func tlsServerName(s *stream, server socks.Addr) string {
	if s.tls.serverName != "" {
		return s.tls.serverName
	}
	if s.security == "reality" {
		return s.reality.serverName
	}
	if server.IsDomain() {
		return server.Host
	}
	return ""
}

func alpnFor(s *stream) []string {
	if len(s.tls.alpn) > 0 {
		return s.tls.alpn
	}
	switch s.network {
	case "h2", "grpc":
		return []string{"h2"}
	case "ws", "httpupgrade", "xhttp":
		return []string{"http/1.1"}
	}
	return nil
}

// checkPinned verifies the leaf certificate's SHA-256 against
// pinned_cert_sha256 / pinnedPeerCertSha256.
func checkPinned(c *tls.Conn, want []byte) error {
	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("the server sent no certificate to pin")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return fmt.Errorf("the server certificate does not match pinned_cert_sha256 (got %x)", sum)
	}
	return nil
}

// pluginStream applies a SIP003 plugin to the transport. obfs=http is the
// headerConn decorator (REPORT.md §9); v2ray-plugin is a websocket upgrade;
// shadow-tls borrows a real site's TLS handshake and lives in ctransport
// (notes/rev-transport.md), so it needs the dialer.
func (p *Proxy) pluginStream(ctx context.Context, s *stream) (net.Conn, error) {
	pl := s.plugin
	switch pl.name {
	case "obfs":
		if strings.EqualFold(pl.opts["obfs"], "tls") {
			return nil, errors.New("obfs=tls needs the transport dialer: wire outbound.DialTransport")
		}
		c, err := p.dialServer(ctx)
		if err != nil {
			return nil, err
		}
		host := pl.opts["obfs-host"]
		if host == "" {
			host = pl.opts["obfs_host"]
		}
		if host == "" {
			host = "cloudfront.net"
		}
		return newHeaderConn(c, host), nil
	case "v2ray-plugin":
		host := pl.opts["host"]
		path := pl.opts["path"]
		if path == "" {
			path = "/"
		}
		tlsOn := strings.EqualFold(pl.opts["tls"], "true") || pl.opts["tls"] == "1"
		c, err := p.dialServer(ctx)
		if err != nil {
			return nil, err
		}
		if tlsOn {
			tc, err := clientTLS(ctx, c, s, p.addr)
			if err != nil {
				c.Close()
				return nil, err
			}
			c = tc
		}
		ws, err := wsClient(ctx, c, path, host, nil, s.tls.alpn)
		if err != nil {
			c.Close()
			return nil, err
		}
		return ws, nil
	case "shadow-tls":
		if ShadowTLSDial == nil {
			return nil, errors.New("shadow-tls needs the transport dialer: wire outbound.ShadowTLSDial")
		}
		host := pl.opts["host"]
		password := pl.opts["password"]
		if host == "" || password == "" {
			return nil, errors.New("shadow-tls needs host= and password= in the plugin options")
		}
		return ShadowTLSDial(ctx, "tcp", p.addr.String(), host, password)
	}
	return p.dialServer(ctx)
}
