// Package transport is the server side of kaze's stream transports: TLS /
// REALITY wrapping plus the ws, httpupgrade, grpc, h2 and xhttp handshakes.
//
// Evidence: REPORT.md §7 (dispatch tree, transport matrix), §7.3 (XHTTP),
// §7.5 (REALITY), §7.9 (decoy) and notes/rev-transport.md §1, §3, §4, §7.
// The sample builds every variant from one config struct
// (transport.(*Config) in the binary: transport.go, http.go, xhttp.go,
// decoy.go, fallback.go, reality.go, reality_mirror.go, reality_tls13.go,
// reality_limit.go, shadowtls.go, naive.go, obfs.go -- file list recovered
// from the pclntab in kazecore/bin/kaze-linux-amd64).
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// Network names accepted by Inbound. The sample rejects anything else with
// "network %q is not supported (tcp, ws, http, h2, grpc, xhttp)" (string
// table; notes/rev-transport.md §1.1) and the node-side rebuild reports
// "transport %q is not supported; use TCP, WebSocket, HTTPUpgrade, gRPC, H2 or
// XHTTP".
const (
	NetworkTCP         = "tcp"
	NetworkWS          = "ws"
	NetworkHTTPUpgrade = "httpupgrade"
	NetworkGRPC        = "grpc"
	NetworkH2          = "h2"
	NetworkXHTTP       = "xhttp"
	NetworkHTTP        = "http" // simple-obfs style HTTP/1.1 obfs (client only)
)

// Inbound is one server-side transport configuration. It mirrors the fields
// the node assembles in apply.go (network/path/host/service name, the TLS
// mode, the REALITY wrapper and the xhttp option map).
type Inbound struct {
	Network     string // tcp, ws, httpupgrade, grpc, h2, xhttp
	Path        string
	Host        string
	ServiceName string
	TLS         int // 0 none, 1 tls, 2 reality
	TLSConfig   *tls.Config
	Reality     *Reality
	StrictALPN  bool
	XHTTP       map[string]any
	Logger      *slog.Logger

	// Relay hands a session produced by a multiplexed transport (h2, gRPC,
	// XHTTP) back to the node's relay. Nil falls back to ServeSession.
	Relay func(ctx context.Context, s *core.Session) error
}

func (i *Inbound) logger() *slog.Logger {
	if i.Logger != nil {
		return i.Logger
	}
	return slog.Default()
}

// WrapListener applies TLS or REALITY to a plain listener. TLS == 0 returns
// the listener unchanged (REPORT.md §7.1: the plain stream is the default
// branch of the dispatch tree).
func (i *Inbound) WrapListener(ln net.Listener) (net.Listener, error) {
	switch i.TLS {
	case 0:
		return ln, nil
	case 2:
		if i.Reality == nil {
			return nil, errors.New("security=reality needs reality_private_key (make a pair with: kaze -reality-keypair; the public key goes to the clients)")
		}
		return &realityListener{Listener: ln, r: i.Reality, log: i.logger()}, nil
	case 1:
		cfg, err := i.serverTLSConfig()
		if err != nil {
			return nil, err
		}
		return tls.NewListener(ln, cfg), nil
	}
	return nil, fmt.Errorf("security %d is not one of none, tls, reality", i.TLS)
}

// WrapHandler wraps the protocol handler with the stream transport. tcp keeps
// the handler as-is (REPORT.md §7.1 default branch).
func (i *Inbound) WrapHandler(h core.Handler) (core.Handler, error) {
	switch strings.ToLower(strings.TrimSpace(i.Network)) {
	case "", NetworkTCP:
		return h, nil
	case NetworkWS, NetworkHTTPUpgrade:
		// httpupgrade is the same RFC6455 upgrade without frames (REPORT.md
		// §7.2: "GET / + Upgrade: websocket-style headers, must answer 101").
		if strings.EqualFold(i.Network, NetworkHTTPUpgrade) {
			return &upgradeHandler{in: i, next: h}, nil
		}
		return &wsHandler{in: i, next: h}, nil
	case NetworkHTTP:
		// simple-obfs HTTP: a POST-style header, then the raw stream.
		return &obfsHandler{in: i, next: h}, nil
	case NetworkGRPC:
		return &grpcHandler{in: i, next: h}, nil
	case NetworkH2:
		return &h2Handler{in: i, next: h}, nil
	case NetworkXHTTP:
		return newXHTTPServer(i, h)
	}
	return nil, fmt.Errorf("network %q is not supported (tcp, ws, http, h2, grpc, xhttp)", i.Network)
}

// alpnFor is the server-side counterpart of (*Transport).secure in
// notes/rev-transport.md §1.2: h2/grpc ask for h2, http/ws for http/1.1, and
// xhttp follows the mux setting (the client picks h2 when it has no mux pool
// and http/1.1 when it has one), so the server has to offer both.
func alpnFor(network string, muxed bool, configured []string) []string {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case NetworkH2, NetworkGRPC:
		return []string{"h2"}
	case NetworkHTTP, NetworkWS, NetworkHTTPUpgrade:
		return []string{"http/1.1"}
	case NetworkXHTTP:
		if muxed {
			return []string{"http/1.1"}
		}
		return []string{"h2", "http/1.1"}
	}
	if len(configured) > 0 {
		return configured
	}
	return nil
}

// prefixConn replays the bytes a sniffer already read. The sample has the
// same wrapper as (*prefixConn).Read/ReadsFrom/WritesTo
// (notes/rev-transport.md §7.5, addresses 0xabac80/0xabada0/0xabadc0).
type prefixConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func newPrefixConn(c net.Conn, prefix []byte) *prefixConn {
	return &prefixConn{Conn: c, buf: prefix}
}

func (c *prefixConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

func (c *prefixConn) WriteTo(w io.Writer) (int64, error) {
	c.mu.Lock()
	prefix := c.buf
	c.buf = nil
	c.mu.Unlock()
	var n int64
	if len(prefix) > 0 {
		k, err := w.Write(prefix)
		n += int64(k)
		if err != nil {
			return n, err
		}
	}
	k, err := io.Copy(w, c.Conn)
	return n + int64(k), err
}

// webConn makes a plain connection look like a TLS one to net/http, so the
// standard library negotiates HTTP/2 the way it does on a real TLS listener.
// Evidence: (*Config).webTLS / (*webConn) / (*webTLSConn).ConnectionState in
// notes/rev-transport.md §7.5.
type webConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c *webConn) ConnectionState() tls.ConnectionState { return c.state }

// oneConnListener hands the accept loop a single connection and reports the
// listener closed once that connection is closed, so http.Server.Serve
// returns instead of blocking in Accept.
type oneConnListener struct {
	conn net.Conn
	addr net.Addr
	done chan struct{}
	once sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: &notifyConn{Conn: c, onClose: nil}, addr: c.LocalAddr(), done: make(chan struct{})}
}

// notifyConn reports its Close through the listener.
type notifyConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *notifyConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.Conn.Close()
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		if nc, ok := l.conn.(*notifyConn); ok {
			nc.onClose = l.closeDone
		}
		c = l.conn
	})
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) closeDone() { l.Close() }

func (l *oneConnListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.addr }

// deadline helpers: the transports set a handshake deadline and clear it once
// the stream is established (the sample uses (*Transport).readClock and the
// handshake timeout plumbed through the node).
func setDeadline(c net.Conn, t time.Time) error {
	if d, ok := c.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return nil
}

// ServeSession relays one session produced by a multiplexed transport. The
// node wires it to core.(*Server).ServeSession; the sample's mux/xhttp servers
// call the server's session relay after each stream handshake
// (notes/rev-transport.md §4.1 readStreamRequest).
var ServeSession func(ctx context.Context, s *core.Session) error

// relaySession prefers the per-inbound hook and falls back to ServeSession.
func (i *Inbound) relaySession(ctx context.Context, s *core.Session) error {
	if i.Relay != nil {
		return i.Relay(ctx, s)
	}
	if ServeSession != nil {
		return ServeSession(ctx, s)
	}
	return errors.New("transport: no session relay")
}

// handshakeTimeout mirrors the node's handshake deadline.
const handshakeTimeout = 15 * time.Second

func withHandshakeDeadline(ctx context.Context, c net.Conn) (func(), error) {
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	if err := setDeadline(c, deadline); err != nil {
		return nil, err
	}
	return func() { _ = setDeadline(c, time.Time{}) }, nil
}

// hostAllowed checks the HTTP Host header against the configured host. An
// empty configured host accepts anything (the sample only rejects a mismatch
// when wsSettings.host is set).
func hostAllowed(want, got string) bool {
	if want == "" {
		return true
	}
	got = strings.ToLower(strings.TrimSpace(got))
	want = strings.ToLower(strings.TrimSpace(want))
	if h, _, err := net.SplitHostPort(got); err == nil {
		got = h
	}
	if h, _, err := net.SplitHostPort(want); err == nil {
		want = h
	}
	return got == want || strings.HasSuffix(got, "."+want)
}

// pathAllowed compares request paths, ignoring a trailing slash.
func pathAllowed(want, got string) bool {
	if want == "" {
		want = "/"
	}
	if got == "" {
		got = "/"
	}
	trim := func(p string) string { return strings.TrimSuffix(p, "/") }
	if trim(want) == trim(got) {
		return true
	}
	// XHTTP puts a session id after the configured path.
	return strings.HasPrefix(got, trim(want)+"/")
}
