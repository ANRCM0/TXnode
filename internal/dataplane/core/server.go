package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server is the accept side of the kernel: core.(*Server) as recovered in
// notes/rev-core.md §2.2/§2.3. Each accepted connection walks the fifteen stages
// of (*Server).handle @0x7afd80 in the same order:
//
//	 1. track(conn) (defer untrack)
//	 2. TCP keepalive
//	 3. freshSet.add concurrency gate (defer Fresh.Done)
//	 4. handshake deadline
//	 5. proxy_protocol / force_proxy_protocol flags
//	 6. Trust.Allows
//	 7. untrusted peer carrying a PROXY header -> peekProxyHeader
//	 8. warnUntrustedProxy
//	 9. readProxyHeader v1/v2
//	10. clientIP (the real source address)
//	11. Tracker.deviceKey (inside Tracker.Acquire)
//	12. Guard.Blocked (invalid_access_*)
//	13. Server.Transport hook
//	14. localOf (auto_out_ip source address)
//	15. (*Server).serve -> handler.Handle -> ServeSession

// ServerOptions mirrors the contract in REPLICATION.md §3.1. BindLocal and
// Fronted are the two booleans observed at Server+0x58/+0x59 in
// notes/rev-core.md (未决 8); BindLocal is auto_out_ip.
type ServerOptions struct {
	Handler   Handler
	Transport func(net.Conn) net.Conn // TLS/REALITY 之后的上层包装钩子
	Tracker   *Tracker
	Router    func() *Router // 原子热替换的当前路由
	Trust     *Trust
	Guard     *Guard
	Logger    *slog.Logger

	HandshakeTimeout       time.Duration
	TCPTimeout, UDPTimeout time.Duration
	MaxFresh               int

	ProxyProtocol, RequireProxyProtocol bool
	BindLocal                           bool // auto_out_ip
	Fronted                             bool // UNVERIFIED: Server+0x58

	NodeID    int
	OnTraffic func(userID int, up, down int64) // 计数回调；可空

	// Admission gates new sessions (authorization expiry / drain). nil admits.
	Admission func() bool
	// OnAudit observes one routed session (audit reporter). target is the
	// requested domain (may be empty), targetIP the dialled address.
	OnAudit func(userID int, target, targetIP, sourceIP string)
}

type handlerBox struct{ h Handler }

// Server owns one listener (or packet conn), the handler and the per-connection
// lifecycle.
type Server struct {
	mu      sync.RWMutex
	opts    ServerOptions
	handler atomic.Pointer[handlerBox]
	fresh   *freshSet
	dialer  *Dialer

	ln net.Listener
	pc net.PacketConn

	ctx    context.Context
	cancel context.CancelFunc

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}

	proxyMu   sync.Mutex
	proxyWarn map[string]time.Time

	closeOnce sync.Once
	closed    chan struct{}
}

// ErrSessionRefused is returned by ServeSession when the tracker refuses the
// session (connection or device limit). The caller has already logged the
// observed "session refused" line.
var ErrSessionRefused = errors.New("session refused")

// NewServer builds a server. Missing dependencies fall back to safe defaults:
// slog.Default, a fresh Tracker, the default trust table and a disabled Guard.
func NewServer(o ServerOptions) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Tracker == nil {
		o.Tracker = NewTracker()
	}
	if o.Trust == nil {
		o.Trust, _ = ParseTrust("")
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.TCPTimeout <= 0 {
		o.TCPTimeout = 5 * time.Minute
	}
	if o.UDPTimeout <= 0 {
		o.UDPTimeout = 2 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		opts:      o,
		fresh:     newFreshSet(o.MaxFresh),
		dialer:    NewDialer(o.HandshakeTimeout),
		ctx:       ctx,
		cancel:    cancel,
		conns:     make(map[net.Conn]struct{}),
		proxyWarn: make(map[string]time.Time),
		closed:    make(chan struct{}),
	}
	if o.Handler != nil {
		s.handler.Store(&handlerBox{h: o.Handler})
	}
	return s
}

// SetHandler hot-swaps the protocol handler. It is safe before and during
// Serve (node swaps in the transport-wrapped handler after binding).
func (s *Server) SetHandler(h Handler) {
	if h == nil {
		return
	}
	s.handler.Store(&handlerBox{h: h})
}

// Handler returns the current handler.
func (s *Server) Handler() Handler {
	if b := s.handler.Load(); b != nil {
		return b.h
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.opts.Handler
}

// Update hot-replaces the handler/router and the policy fields, keeping the
// listener and the live sessions untouched (REPLICATION.md §3.1). Nil fields
// keep their previous value; zero durations keep the previous value.
func (s *Server) Update(o ServerOptions) {
	s.mu.Lock()
	old := s.opts
	if o.Handler == nil {
		o.Handler = old.Handler
	}
	if o.Tracker == nil {
		o.Tracker = old.Tracker
	}
	if o.Router == nil {
		o.Router = old.Router
	}
	if o.Trust == nil {
		o.Trust = old.Trust
	}
	if o.Guard == nil {
		o.Guard = old.Guard
	}
	if o.Logger == nil {
		o.Logger = old.Logger
	}
	if o.Transport == nil {
		o.Transport = old.Transport
	}
	if o.OnTraffic == nil {
		o.OnTraffic = old.OnTraffic
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = old.HandshakeTimeout
	}
	if o.TCPTimeout <= 0 {
		o.TCPTimeout = old.TCPTimeout
	}
	if o.UDPTimeout <= 0 {
		o.UDPTimeout = old.UDPTimeout
	}
	s.dialer = NewDialer(o.HandshakeTimeout)
	s.opts = o
	s.mu.Unlock()

	if o.Handler != nil {
		s.SetHandler(o.Handler)
	}
	s.fresh.setMax(o.MaxFresh)
}

// snapshot returns a consistent copy of the options.
func (s *Server) snapshot() ServerOptions {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.opts
}

// getDialer returns the current dialer (Update may replace it).
func (s *Server) getDialer(fallback time.Duration) *Dialer {
	s.mu.RLock()
	d := s.dialer
	s.mu.RUnlock()
	if d == nil {
		return NewDialer(fallback)
	}
	return d
}

// Router returns the current routing table (nil is allowed; callers treat nil as
// direct).
func (s *Server) Router() *Router {
	s.mu.RLock()
	fn := s.opts.Router
	s.mu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// Serve accepts connections until the listener is closed. Accept errors on a
// closed listener end the loop with nil. "too many open files" backs off
// exponentially from 1s to 5s (notes/rev-core.md §7.4: cmp rax,0x3b9aca00 /
// 0x4c4b40 in (*Server).Serve @0x7af4c0).
func (s *Server) Serve(ln net.Listener) error {
	if ln == nil {
		return errors.New("nil listener")
	}
	s.mu.Lock()
	if s.ln != nil {
		s.mu.Unlock()
		return errors.New("listener already set")
	}
	s.ln = ln
	s.mu.Unlock()
	defer ln.Close()

	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				select {
				case <-time.After(5 * time.Millisecond):
					continue
				case <-s.closed:
					return nil
				}
			}
			if strings.Contains(err.Error(), "too many open files") {
				if delay == 0 {
					delay = time.Second
				} else if delay *= 2; delay > 5*time.Second {
					delay = 5 * time.Second
				}
				select {
				case <-time.After(delay):
					continue
				case <-s.closed:
					return nil
				}
			}
			// Other transient errors: brief pause, keep serving.
			select {
			case <-time.After(5 * time.Millisecond):
				continue
			case <-s.closed:
				return nil
			}
		}
		delay = 0
		go s.handle(c)
	}
}

// ServePackets serves a datagram socket. Protocols that own their UDP framing
// implement PacketHandler and are driven by node directly; when the handler does
// not, the connection is drained until it is closed.
func (s *Server) ServePackets(pc net.PacketConn) error {
	if pc == nil {
		return errors.New("nil packet conn")
	}
	s.mu.Lock()
	if s.pc != nil {
		s.mu.Unlock()
		return errors.New("packet conn already set")
	}
	s.pc = pc
	s.mu.Unlock()
	defer pc.Close()

	if ph, ok := s.Handler().(PacketHandler); ok {
		return ph.ServePackets(s.ctx, pc)
	}
	buf := make([]byte, 65535)
	for {
		if _, _, err := pc.ReadFrom(buf); err != nil {
			if s.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

// Close stops the listener, the packet conn and every tracked connection.
func (s *Server) Close() error {
	var first error
	s.closeOnce.Do(func() {
		close(s.closed)
		s.cancel()
		s.mu.RLock()
		ln, pc := s.ln, s.pc
		s.mu.RUnlock()
		if ln != nil {
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				first = err
			}
		}
		if pc != nil {
			if err := pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				first = err
			}
		}
		s.connsMu.Lock()
		conns := make([]net.Conn, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.connsMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return first
}

func (s *Server) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// track registers a connection so Close can tear it down (Server.track
// @0x7af8c0).
func (s *Server) track(c net.Conn) {
	s.connsMu.Lock()
	s.conns[c] = struct{}{}
	s.connsMu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.connsMu.Lock()
	delete(s.conns, c)
	s.connsMu.Unlock()
}

// warnUntrustedProxy logs the actionable warning once per source address in a
// 10 minute window (Server.warnUntrustedProxy @0x7afa20 keeps
// proxyWarned map[string]time.Time).
func (s *Server) warnUntrustedProxy(addr netip.Addr) {
	key := addr.String()
	now := time.Now()
	s.proxyMu.Lock()
	last, ok := s.proxyWarn[key]
	if ok && now.Sub(last) < 10*time.Minute {
		s.proxyMu.Unlock()
		return
	}
	s.proxyWarn[key] = now
	s.proxyMu.Unlock()
	msg := fmt.Sprintf("PROXY protocol header from %s, which is not in trusted_proxies; "+
		"add it (trusted_proxies=private,cloudflare,%s) or the relay's users cannot connect",
		key, key)
	s.snapshot().Logger.Warn(msg)
}

// handle runs the fifteen stages for one accepted connection.
func (s *Server) handle(c net.Conn) {
	o := s.snapshot()
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}

	// 1. track
	s.track(c)
	defer s.untrack(c)

	// 2. TCP keepalive
	if tc, ok := c.(*net.TCPConn); ok {
		KeepAlive(tc)
	}

	// 3. fresh concurrency gate
	fresh := s.fresh.add(c)
	if fresh == nil {
		// The gate is full: drop the unauthenticated connection.
		_ = c.Close()
		return
	}
	defer fresh.Done()

	// 3b. admission (authorization expiry / draining)
	if o.Admission != nil && !o.Admission() {
		log.Debug("session refused: admission closed", "from", clientIP(c).String())
		abortConn(c)
		return
	}

	// 4. handshake deadline
	hsDeadline := time.Now().Add(o.HandshakeTimeout)
	_ = c.SetDeadline(hsDeadline)

	src := clientIP(c)

	// 5-9. PROXY protocol. The header is only parsed for trusted peers; with
	// proxy_protocol off nothing is peeked, so ordinary public clients pay
	// nothing.
	peerTrusted := o.Trust.Allows(src)
	conn := net.Conn(c)
	if o.ProxyProtocol || o.RequireProxyProtocol {
		pc := newProxyConn(c)
		conn = pc
		if !peerTrusted {
			if o.RequireProxyProtocol {
				log.Debug("PROXY header required but the peer is not a trusted proxy", "from", src.String())
				abortConn(conn)
				return
			}
			// 7-8: proxy_protocol is on but the peer is not trusted. A header
			// is ignored and the relay is told to fix trusted_proxies.
			if pc.peekProxyHeader() {
				s.warnUntrustedProxy(src)
				abortConn(conn)
				return
			}
		} else {
			claimed, found, err := pc.readProxyHeader()
			if err != nil {
				log.Debug("malformed PROXY header", "from", src.String(), "err", err)
				abortConn(conn)
				return
			}
			if found {
				if claimed.IsValid() {
					src = claimed
				}
			} else if o.RequireProxyProtocol {
				log.Debug("connection without a PROXY header", "from", src.String())
				abortConn(conn)
				return
			}
		}
	}
	// The peek lowered the read deadline; restore the handshake deadline.
	_ = conn.SetDeadline(hsDeadline)

	// 10. real source address (proxyConn.RemoteAddr already overrides it)
	src = clientIP(conn)

	// 11. device key / 12. guard
	if o.Guard.Blocked(src) {
		abortConn(conn)
		return
	}

	// 13. transport hook (TLS/REALITY/stream wrappers)
	if o.Transport != nil {
		wrapped := o.Transport(conn)
		if wrapped == nil {
			log.Debug("transport handshake failed", "from", src.String())
			o.Guard.Failed(src)
			abortConn(conn)
			return
		}
		conn = wrapped
	}

	// 14. localOf
	local := s.localOf(conn, o.BindLocal)

	// 15. serve
	s.serve(o, conn, src, local)
}

// serve runs the protocol handshake and, on success, dispatches the session.
// Handshake failures are counted by the brute-force guard and logged as
// "handshake failed" (0x7b14a2).
func (s *Server) serve(o ServerOptions, conn net.Conn, src netip.Addr, local netip.Addr) {
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	h := s.Handler()
	if h == nil {
		_ = conn.Close()
		return
	}
	sess, err := h.Handle(s.ctx, conn)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		if st, ok := IsStranger(err); ok {
			// A stranger is not an authentication failure; the brute-force
			// guard only counts failed handshakes of real protocol clients.
			if !st.Quiet {
				dismissStranger(conn)
			} else {
				_ = conn.Close()
			}
			return
		}
		log.Debug("handshake failed", "from", src.String(), "err", err)
		o.Guard.Failed(src)
		_ = conn.Close()
		return
	}
	if sess == nil {
		log.Debug("handshake failed", "from", src.String(), "err", "no session")
		o.Guard.Failed(src)
		_ = conn.Close()
		return
	}
	o.Guard.Succeeded(src)
	if sess.Conn == nil {
		sess.Conn = conn
	}
	if !sess.Local.IsValid() && local.IsValid() {
		sess.Local = local
	}
	if sess.Socket == nil {
		sess.Socket = tcpWriter(conn)
	}

	lease, ok := s.acquire(sess, src, log)
	if !ok {
		_ = sess.Conn.Close()
		return
	}
	defer lease.Release()
	_ = s.serveSession(s.ctx, sess, src)
}

// acquire reserves the tracker quota for a session. A userID of 0 (protocols
// without users) and a nil tracker are unrestricted.
func (s *Server) acquire(sess *Session, src netip.Addr, log *slog.Logger) (*Lease, bool) {
	o := s.snapshot()
	if o.Tracker == nil || sess.UserID <= 0 {
		return nil, true
	}
	lease, ok := o.Tracker.Acquire(sess.UserID, src, sess.Conn)
	if ok {
		return lease, true
	}
	reason := o.Tracker.refuseReason(sess.UserID, src)
	if log == nil {
		log = slog.Default()
	}
	log.Info("session refused", "user", sess.UserID, "from", src.String(), "reason", reason)
	return nil, false
}

// refuseReason reports which quota refused the session, for the observed
// `reason="connection limit reached"` / `reason="device limit reached"` logs.
// It reads the tracker after Acquire failed, so it is only diagnostic.
func (t *Tracker) refuseReason(userID int, src netip.Addr) string {
	t.mu.RLock()
	u := t.users[userID]
	connLimit := t.connLimit
	devLimit := t.globalDeviceLimit
	t.mu.RUnlock()
	if u == nil {
		return "unknown user"
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if connLimit > 0 && len(u.conns) >= connLimit {
		return "connection limit reached"
	}
	if devLimit > 0 && len(u.ips) >= devLimit {
		return "device limit reached"
	}
	return "limit reached"
}

// clientIP returns the socket peer address (core.clientIP @0x7afcc0). A
// proxyConn overrides RemoteAddr with the PROXY protocol source.
func clientIP(c net.Conn) netip.Addr {
	if c == nil || c.RemoteAddr() == nil {
		return netip.Addr{}
	}
	s := c.RemoteAddr().String()
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr()
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

// ClientIP exposes clientIP to transport wrappers.
func ClientIP(c net.Conn) netip.Addr { return clientIP(c) }

// localOf returns the local address the client reached when auto_out_ip is on
// (Server.localOf @0x7b0f60).
func (s *Server) localOf(c net.Conn, bind bool) netip.Addr {
	if !bind || c == nil || c.LocalAddr() == nil {
		return netip.Addr{}
	}
	s2 := c.LocalAddr().String()
	if ap, err := netip.ParseAddrPort(s2); err == nil {
		return ap.Addr()
	}
	return netip.Addr{}
}

// abortConn closes a connection with RST when possible, matching the observed
// "connection reset" outcome for banned/refused peers (REPORT.md §21.3).
func abortConn(c net.Conn) {
	if pc, ok := c.(*proxyConn); ok {
		c = pc.Conn
	}
	if tc := tcpWriter(c); tc != nil {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

// dismissStranger answers a connection that does not look like one of our
// clients the way a web server would (core.Stranger.Dismiss @0x7b8940).
//
// UNVERIFIED: the exact decoy body is produced by transport.siteAnswer; the
// keep-alive decoy is not part of core. This minimal 404 keeps the connection
// shape (HTTP status line + empty body) without touching disk (REPORT.md §7.9).
func dismissStranger(c net.Conn) {
	if c == nil {
		return
	}
	const body = "404 page not found\n"
	resp := "HTTP/1.1 404 Not Found\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n\r\n" + body
	_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte(resp))
	_ = c.Close()
}
