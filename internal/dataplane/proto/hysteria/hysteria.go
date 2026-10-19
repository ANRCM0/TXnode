// Package hysteria implements the Hysteria2 inbound server of kaze.
//
// Evidence: kazecore/notes/rev-proto-udp.md §1 (hysteria) and REPORT.md §6.6.
// The binary's package is github.com/ANRCM0/TX-Node/internal/dataplane/proto/hysteria with 91 functions; the
// handshake (HTTP/3 POST /auth), the headers, the padding, the salamander
// obfuscation and the brutal congestion controller are read instruction by
// instruction, and the constants below carry the address they come from.
//
// API shape: the contract (REPLICATION.md §3.2) gives QUIC inbounds a
// net.PacketConn surface instead of core.Handler, because QUIC demultiplexes
// connections itself:
//
//	type Options struct{ ... }
//	func NewServer(Options) (*Server, error)
//	func (s *Server) Serve(pc net.PacketConn) error
//	func (s *Server) Close() error
//
// UNVERIFIED / API adaptation: the sample was built against an apernet/quic-go
// that still exposed http3.Server.StreamHijacker and DatagramHijacker, both of
// which received the *quic.Conn. The pinned fork replaced them with a
// StreamDispatcher that only receives the *quic.Stream, so the association with
// the connection is rebuilt here by giving every QUIC connection its own
// http3.Server value (cheap struct) whose StreamDispatcher closes over that
// connection's state. The wire behaviour (HTTP/3 auth on stream 0, hysteria
// request headers on the following streams, QUIC datagrams for UDP) is
// unchanged.
package hysteria

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// Constants recovered from (*client).Listen @0xaa22c0 and
// (*client).ServeHTTP @0xaa2ce0 (notes/rev-proto-udp.md §1.1, §1.2, §1.7).
const (
	// maxIdleTimeout is quic.Config.MaxIdleTimeout (+0x28).
	maxIdleTimeout = 30 * time.Second
	// maxIncomingStreams is quic.Config.MaxIncomingStreams (+0x68).
	maxIncomingStreams = 1024
	// streamReceiveWindow is Initial/MaxStreamReceiveWindow (+0x40/+0x48).
	streamReceiveWindow = 8 << 20
	// connectionReceiveWindow is Initial/MaxConnectionReceiveWindow
	// (+0x50/+0x58).
	connectionReceiveWindow = 20 << 20
	// defaultHandshakeTimeout is Server+0x30's 120 s default. The field is not
	// named in the report (§1.1 marks it inferred: "handshake/auth timeout").
	defaultHandshakeTimeout = 120 * time.Second
	// obfsSocketBuffer is the 8 MiB send/receive buffer applied to the UDP
	// socket only when obfs is configured (0xaa23c0/0xaa23cf).
	obfsSocketBuffer = 8 << 20
)

// Options is the contract's QUIC inbound option set plus the two knobs the
// hysteria implementation needs to reproduce the sample.
type Options struct {
	Users      []core.User
	TLSConfig  *tls.Config
	Congestion string
	UpMbps     int
	DownMbps   int
	Brutal     bool
	Logger     *slog.Logger
	// Relay hands an established session to the node. When nil the server
	// relays the stream itself (useful for the loopback tests).
	Relay func(ctx context.Context, sess *core.Session) error

	// ObfsPassword enables salamander obfuscation. kaze's key schedule is a
	// private variant (see salamander.go), so it does not interoperate with
	// upstream hysteria2.
	ObfsPassword string
	// HandshakeTimeout bounds the auth exchange; 0 uses 120 s.
	HandshakeTimeout time.Duration
	// Profile selects the BBR profile (applyProfile in internal/congestion/bbr).
	Profile string
}

// Server is the Hysteria2 inbound.
type Server struct {
	opts Options
	log  *slog.Logger

	usersMu sync.RWMutex
	users   map[string]core.User

	// upBytesPerSec and downBytesPerSec convert the Mbps options to the byte
	// rates the protocol speaks. INFERRED: pkg.FlexInt -> *1e6/8 is not
	// instruction-verified (notes/rev-proto-udp.md §1.3 marks it U); brutal's
	// +0x08 is confirmed to be bytes/second.
	upBytesPerSec   int64
	downBytesPerSec int64
	autoCC          bool

	pc net.PacketConn
	tr *quic.Transport
	ln *quic.Listener

	// mu guards tr/ln: Serve publishes them while Close may run concurrently
	// (node shutdown or a configuration reload).
	mu sync.Mutex

	closeOnce sync.Once
	closed    chan struct{}

	// authAttempts / authFailures count the /auth outcomes for logs.
	authAttempts atomic.Int64
	authFailures atomic.Int64
}

// NewServer validates the options and builds the QUIC/TLS configuration.
func NewServer(o Options) (*Server, error) {
	if o.TLSConfig == nil {
		return nil, errors.New("hysteria: a TLS config is required (QUIC has no plaintext mode)")
	}
	if len(o.Users) == 0 {
		return nil, errors.New("hysteria: no users configured")
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		opts:   o,
		log:    log,
		users:  make(map[string]core.User, len(o.Users)),
		closed: make(chan struct{}),
	}
	for _, u := range o.Users {
		// The auth header value is the users map key itself, not
		// base64(user:pass) and not a UUID (notes/rev-proto-udp.md §1.2). The
		// panel hands the node "name:token", so the token is what a client sends.
		token := u.UUID
		if token == "" {
			continue
		}
		s.users[token] = u
	}
	if len(s.users) == 0 {
		return nil, errors.New("hysteria: no usable auth tokens")
	}
	s.upBytesPerSec = mbpsToBytesPerSec(o.UpMbps)
	s.downBytesPerSec = mbpsToBytesPerSec(o.DownMbps)
	// cfg->cc_auto (+0x28) is false when the node has a fixed bandwidth. Same
	// rule as the binary: brutal only when the operator pinned the bandwidth and
	// did not ask for auto.
	s.autoCC = !o.Brutal || o.UpMbps <= 0
	if o.Congestion == "bbr" {
		s.autoCC = true
	}
	return s, nil
}

// mbpsToBytesPerSec converts the panel's Mbps into bytes per second.
func mbpsToBytesPerSec(mbps int) int64 {
	if mbps <= 0 {
		return 0
	}
	return int64(mbps) * 1_000_000 / 8
}

// SetUsers hot-swaps the user table. Evidence: (*Server).SetUsers @0xaa2100
// builds a fresh map and publishes it with atomic.StorePointer(Server+0x48);
// here the same happens under the users mutex.
func (s *Server) SetUsers(users []core.User) {
	next := make(map[string]core.User, len(users))
	for _, u := range users {
		if u.UUID == "" {
			continue
		}
		next[u.UUID] = u
	}
	s.usersMu.Lock()
	s.users = next
	s.usersMu.Unlock()
}

func (s *Server) lookupUser(token string) (core.User, bool) {
	s.usersMu.RLock()
	u, ok := s.users[token]
	s.usersMu.RUnlock()
	return u, ok
}

// quicConfig returns the transport parameters measured in Listen @0xaa22c0.
func (s *Server) quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 maxIdleTimeout,
		MaxIncomingStreams:             maxIncomingStreams,
		MaxIncomingUniStreams:          maxIncomingStreams,
		InitialStreamReceiveWindow:     streamReceiveWindow,
		MaxStreamReceiveWindow:         streamReceiveWindow,
		InitialConnectionReceiveWindow: connectionReceiveWindow,
		MaxConnectionReceiveWindow:     connectionReceiveWindow,
		// EnableDatagrams (+0x84) = 1: hysteria carries UDP in QUIC datagrams.
		EnableDatagrams: true,
		// Allow0RTT (+0x83) is never written, and Listen uses
		// quic.Transport.Listen rather than ListenEarly: no 0-RTT.
		Allow0RTT:               false,
		DisablePathMTUDiscovery: false,
		HandshakeIdleTimeout:    s.handshakeTimeout(),
	}
}

func (s *Server) handshakeTimeout() time.Duration {
	if s.opts.HandshakeTimeout > 0 {
		return s.opts.HandshakeTimeout
	}
	return defaultHandshakeTimeout
}

// tlsConfig clones the caller's config, pins TLS 1.3 and lets http3 install its
// ALPN ("h3"). Evidence: Listen calls http3.configureTLSConfig at 0xaa24ee.
func (s *Server) tlsConfig() *tls.Config {
	cfg := s.opts.TLSConfig.Clone()
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	return http3.ConfigureTLSConfig(cfg)
}

// Serve runs the server on an already bound UDP socket and blocks until the
// socket fails or Close is called. It takes ownership of pc.
func (s *Server) Serve(pc net.PacketConn) error {
	if pc == nil {
		return errors.New("hysteria: nil packet conn")
	}
	s.pc = pc

	var transportConn net.PacketConn = pc
	disableGSO := false
	if s.opts.ObfsPassword != "" {
		// obfs branch: 8 MiB read/write buffers, then the salamander wrapper
		// (0xaa23c0, 0xaa23cf, newSalamanderOOB @0xaa6ee0).
		if udp, ok := pc.(*net.UDPConn); ok {
			_ = udp.SetReadBuffer(obfsSocketBuffer)
			_ = udp.SetWriteBuffer(obfsSocketBuffer)
		}
		transportConn = newSalamanderPacketConn(pc, s.opts.ObfsPassword)
		// The wrapper rewrites every datagram after the kernel would have
		// coalesced it, so GSO must be off or all but the first segment is
		// corrupted (quic.Transport.DisableGSO documents exactly this).
		disableGSO = true
	}

	tr := &quic.Transport{Conn: transportConn, DisableGSO: disableGSO}
	ln, err := tr.Listen(s.tlsConfig(), s.quicConfig())
	if err != nil {
		return fmt.Errorf("hysteria: listening: %w", err)
	}
	s.publish(tr, ln)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-s.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
			}
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		go s.serveConn(conn)
	}
}

// serveConn gives one QUIC connection its own HTTP/3 server value so the
// StreamDispatcher can reach the connection state (see the package comment).
func (s *Server) serveConn(conn *quic.Conn) {
	st := &connState{
		srv:    s,
		conn:   conn,
		authed: false,
	}
	h3 := &http3.Server{
		Handler:     &authHandler{srv: s},
		QUICConfig:  s.quicConfig(),
		Logger:      s.log,
		IdleTimeout: maxIdleTimeout,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			return context.WithValue(ctx, connStateKey{}, st)
		},
		StreamDispatcher: st.dispatchStream,
	}
	// The HTTP/3 exchange includes the auth request; streams that are not HTTP/3
	// requests are handed to st.handleStream, which runs the hysteria data plane.
	err := h3.ServeQUICConn(conn)
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Debug("hysteria: connection finished", "error", err, "remote", conn.RemoteAddr().String())
	}
	st.closeSessions()
}

// Close stops the listener, the transport and every session.
// listeners returns the published transport and listener under the lock.
func (s *Server) listeners() (*quic.Transport, *quic.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tr, s.ln
}

// publish stores the transport and listener.
func (s *Server) publish(tr *quic.Transport, ln *quic.Listener) {
	s.mu.Lock()
	s.tr, s.ln = tr, ln
	s.mu.Unlock()
}

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		tr, ln := s.listeners()
		if ln != nil {
			err = ln.Close()
		}
		if tr != nil {
			if e := tr.Close(); err == nil {
				err = e
			}
		}
	})
	return err
}

// Addr reports the QUIC listener's address once Serve is running.
func (s *Server) Addr() net.Addr {
	_, ln := s.listeners()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

// connStateKey is the context key carrying the per-connection state.
type connStateKey struct{}
