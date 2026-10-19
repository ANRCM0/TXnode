// Package socks5 is the SOCKS5 inbound protocol of kaze v0.5.18.
//
// Evidence:
//   - REPORT.md §6.9 (error strings), §20.5 (method negotiation observed on the
//     wire), §22.2 (UDP ASSOCIATE relay replies on the same port), §24.2
//     (the per-user connection limit is enforced by core, not here).
//   - notes/rev-proto-tcp.md §5.1 (Handshake/auth), §5.2
//     (ListenUDP/associate/loop/remove, 65536 association table, 512 KiB loop
//     bound), §4.6 (the "%s: a key is not unpadded URL" blob tail belongs to
//     shadowsocks, not here).
//
// Wire behaviour reproduced from the binary (addresses are VAs in
// kazecore/bin/kaze-linux-amd64, sha256 723d4e20…f900):
//
//	socks5.(*Handler).Handshake      @0xb2d240  method negotiation, cmd dispatch
//	socks5.(*Handler).auth           @0xb2d820  RFC 1929 sub-negotiation
//	socks5.reply                     @0xb2e4a0
//	socks5.addrPortOf                @0xb2e5a0
//	socks5.(*Handler).ListenUDP      @0xb2e660  the handler owns the UDP socket
//	socks5.(*PacketServer).associate @0xb2e9a0
//	socks5.(*PacketServer).loop      @0xb2ef00
//	socks5.(*association).ReadPacket @0xb2f920
//	socks5.(*association).WritePacket @0xb2fa80
//
// The method table is fixed by observation (REPORT.md §20.5):
//
//	client offers {0x00}       -> server answers 05 ff (no acceptable method),
//	                              even when users are configured
//	client offers {0x02}       -> 05 02, then RFC 1929
//	client offers {0x00,0x02}  -> 02 (user/pass wins whenever users exist)
//
// The username is ignored; the password must equal a user's secret (local mode)
// or uuid (panel mode). Observed on the wire: `bob/secret` and `(empty)/secret`
// both pass (§20.5).
package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Protocol constants (RFC 1928 / RFC 1929).
const (
	Version = 0x05

	MethodNoAuth       = 0x00
	MethodGSSAPI       = 0x01
	MethodUserPass     = 0x02
	MethodNoAcceptable = 0xff

	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	RepSuccess             = 0x00
	RepGeneralFailure      = 0x01
	RepNotAllowed          = 0x02
	RepNetworkUnreachable  = 0x03
	RepHostUnreachable     = 0x04
	RepConnectionRefused   = 0x05
	RepTTLExpired          = 0x06
	RepCommandNotSupported = 0x07
	RepAddressNotSupported = 0x08

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04

	// authVersion is the RFC 1929 version byte; @0xb2df8d the binary compares the
	// first byte against 0x1 and reports "socks5: bad authentication version".
	authVersion = 0x01

	// udpHeaderLen is RSV(2)+FRAG(1); kaze does not implement SOCKS5 datagram
	// fragmentation (there is no error string for it), so non-zero FRAG datagrams
	// are dropped.
	udpHeaderLen = 3
)

// Error strings are the binary's own literals; tests assert the exact text.
var (
	// ErrNotClient ← "socks5: not a SOCKS5 client" @0xf7025d.
	ErrNotClient = errors.New("socks5: not a SOCKS5 client")
	// ErrAuthFailed ← "socks5: authentication failed" @0xf72f63.
	ErrAuthFailed = errors.New("socks5: authentication failed")
	// ErrBadAuthVersion ← "socks5: bad authentication version" @0xf7a6fa.
	ErrBadAuthVersion = errors.New("socks5: bad authentication version")
	// ErrBadRequestVersion ← "socks5: bad request version" @0xf70227.
	ErrBadRequestVersion = errors.New("socks5: bad request version")
	// ErrUnsupportedCommand ← "socks5: unsupported command" @0xf70242.
	ErrUnsupportedCommand = errors.New("socks5: unsupported command")
	// ErrUnknownClientAddress ← "socks5: unknown client address" @0xf74518; the
	// binary raises it from socks5.addrPortOf @0xb2e5a0 when a peer address is
	// neither *net.UDPAddr nor *net.TCPAddr.
	ErrUnknownClientAddress = errors.New("socks5: unknown client address")
	// ErrTooManyAssociations ← "socks5: too many UDP associations" @0xf78e34.
	ErrTooManyAssociations = errors.New("socks5: too many UDP associations")
	// ErrUDPUnavailable ← "socks5: UDP is not available on this node" @0xf84ed3.
	// (The rodata blob carries a concatenated "%s: a key is not unpadded URL"
	// right after it; that tail belongs to the shadowsocks key parser, see
	// notes/rev-proto-tcp.md §4.6.)
	ErrUDPUnavailable = errors.New("socks5: UDP is not available on this node")

	// errBadAddr covers ATYP values 0x02/0x05..0xff. The binary has no surviving
	// literal for this branch (all eight of its strings are accounted for).
	// UNVERIFIED: wording
	errBadAddr = errors.New("socks5: bad address type")
)

// Options is the package contract (REPLICATION.md §3.2).
type Options struct {
	// Users are the admitted accounts. A user's UUID is its password; the
	// anonymous SOCKS5 username field is ignored (REPORT.md §20.5).
	Users []core.User
	// NoAuth accepts method 0x00. It does not override a configured user table:
	// with users present the server always selects 0x02 (§20.5).
	NoAuth bool
	// UDP enables the UDP ASSOCIATE command (needs ServePackets to be running).
	UDP bool
	// MaxAssociations bounds the association table. The binary compares against a
	// capacity of 0x10000 (@0xb2e9a0 `cmp qword [rdx+0x28],0x10000`) but takes the
	// effective limit from configuration, so it is exposed here.
	// UNVERIFIED: the 1024 default is our choice; <=0 keeps it.
	MaxAssociations int
	// AssociationIdle closes an idle association. UNVERIFIED: value.
	AssociationIdle time.Duration
}

var (
	_ core.Handler       = (*Handler)(nil)
	_ core.PacketHandler = (*Handler)(nil)
)

// Handler is the SOCKS5 inbound. It implements both core.Handler and
// core.PacketHandler (socks5.(*Handler).ListenUDP @0xb2e660 in the binary).
type Handler struct {
	users  map[string]*core.User // password (secret/uuid) -> user
	noAuth bool
	udp    bool
	max    int
	idle   time.Duration

	pkt atomic.Pointer[packetServer]
}

// NewHandler validates Options and builds the handler.
func NewHandler(o Options) (*Handler, error) {
	h := &Handler{
		users:  make(map[string]*core.User, len(o.Users)),
		noAuth: o.NoAuth,
		udp:    o.UDP,
		max:    o.MaxAssociations,
		idle:   o.AssociationIdle,
	}
	if h.max <= 0 {
		h.max = 1024
	}
	if h.idle <= 0 {
		h.idle = 120 * time.Second
	}
	for i := range o.Users {
		if o.Users[i].UUID == "" {
			continue
		}
		h.users[o.Users[i].UUID] = &o.Users[i]
	}
	if len(h.users) == 0 {
		// A node without users cannot authenticate anybody; it must accept
		// no-auth or it would be unreachable.
		h.noAuth = true
	}
	return h, nil
}

// Handle performs method negotiation, authentication and the command request,
// then returns the session for core to relay.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	// The binary reads the greeting with two fixed-size reads: ver+nmethods
	// (2 bytes, cap 0x201) then the method list (@0xb2df65 `mov esi,0x201`).
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	if head[0] != Version {
		// Nothing about this peer looks like SOCKS5: let core answer the way a
		// web server would (the sniffer's "socks5: not a SOCKS5 client").
		return nil, &core.Stranger{Conn: conn, Err: ErrNotClient}
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}
	method := h.selectMethod(methods)
	if _, err := conn.Write([]byte{Version, method}); err != nil {
		return nil, err
	}
	if method == MethodNoAcceptable {
		return nil, ErrAuthFailed
	}
	var user *core.User
	if method == MethodUserPass {
		u, err := h.auth(conn)
		if err != nil {
			return nil, err
		}
		user = u
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT (RFC 1928 §4).
	var req [3]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return nil, err
	}
	if req[0] != Version {
		return nil, ErrBadRequestVersion
	}
	dest, err := ReadAddr(conn)
	if err != nil {
		_ = reply(conn, RepAddressNotSupported, socks.Addr{})
		return nil, err
	}

	userID := 0
	if user != nil {
		userID = user.ID
	}

	switch req[1] {
	case CmdConnect:
		// BND.ADDR is the literal 0.0.0.0 (@0xf596d5), BND.PORT 0.
		if err := reply(conn, RepSuccess, socks.Addr{Host: "0.0.0.0"}); err != nil {
			return nil, err
		}
		return &core.Session{
			UserID: userID,
			Dest:   dest,
			Conn:   conn,
			Socket: tcpConn(conn),
		}, nil

	case CmdUDPAssociate:
		return h.associate(conn, userID)

	default:
		_ = reply(conn, RepCommandNotSupported, socks.Addr{})
		return nil, ErrUnsupportedCommand
	}
}

// selectMethod implements the table in REPORT.md §20.5.
func (h *Handler) selectMethod(methods []byte) byte {
	hasNoAuth, hasUserPass := false, false
	for _, m := range methods {
		switch m {
		case MethodNoAuth:
			hasNoAuth = true
		case MethodUserPass:
			hasUserPass = true
		}
	}
	if len(h.users) > 0 {
		// Only 0x02 is acceptable when users exist — a client offering no-auth
		// alone is refused with 05 ff, never downgraded (§20.5).
		if hasUserPass {
			return MethodUserPass
		}
		return MethodNoAcceptable
	}
	if hasNoAuth && (h.noAuth || len(h.users) == 0) {
		return MethodNoAuth
	}
	return MethodNoAcceptable
}

// auth is the RFC 1929 sub-negotiation (socks5.(*Handler).auth @0xb2d820):
// VER ULEN UNAME PLEN PASSWD. The username is ignored, the password is looked up
// in the user table. Reply bytes are observed at @0xb2e189
// `mov WORD PTR [rax],0x1` for success (01 00) and @0xb2e1e5
// `mov WORD PTR [rax],0x101` for failure (01 01) — REPORT.md §20.5.
func (h *Handler) auth(conn net.Conn) (*core.User, error) {
	var ver [2]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		return nil, err
	}
	if ver[0] != authVersion {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		return nil, ErrBadAuthVersion
	}
	uname := make([]byte, int(ver[1]))
	if _, err := io.ReadFull(conn, uname); err != nil {
		return nil, err
	}
	var plen [1]byte
	if _, err := io.ReadFull(conn, plen[:]); err != nil {
		return nil, err
	}
	passwd := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return nil, err
	}
	user, ok := h.users[string(passwd)]
	if !ok {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		return nil, ErrAuthFailed
	}
	if _, err := conn.Write([]byte{authVersion, 0x00}); err != nil {
		return nil, err
	}
	return user, nil
}

// associate answers cmd 0x03: it registers the association on the UDP socket
// owned by ServePackets, replies with the relay endpoint and hands core a
// PacketStream. REPORT.md §22.2: the reply carries the node's own port, i.e. the
// UDP relay answers on the same port as the TCP listener.
func (h *Handler) associate(conn net.Conn, userID int) (*core.Session, error) {
	srv := h.pkt.Load()
	if !h.udp || srv == nil {
		_ = reply(conn, RepCommandNotSupported, socks.Addr{})
		return nil, ErrUDPUnavailable
	}
	a, err := srv.associate(conn, h.idle)
	if err != nil {
		_ = reply(conn, RepGeneralFailure, socks.Addr{})
		return nil, err
	}
	if err := reply(conn, RepSuccess, srv.relayAddr(conn)); err != nil {
		_ = a.Close()
		return nil, err
	}
	// core gets the control connection (the association dies with it — the binary
	// keeps one goroutine per association in PacketServer.loop @0xb2ef00) plus the
	// datagram stream.
	return &core.Session{
		UserID:  userID,
		Conn:    &controlConn{Conn: conn, a: a},
		Packets: a,
	}, nil
}

// ServePackets implements core.PacketHandler: the node binds the UDP socket
// (same port as the TCP listener) and hands it over here, mirroring
// socks5.(*Handler).ListenUDP @0xb2e660.
func (h *Handler) ServePackets(ctx context.Context, pc net.PacketConn) error {
	if !h.udp {
		return ErrUDPUnavailable
	}
	srv := &packetServer{h: h, pc: pc, assocs: make(map[string]*association)}
	h.pkt.Store(srv)
	defer h.pkt.Store(nil)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = pc.Close()
		case <-stop:
		}
	}()

	buf := make([]byte, 0x10000)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if n < udpHeaderLen {
			continue
		}
		a := srv.lookup(hostOf(from))
		if a == nil {
			// Unknown peer: nothing to do. The association table is keyed by the
			// control connection's IP, so stray datagrams never match.
			continue
		}
		a.deliver(from, buf[:n])
	}
}

// packetServer is socks5.PacketServer: the shared UDP socket plus the
// association table.
type packetServer struct {
	h      *Handler
	pc     net.PacketConn
	mu     sync.RWMutex
	assocs map[string]*association
}

func (s *packetServer) lookup(key string) *association {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.assocs[key]
}

func (s *packetServer) associate(conn net.Conn, idle time.Duration) (*association, error) {
	key := hostOf(conn.RemoteAddr())
	if key == "" {
		return nil, ErrUnknownClientAddress
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.assocs) >= s.h.max {
		return nil, ErrTooManyAssociations
	}
	a := &association{
		srv:     s,
		key:     key,
		control: conn,
		ch:      make(chan udpDatagram, 8),
		done:    make(chan struct{}),
		idle:    idle,
	}
	a.touch()
	s.assocs[key] = a
	go a.expire()
	return a, nil
}

func (s *packetServer) remove(a *association) {
	s.mu.Lock()
	if cur, ok := s.assocs[a.key]; ok && cur == a {
		delete(s.assocs, a.key)
	}
	s.mu.Unlock()
}

// relayAddr is what the ASSOCIATE reply advertises: the node's own port
// (REPORT.md §22.2: `associate reply 05 00 00 01 7f000001 46a0`, 0x46a0 = 18080,
// the same port the TCP listener used). When the socket is bound to the wildcard
// address the control connection's local address is used instead.
func (s *packetServer) relayAddr(conn net.Conn) socks.Addr {
	addr := socks.FromNetAddr(s.pc.LocalAddr())
	ip := addr.IP()
	if ip.IsValid() && !ip.IsUnspecified() {
		return addr
	}
	if la := conn.LocalAddr(); la != nil {
		local := socks.FromNetAddr(la)
		if lip := local.IP(); lip.IsValid() && !lip.IsUnspecified() {
			return local
		}
	}
	return socks.Addr{Host: "0.0.0.0", Port: addr.Port}
}

// association is socks5.association: one UDP association, exposed to core as a
// core.PacketStream.
type association struct {
	srv     *packetServer
	control net.Conn
	key     string // client host, same as the TCP peer

	once sync.Once
	ch   chan udpDatagram
	done chan struct{}
	idle time.Duration
	last atomic.Int64 // unix nanos of the last datagram

	peerMu sync.Mutex
	peer   net.Addr // endpoint of the most recent request datagram
}

type udpDatagram struct {
	from net.Addr
	buf  []byte
}

func (a *association) touch() { a.last.Store(time.Now().UnixNano()) }

func (a *association) expire() {
	t := time.NewTicker(a.idle / 2)
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case <-t.C:
			if time.Since(time.Unix(0, a.last.Load())) > a.idle {
				_ = a.Close()
				return
			}
		}
	}
}

// deliver queues one raw datagram read by the packet server and remembers the
// client endpoint to answer on.
func (a *association) deliver(from net.Addr, p []byte) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case a.ch <- udpDatagram{from: from, buf: buf}:
	default:
		// Bounded queue; the binary bounds its loop buffer at 512 KiB
		// (@0xb2ef00 `cmp r9,0x80000`). Drop when the reader falls behind.
	}
}

// ReadPacket parses one RFC 1928 UDP request header (RSV RSV FRAG ATYP ADDR PORT
// DATA) and returns the payload with its destination.
func (a *association) ReadPacket(p []byte) (int, socks.Addr, error) {
	for {
		select {
		case <-a.done:
			return 0, socks.Addr{}, io.EOF
		case d := <-a.ch:
			a.touch()
			if len(d.buf) < udpHeaderLen {
				continue
			}
			if d.buf[2] != 0 {
				continue // FRAG: fragmentation is not implemented
			}
			n, addr, err := parseUDPRequest(p, d.buf)
			if err != nil {
				continue
			}
			a.peerMu.Lock()
			a.peer = d.from
			a.peerMu.Unlock()
			return n, addr, nil
		}
	}
}

// WritePacket wraps a reply payload in an RFC 1928 UDP response header and sends
// it to the client endpoint.
func (a *association) WritePacket(p []byte, addr socks.Addr) error {
	peer := a.remote()
	if peer == nil {
		return ErrUnknownClientAddress
	}
	buf := make([]byte, 0, udpHeaderLen+len(addr.Host)+7+len(p))
	buf = append(buf, 0, 0, 0)
	buf = appendAddr(buf, addr)
	buf = append(buf, p...)
	_, err := a.srv.pc.WriteTo(buf, peer)
	return err
}

func (a *association) remote() net.Addr {
	a.peerMu.Lock()
	peer := a.peer
	a.peerMu.Unlock()
	if peer != nil {
		return peer
	}
	return a.control.RemoteAddr()
}

// Close removes the association from the table and unblocks ReadPacket.
func (a *association) Close() error {
	a.once.Do(func() {
		close(a.done)
		a.srv.remove(a)
	})
	return nil
}

// controlConn ties the association to the TCP control connection: the binary
// keeps the association until the control connection goes away.
type controlConn struct {
	net.Conn
	a *association
}

func (c *controlConn) Read(p []byte) (int, error) {
	<-c.a.done
	return 0, io.EOF
}

func (c *controlConn) Close() error {
	_ = c.a.Close()
	return c.Conn.Close()
}

func hostOf(n net.Addr) string {
	switch v := n.(type) {
	case *net.TCPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	case nil:
		return ""
	}
	host, _, err := net.SplitHostPort(n.String())
	if err != nil {
		return n.String()
	}
	return host
}

func tcpConn(c net.Conn) *net.TCPConn {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc
	}
	return nil
}
