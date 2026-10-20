package tuic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"

	"github.com/ANRCM0/TX-Node/internal/dataplane/congestion/bbr"
	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// QUIC / TLS constants from (*client).Listen @0xb41260
// (notes/rev-proto-udp.md §2.5).
const (
	// maxIdleTimeout is cfg+0x28.
	maxIdleTimeout = 30 * time.Second
	// maxStreams is MaxIncomingStreams / MaxIncomingUniStreams (+0x68/+0x70).
	maxStreams = 1024
	// initialStreamWindow / maxStreamWindow are cfg+0x40 / +0x48 (2 MiB / 6 MiB).
	initialStreamWindow = 2 << 20
	maxStreamWindow     = 6 << 20
	// initialConnWindow / maxConnWindow are cfg+0x50 / +0x58 (3 MiB / 15 MiB).
	initialConnWindow = 3 << 20
	maxConnWindow     = 15 << 20
	// authReadTimeout is the 10 s deadline uniStream sets before reading.
	authReadTimeout = 10 * time.Second
	// writeTimeout is the 10 s deadline the fallback stream write sets.
	writeTimeout = 10 * time.Second
	// udpIdleTimeout is the default per-association idle timeout.
	// UNVERIFIED: cfg+0x08 UDPIdle exists but its value was not extracted; 60 s
	// is upstream TUIC's default.
	udpIdleTimeout = 60 * time.Second
)

// errAuthenticationFailed is the connection error string. Evidence:
// CloseWithError(21, "authentication failed") @0xa42060, string @0xf67f45
// length 21 (notes/rev-proto-udp.md §2.2).
const errAuthenticationFailed = "authentication failed"

// authErrorCode is the application error code, 21 (0x15).
const authErrorCode = quic.ApplicationErrorCode(21)

// Options is the contract's QUIC inbound option set plus the TUIC-specific
// knobs.
type Options struct {
	Users           []core.User
	AllowEmptyUsers bool
	TLSConfig       *tls.Config
	Congestion      string
	UpMbps          int
	DownMbps        int
	Brutal          bool
	Logger          *slog.Logger
	Relay           func(ctx context.Context, sess *core.Session) error

	// Passwords maps a UUID string to its TUIC password. When nil the password
	// is taken from User.UUID's "uuid:password" form (the panel hands the node a
	// single string; notes §2.5 records the split).
	Passwords map[string]string
	// TokenFunc replaces the token derivation. cfg.Serve (+0x10) is a callback
	// in the sample; its body was not resolved (notes §7 item 1), so the default
	// here is sha256(uuidString || password).
	TokenFunc func(uuid string, password []byte, n int) ([]byte, error)
	// UDPIdleTimeout overrides the association idle timeout.
	UDPIdleTimeout time.Duration
}

// user mirrors tuic.user (size 0x20): +0x00 id int64, +0x08 password []byte.
type user struct {
	ID       int64
	Password []byte
}

// Server is the TUIC v5 inbound.
type Server struct {
	opts Options
	log  *slog.Logger

	usersMu            sync.RWMutex
	credentialValidity map[[16]byte]*atomic.Bool
	users              map[[16]byte]user

	pc net.PacketConn
	tr *quic.Transport
	ln *quic.Listener

	// mu guards the listener/transport fields: Serve publishes them while
	// Close may run concurrently (accept loop shutdown, node reload).
	mu sync.Mutex

	closeOnce sync.Once
	closed    chan struct{}
}

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

// NewServer validates the options.
func NewServer(o Options) (*Server, error) {
	if o.TLSConfig == nil {
		return nil, errors.New("tuic: a TLS config is required")
	}
	if len(o.Users) == 0 && !o.AllowEmptyUsers {
		return nil, errors.New("tuic: no users configured")
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{opts: o, log: log, users: make(map[[16]byte]user), closed: make(chan struct{})}
	s.SetUsers(o.Users)
	if len(s.users) == 0 && !(o.AllowEmptyUsers && len(o.Users) == 0) {
		return nil, errors.New("tuic: no user has a usable UUID")
	}
	return s, nil
}

// SetUsers rebuilds the UUID table. Evidence: (*Server).SetUsers @0xb40f80 uses
// runtime.makemap plus atomic.StorePointer.
func (s *Server) SetUsers(users []core.User) {
	next := make(map[[16]byte]user, len(users))
	for _, u := range users {
		uuidStr, password := splitUser(u.UUID)
		if pw, ok := s.opts.Passwords[uuidStr]; ok {
			password = []byte(pw)
		}
		id, err := parseUUID(uuidStr)
		if err != nil {
			s.log.Debug("tuic: skipping user with a bad uuid", "uuid", uuidStr, "error", err)
			continue
		}
		next[id] = user{ID: int64(u.ID), Password: password}
	}
	s.usersMu.Lock()
	valid := make(map[[16]byte]*atomic.Bool, len(next))
	for uuid, u := range next {
		if old, ok := s.users[uuid]; ok && old.ID == u.ID && bytes.Equal(old.Password, u.Password) && s.credentialValidity[uuid] != nil {
			valid[uuid] = s.credentialValidity[uuid]
		} else {
			v := new(atomic.Bool)
			v.Store(true)
			valid[uuid] = v
		}
	}
	for uuid, v := range s.credentialValidity {
		if valid[uuid] != v {
			v.Store(false)
		}
	}
	s.users = next
	s.credentialValidity = valid
	s.usersMu.Unlock()
}

// splitUser splits "uuid:password". A value without ':' is a bare UUID whose
// password is empty. Evidence for the single-string form: notes §2.5 ("推断面板
// 下发 uuid:password 单串").
func splitUser(v string) (string, []byte) {
	for i := len(v) - 1; i >= 0; i-- {
		if v[i] == ':' {
			return v[:i], []byte(v[i+1:])
		}
	}
	return v, nil
}

// parseUUID accepts the canonical 8-4-4-4-12 form and the 32-hex-digit form.
func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	hexOnly := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-':
			continue
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F':
			hexOnly = append(hexOnly, s[i])
		default:
			return out, fmt.Errorf("invalid uuid character %q", s[i])
		}
	}
	if len(hexOnly) != 32 {
		return out, fmt.Errorf("uuid has %d hex digits, want 32", len(hexOnly))
	}
	for i := 0; i < 16; i++ {
		hi, err := hexNibble(hexOnly[i*2])
		if err != nil {
			return out, err
		}
		lo, err := hexNibble(hexOnly[i*2+1])
		if err != nil {
			return out, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex digit %q", c)
}

func formatUUID(id [16]byte) string {
	const hexdigits = "0123456789abcdef"
	buf := make([]byte, 0, 36)
	for i, b := range id {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			buf = append(buf, '-')
		}
		buf = append(buf, hexdigits[b>>4], hexdigits[b&0xf])
	}
	return string(buf)
}

// tlsConfig pins TLS 1.3 and installs the default ALPN list only when the
// caller left NextProtos empty. Evidence: MinVersion=MaxVersion=0x0304 at
// 0xb4143e and the ["h3","h2","http/1.1"] defaults at 0xf570c8/0xf57084/0xf59d28
// (notes §2.5).
func (s *Server) tlsConfig() *tls.Config {
	cfg := s.opts.TLSConfig.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"h3", "h2", "http/1.1"}
	}
	return cfg
}

func (s *Server) quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 maxIdleTimeout,
		MaxIncomingStreams:             maxStreams,
		MaxIncomingUniStreams:          maxStreams,
		InitialStreamReceiveWindow:     initialStreamWindow,
		MaxStreamReceiveWindow:         maxStreamWindow,
		InitialConnectionReceiveWindow: initialConnWindow,
		MaxConnectionReceiveWindow:     maxConnWindow,
		EnableDatagrams:                true,
		// Allow0RTT is never written and Listen (not ListenEarly) is used.
		Allow0RTT: false,
	}
}

// Serve runs on an already bound UDP socket and takes ownership of it.
func (s *Server) Serve(pc net.PacketConn) error {
	if pc == nil {
		return errors.New("tuic: nil packet conn")
	}
	s.pc = pc
	tr := &quic.Transport{Conn: pc}
	ln, err := tr.Listen(s.tlsConfig(), s.quicConfig())
	if err != nil {
		return fmt.Errorf("tuic: listening: %w", err)
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

// Close stops the listener and transport.
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

// Addr reports the listener address once Serve is running.
func (s *Server) Addr() net.Addr {
	_, ln := s.listeners()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

// client mirrors the per-connection struct the report reconstructs: +0x00
// Server, +0x08 conn, +0x10 authDone, +0x18 sync.Once, +0x28 user id,
// +0x30 mutex, +0x38 map[uint16]*udpSession.
type client struct {
	srv  *Server
	conn *quic.Conn

	authDone chan struct{}
	authOnce sync.Once

	mu        sync.Mutex
	authed    bool
	userID    int64
	userValid *atomic.Bool
	sessions  map[uint16]*udpSession

	ctx    context.Context
	cancel context.CancelFunc
}

func (s *Server) serveConn(conn *quic.Conn) {
	ctx, cancel := context.WithCancel(conn.Context())
	c := &client{
		srv:      s,
		conn:     conn,
		authDone: make(chan struct{}),
		sessions: make(map[uint16]*udpSession),
		ctx:      ctx,
		cancel:   cancel,
	}
	go c.acceptUniStreams()
	go c.acceptStreams()
	go c.acceptDatagrams()
	go c.sweepLoop()
	<-ctx.Done()
	c.closeAll()
}

// acceptDatagrams serves the QUIC DATAGRAM half of the packet transport. The
// frame layout is identical to the unidirectional-stream frames
// (docs: sing-quic/tuic packet.go pack()); a client picks datagrams when the
// server advertised them, which quicConfig always does.
func (c *client) acceptDatagrams() {
	for {
		raw, err := c.conn.ReceiveDatagram(c.ctx)
		if err != nil {
			return
		}
		if len(raw) < frameHeaderLen {
			continue
		}
		if raw[0] != version || raw[1] != cmdPacket {
			continue
		}
		// The datagram body is the frame without the 2-byte (version, command)
		// stream prefix: the same fields as readFrameFromStream.
		f, err := parsePacketBody(raw[2:])
		if err != nil {
			continue
		}
		if !c.tryAuthed() {
			continue
		}
		c.deliverPacket(f)
	}
}

// waitAuth blocks until authentication succeeded or the connection ended. The
// sample's waitAuth @0xb41e40 is a two-case selectgo over conn.Context().Done()
// and c.authDone.
func (c *client) waitAuth(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-c.authDone:
		return c.isAuthed()
	}
}

func (c *client) isAuthed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authed && c.userValid != nil && c.userValid.Load()
}

func (c *client) authValid() bool { return c.isAuthed() }

func (c *client) failAuth() {
	// Same call the binary makes for every auth failure.
	_ = c.conn.CloseWithError(authErrorCode, errAuthenticationFailed)
}

// acceptUniStreams serves every unidirectional stream on the connection.
func (c *client) acceptUniStreams() {
	for {
		str, err := c.conn.AcceptUniStream(c.ctx)
		if err != nil {
			return
		}
		go c.uniStream(str)
	}
}

// uniStream demultiplexes the 2-byte (version, command) prefix.
func (c *client) uniStream(str *quic.ReceiveStream) {
	_ = str.SetReadDeadline(time.Now().Add(authReadTimeout))
	var hdr [2]byte
	if _, err := io.ReadFull(str, hdr[:]); err != nil {
		return
	}
	if hdr[0] != version {
		// Any version but 5 closes the stream (0xb41fc4).
		str.CancelRead(quic.StreamErrorCode(0))
		return
	}
	switch hdr[1] {
	case cmdAuthenticate:
		c.authenticate(str)
	case cmdPacket:
		c.packet(str)
	case cmdDissociate:
		c.dissociate(str)
	default:
		c.srv.log.Debug("tuic: unknown uni command", "cmd", hdr[1])
		// cmd == 1 does not exist on a uni stream.
		str.CancelRead(quic.StreamErrorCode(0))
	}
}

// authenticate handles the 48-byte Authenticate body.
func (c *client) authenticate(str *quic.ReceiveStream) {
	buf := make([]byte, authLen)
	if _, err := io.ReadFull(str, buf); err != nil {
		return
	}
	var uuid [16]byte
	copy(uuid[:], buf[:uuidLen])
	token := buf[uuidLen:authLen]

	c.srv.usersMu.RLock()
	u, ok := c.srv.users[uuid]
	valid := c.srv.credentialValidity[uuid]
	c.srv.usersMu.RUnlock()
	if !ok {
		c.failAuth()
		return
	}
	// TUIC 5.x derives the token from the TLS exporter:
	// ExportKeyingMaterial(label=uuid bytes, context=password, 32). Older
	// clients (and the sampled build) use sha256(uuid string || password).
	authed := false
	if state := c.conn.ConnectionState(); state.TLS.Version != 0 {
		if exp, err := state.TLS.ExportKeyingMaterial(string(uuid[:]), u.Password, tokenLen); err == nil &&
			subtle.ConstantTimeCompare(exp, token) == 1 {
			authed = true
		}
	}
	if !authed {
		expect, err := c.srv.expectedToken(uuid, u)
		if err == nil && len(expect) == tokenLen && subtle.ConstantTimeCompare(expect, token) == 1 {
			authed = true
		}
	}
	if !authed {
		// Constant-time compare, as in the binary's 0xb4246b loop.
		c.failAuth()
		return
	}
	c.authOnce.Do(func() {
		c.mu.Lock()
		c.authed = true
		c.userID = u.ID
		c.userValid = valid
		c.mu.Unlock()
		// Congestion choice happens once, after authentication
		// (node.applyQUIC.func1 @0xc9af80 only passes BBR for "bbr").
		applyCongestion(c.conn, c.srv.opts.Congestion)
		close(c.authDone)
	})
	// Keep the stream open: the client closes it once it sees the connection
	// stays alive. Draining keeps flow-control credit moving.
	go io.Copy(io.Discard, str)
}

// udpIdle is the association idle timeout (cfg+0x08; value UNVERIFIED).
func (s *Server) udpIdle() time.Duration {
	if s.opts.UDPIdleTimeout > 0 {
		return s.opts.UDPIdleTimeout
	}
	return udpIdleTimeout
}

// expectedToken derives the 32-byte token the client must present.
func (s *Server) expectedToken(uuid [16]byte, u user) ([]byte, error) {
	if s.opts.TokenFunc != nil {
		return s.opts.TokenFunc(formatUUID(uuid), u.Password, tokenLen)
	}
	h := sha256.New()
	h.Write([]byte(formatUUID(uuid)))
	h.Write(u.Password)
	return h.Sum(nil), nil
}

// packet handles a client Packet command. The body continues with the 8-byte
// frame header, the address and the payload. One uni stream may carry several
// frames; the loop stops at EOF.
func (c *client) packet(str *quic.ReceiveStream) {
	if !c.tryAuthed() {
		str.CancelRead(quic.StreamErrorCode(0))
		return
	}
	for {
		f, err := readFrameFromStream(str)
		if err != nil {
			return
		}
		f.stream = true
		c.deliverPacket(f)
	}
}

func (c *client) tryAuthed() bool {
	if c.isAuthed() {
		return true
	}
	// A short grace period: the auth stream and the packet stream are separate
	// streams and may race on the wire.
	ctx, cancel := context.WithTimeout(c.ctx, authReadTimeout)
	defer cancel()
	return c.waitAuth(ctx)
}

// dissociate closes an association: 2-byte big-endian assocID (0xb42009).
func (c *client) dissociate(str *quic.ReceiveStream) {
	var buf [2]byte
	if _, err := io.ReadFull(str, buf[:]); err != nil {
		return
	}
	id := binary.BigEndian.Uint16(buf[:])
	c.mu.Lock()
	sess := c.sessions[id]
	delete(c.sessions, id)
	c.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
}

// acceptStreams serves bidirectional streams, which are CONNECT requests.
func (c *client) acceptStreams() {
	for {
		str, err := c.conn.AcceptStream(c.ctx)
		if err != nil {
			return
		}
		go c.connect(str)
	}
}

// connect reads the CONNECT header and relays the stream to its destination.
func (c *client) connect(str *quic.Stream) {
	_ = str.SetReadDeadline(time.Now().Add(authReadTimeout))
	var hdr [2]byte
	if _, err := io.ReadFull(str, hdr[:]); err != nil {
		return
	}
	if hdr[0] != version || hdr[1] != cmdConnect {
		str.CancelWrite(quic.StreamErrorCode(0))
		return
	}
	dest, err := readAddrFromStream(str)
	if err != nil {
		str.CancelWrite(quic.StreamErrorCode(0))
		return
	}
	_ = str.SetReadDeadline(time.Time{})
	if !c.tryAuthed() {
		str.CancelWrite(quic.StreamErrorCode(0))
		return
	}
	sess := &core.Session{
		UserID:    int(c.userIDLocked()),
		AuthValid: c.authValid,
		SourceIP:  c.sourceIP(),
		Dest:      dest,
		Conn:      &streamConn{Stream: str, conn: c.conn},
	}
	if relay := c.srv.opts.Relay; relay != nil {
		_ = relay(c.ctx, sess)
		return
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(c.ctx, "tcp", dest.String())
	if err != nil {
		str.CancelWrite(quic.StreamErrorCode(0))
		return
	}
	defer conn.Close()
	pipeStream(c.ctx, sess.Conn, conn)
}

func (c *client) userIDLocked() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.userID
}

// streamConn adapts *quic.Stream to net.Conn.
type streamConn struct {
	Stream *quic.Stream
	conn   *quic.Conn
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.Stream.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.Stream.Write(p) }
func (c *streamConn) Close() error {
	c.Stream.CancelRead(0)
	c.Stream.CancelWrite(0)
	return nil
}
func (c *streamConn) CloseWrite() error    { return c.Stream.Close() }
func (c *streamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *streamConn) SetDeadline(t time.Time) error {
	if err := c.Stream.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Stream.SetWriteDeadline(t)
}
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.Stream.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.Stream.SetWriteDeadline(t) }

// readFrameFromStream reads one Packet frame from a uni stream.
func readFrameFromStream(r io.Reader) (*frame, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	f := &frame{
		assocID:   binary.BigEndian.Uint16(hdr[0:2]),
		pktID:     binary.BigEndian.Uint16(hdr[2:4]),
		fragTotal: hdr[4],
		fragID:    hdr[5],
	}
	if f.fragTotal > 1 && f.fragID >= f.fragTotal || f.fragTotal <= 1 && f.fragID != 0 {
		return nil, errors.New("tuic: invalid fragment index")
	}
	payloadLen := int(binary.BigEndian.Uint16(hdr[6:8]))
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return nil, err
	}
	if typeBuf[0] != addrNone {
		rest, err := readAddrRest(r, typeBuf[0])
		if err != nil {
			return nil, err
		}
		f.addr = rest
		f.hasAddr = true
	}
	if payloadLen > 0 {
		f.payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// readAddrFromStream reads a TUIC address (type byte first).
func readAddrFromStream(r io.Reader) (socks.Addr, error) {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return socks.Addr{}, err
	}
	return readAddrRest(r, typeBuf[0])
}

// readAddrRest reads the body of an address of the given type.
func readAddrRest(r io.Reader, typ byte) (socks.Addr, error) {
	switch typ {
	case addrDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return socks.Addr{}, err
		}
		buf := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return socks.Addr{}, err
		}
		return socks.Addr{Host: string(buf[:l[0]]), Port: binary.BigEndian.Uint16(buf[l[0]:])}, nil
	case addrIPv4:
		var buf [6]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return socks.Addr{}, err
		}
		return socks.Addr{Host: net.IP(buf[:4]).String(), Port: binary.BigEndian.Uint16(buf[4:])}, nil
	case addrIPv6:
		var buf [18]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return socks.Addr{}, err
		}
		return socks.Addr{Host: net.IP(buf[:16]).String(), Port: binary.BigEndian.Uint16(buf[16:])}, nil
	}
	return socks.Addr{}, fmt.Errorf("tuic: unknown address type %d", typ)
}

// pipeStream is the fallback relay when Options.Relay is nil.
func pipeStream(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = a.Close()
	_ = b.Close()
}

// applyCongestion installs BBR when the operator asked for "bbr" (cfg+0x18).
// Evidence: node.applyQUIC.func1 @0xc9af80 compares the congestion string and
// passes BBR=true only for "bbr" (notes §2.5).
func applyCongestion(conn *quic.Conn, congestion string) {
	if congestion == "bbr" {
		bbr.Use(conn)
	}
}
