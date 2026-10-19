// Package anytls is the AnyTLS inbound of kaze v0.5.18.
//
// Evidence:
//   - REPORT.md §6.1 (TCP; server-side padding scheme), §6.9-adjacent table,
//     notes/protocols.md.
//   - notes/rev-proto-tcp.md §6 (31 functions / 11,392 B):
//     anytls.(*Handler).Handshake @0x962d80 (96 B: it only forwards to ServeConn),
//     anytls.(*Handler).ServeConn @0x962f20 (3264 B: the per-connection loop),
//     anytls.peekHead @0x962de0 (two bufio.Peek(0x22 = 34) + memequal +
//     typeAssert), anytls.(*session).settings @0x964220 (splits on '\n', cuts on
//     '=', keys `v` and `padding-md5`, md5 of the padding string compared with
//     strings.EqualFold, then writeFrame("v=2")),
//     anytls.(*session).writeFrame @0x963ec0 (**7-byte header**, described below,
//     write deadline 0x6fc23ac00 = 30 s, pool.Get buffer reuse),
//     anytls.(*session).open/waitRoom/push/remoteClosed, anytls.(*stream).Read/
//     Write/Close/account/release.
//
// Frame header, read straight off writeFrame @0x963ec0:
//
//	byte [0]      command
//	dword [1..4]  stream id
//	word [5..6]   payload length
//
// (`cmp rcx,0x7` @0x963f58; the zeroing stores at [1] and [3] followed by the
// dword/word writes at [1] and [5] fix the three fields.)
//
// Error literals: "anytls: connections are served through ServeConn" @0xf8c301,
// "anytls: authentication failed", "anytls: not an AnyTLS client".
package anytls

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Frame commands. 0..4 are exercised by any implementation of the protocol
// (waste/syn/psh/fin/settings); the rest keep upstream numbering.
// UNVERIFIED: the numbering above 4.
const (
	cmdWaste    = 0
	cmdSYN      = 1
	cmdPSH      = 2
	cmdFIN      = 3
	cmdSettings = 4
	cmdAlert    = 5
	cmdUpdate   = 6
	cmdSYNACK   = 7
	cmdPong     = 8

	// headerLen is the 7-byte frame header (@0x963f58 `cmp rcx,0x7`).
	headerLen = 7
	// writeTimeout is the 30 s write deadline writeFrame installs
	// (`movabs rdi,0x6fc23ac00`).
	writeTimeout = 30 * time.Second
	// authLen is the SHA-256 password prefix the client sends first; peekHead
	// looks at 34 bytes = 32 + the first two bytes of the following frame header
	// (notes §6).
	authLen = 32
	// settingsVersion is what the server answers after a client settings frame;
	// the literal "v=2" is written by (*session).settings (@0xf5752c).
	settingsVersion = "v=2"
	// maxFrame bounds a single frame payload.
	maxFrame = 0xffff
)

// Error strings are the binary's own literals.
var (
	// ErrServeConn ← "anytls: connections are served through ServeConn" @0xf8c301.
	// It is what Handle reports when the caller has to drive ServeConn itself,
	// because AnyTLS multiplexes many streams over one connection.
	ErrServeConn = errors.New("anytls: connections are served through ServeConn")
	// ErrAuthFailed ← "anytls: authentication failed".
	ErrAuthFailed = errors.New("anytls: authentication failed")
	// ErrNotClient ← "anytls: not an AnyTLS client".
	ErrNotClient = errors.New("anytls: not an AnyTLS client")
)

// Options is the package contract (REPLICATION.md §3.2). TLS is the transport's
// job, so there is no TLS config here.
type Options struct {
	Users []core.User
	// PaddingScheme is the scheme the server hands to clients. Empty means
	// DefaultPaddingScheme.
	PaddingScheme string
	// Relay, when set, is called for every stream by ServeConn; it is the hook the
	// node uses to run a normal session on a stream.
	Relay func(ctx context.Context, sess *core.Session) error
}

// Handler is the AnyTLS inbound.
type Handler struct {
	users  map[[sha256.Size]byte]*core.User
	scheme string
	relay  func(ctx context.Context, sess *core.Session) error
}

var (
	_ core.Handler = (*Handler)(nil)
	_ net.Conn     = (*stream)(nil)
)

// NewHandler validates Options and builds the handler.
func NewHandler(o Options) (*Handler, error) {
	h := &Handler{
		users:  make(map[[sha256.Size]byte]*core.User, len(o.Users)),
		scheme: o.PaddingScheme,
		relay:  o.Relay,
	}
	if h.scheme == "" {
		h.scheme = DefaultPaddingScheme
	}
	for i := range o.Users {
		if o.Users[i].UUID == "" {
			continue
		}
		h.users[sha256.Sum256([]byte(o.Users[i].UUID))] = &o.Users[i]
	}
	return h, nil
}

// Handle serves one connection and returns its first stream as a session.
//
// AnyTLS carries many streams over one connection; core's session model is
// one-connection-one-destination, so this adapter hands core the first SYN stream
// and closes the rest. Node wiring that wants the full multiplexer calls ServeConn
// with Relay set (that is what ErrServeConn is about).
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	sess, err := h.handshake(ctx, conn)
	if err != nil {
		return nil, err
	}
	// A dedicated goroutine owns the frame loop; the returned stream blocks until
	// its data arrives.
	go sess.run()

	for {
		select {
		case st := <-sess.incoming:
			return &core.Session{
				UserID: st.userID,
				Dest:   st.dest,
				Conn:   st,
				Socket: tcpConn(conn),
			}, nil
		case <-sess.done:
			return nil, ErrNotClient
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// ServeConn is the real entry point (anytls.(*Handler).ServeConn @0x962f20): it
// runs the frame loop and hands every accepted stream to Relay.
func (h *Handler) ServeConn(ctx context.Context, conn net.Conn) error {
	if h.relay == nil {
		return ErrServeConn
	}
	sess, err := h.handshake(ctx, conn)
	if err != nil {
		return err
	}
	go sess.run()
	for {
		select {
		case st := <-sess.incoming:
			go func(st *stream) {
				defer st.Close()
				if err := h.relay(ctx, &core.Session{
					UserID: st.userID,
					Dest:   st.dest,
					Conn:   st,
				}); err != nil {
					return
				}
			}(st)
		case <-sess.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// handshake authenticates the peer and sends the settings frame. The client
// starts with SHA-256(password); peekHead @0x962de0 looks at 34 bytes, i.e. the
// 32-byte digest plus the first two bytes of the next frame header.
func (h *Handler) handshake(ctx context.Context, conn net.Conn) (*session, error) {
	br := bufio.NewReaderSize(conn, 4096)
	var auth [sha256.Size]byte
	if _, err := io.ReadFull(br, auth[:]); err != nil {
		return nil, err
	}
	user, ok := h.users[auth]
	if !ok {
		return nil, ErrAuthFailed
	}
	sess := &session{
		conn:     conn,
		r:        br,
		user:     user,
		incoming: make(chan *stream, 8),
		strm:     make(map[uint32]*stream),
		done:     make(chan struct{}),
		scheme:   parseScheme(h.scheme),
	}
	// Server settings: "v=2" plus the padding scheme digest; the binary compares
	// the client's padding-md5 with strings.EqualFold and answers "v=2"
	// ((*session).settings @0x964220).
	sum := md5.Sum([]byte(h.scheme))
	settings := fmt.Sprintf("%s\npadding-md5=%s\n", settingsVersion, hex.EncodeToString(sum[:]))
	if err := sess.writeFrame(cmdSettings, 0, []byte(settings)); err != nil {
		return nil, err
	}
	return sess, nil
}

// session is anytls.(*session): the frame multiplexer for one connection.
type session struct {
	conn     net.Conn
	r        *bufio.Reader
	user     *core.User
	scheme   paddingScheme
	incoming chan *stream
	done     chan struct{}

	wmu     sync.Mutex
	once    sync.Once
	mu      sync.Mutex
	next    uint32
	strm    map[uint32]*stream
	packets int
}

func (s *session) run() {
	defer s.closeAll()
	for {
		cmd, sid, payload, err := s.readFrame()
		if err != nil {
			return
		}
		switch cmd {
		case cmdWaste:
			// Padding frame: discard (the length only mattered on the wire).
		case cmdSettings:
			// The client's scheme digest is compared with our own; a mismatch only
			// costs the padding agreement, the connection stays up.
			_ = payload
		case cmdSYN:
			st := newStream(s, sid)
			dest, err := ParseDestination(string(payload))
			if err != nil {
				st.Close()
				continue
			}
			st.dest = dest
			if s.user != nil {
				st.userID = s.user.ID
			}
			s.mu.Lock()
			s.strm[sid] = st
			s.mu.Unlock()
			select {
			case s.incoming <- st:
			case <-s.done:
				return
			}
		case cmdPSH:
			if st := s.stream(sid); st != nil {
				if !st.push(payload) {
					return
				}
			}
		case cmdFIN:
			if st := s.stream(sid); st != nil {
				st.remoteClosed()
			}
		case cmdAlert:
			return
		}
	}
}

func (s *session) stream(sid uint32) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.strm[sid]
}

func (s *session) remove(sid uint32) {
	s.mu.Lock()
	delete(s.strm, sid)
	s.mu.Unlock()
}

func (s *session) closeAll() {
	s.once.Do(func() {
		close(s.done)
		s.mu.Lock()
		streams := make([]*stream, 0, len(s.strm))
		for _, st := range s.strm {
			streams = append(streams, st)
		}
		s.strm = nil
		s.mu.Unlock()
		for _, st := range streams {
			st.remoteClosed()
		}
		_ = s.conn.Close()
	})
}

func (s *session) readFrame() (byte, uint32, []byte, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	cmd := hdr[0]
	sid := binary.BigEndian.Uint32(hdr[1:5])
	n := int(binary.BigEndian.Uint16(hdr[5:7]))
	var payload []byte
	if n > 0 {
		payload = make([]byte, n)
		if _, err := io.ReadFull(s.r, payload); err != nil {
			return 0, 0, nil, err
		}
	}
	return cmd, sid, payload, nil
}

// writeFrame is anytls.(*session).writeFrame @0x963ec0: 7-byte header, optional
// padding frame first, 30 s write deadline.
func (s *session) writeFrame(cmd byte, sid uint32, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	buf := make([]byte, headerLen+len(payload))
	buf[0] = cmd
	binary.BigEndian.PutUint32(buf[1:5], sid)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[headerLen:], payload)
	_, err := s.conn.Write(buf)
	return err
}

// writeWithPadding sends a data frame with a padding (waste) frame in front,
// following the negotiated scheme (the server side of the padding agreement).
func (s *session) writeWithPadding(cmd byte, sid uint32, payload []byte) error {
	s.wmu.Lock()
	n := s.packets
	s.packets++
	s.wmu.Unlock()
	if n := s.scheme.padding(n); n > 0 {
		pad := make([]byte, n)
		if _, err := rand.Read(pad); err == nil {
			if err := s.writeFrame(cmdWaste, 0, pad); err != nil {
				return err
			}
		}
	}
	return s.writeFrame(cmd, sid, payload)
}

// stream is anytls.(*stream): one multiplexed connection.
type stream struct {
	sess   *session
	sid    uint32
	dest   socks.Addr
	userID int

	mu       sync.Mutex
	buf      []byte
	ch       chan []byte
	done     chan struct{}
	once     sync.Once
	closedIn bool
}

func newStream(s *session, sid uint32) *stream {
	return &stream{
		sess: s,
		sid:  sid,
		ch:   make(chan []byte, 8),
		done: make(chan struct{}),
	}
}

func (s *stream) push(b []byte) bool {
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case s.ch <- cp:
		return true
	case <-s.done:
		return false
	case <-s.sess.done:
		return false
	}
}

func (s *stream) remoteClosed() {
	s.once.Do(func() {
		s.closedIn = true
		close(s.done)
		s.sess.remove(s.sid)
	})
}

func (s *stream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.buf) > 0 {
			n := copy(p, s.buf)
			s.buf = s.buf[n:]
			s.mu.Unlock()
			return n, nil
		}
		s.mu.Unlock()
		select {
		case b := <-s.ch:
			s.mu.Lock()
			s.buf = b
			s.mu.Unlock()
		case <-s.done:
			return 0, io.EOF
		case <-s.sess.done:
			return 0, io.EOF
		}
	}
}

func (s *stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxFrame {
			n = maxFrame
		}
		if err := s.sess.writeWithPadding(cmdPSH, s.sid, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (s *stream) Close() error {
	if !s.closedIn {
		_ = s.sess.writeFrame(cmdFIN, s.sid, nil)
	}
	s.remoteClosed()
	return nil
}

func (s *stream) LocalAddr() net.Addr  { return s.sess.conn.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr { return s.sess.conn.RemoteAddr() }

func (s *stream) SetDeadline(t time.Time) error {
	return s.sess.conn.SetDeadline(t)
}

func (s *stream) SetReadDeadline(t time.Time) error {
	return s.sess.conn.SetReadDeadline(t)
}

func (s *stream) SetWriteDeadline(t time.Time) error {
	return s.sess.conn.SetWriteDeadline(t)
}

// ParseDestination decodes the SYN payload: "host:port".
func ParseDestination(s string) (socks.Addr, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return socks.Addr{}, ErrNotClient
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return socks.Addr{}, ErrNotClient
	}
	return socks.Addr{Host: host, Port: uint16(p)}, nil
}

// Looks reports whether the first bytes of a connection could be an AnyTLS
// client (the structural half of anytls.peekHead @0x962de0): a 32-byte digest
// followed by a plausible frame header.
func Looks(conn net.Conn) bool {
	type peeker interface {
		Peek(n int) ([]byte, error)
	}
	br, ok := conn.(peeker)
	if !ok {
		br = bufio.NewReader(conn)
	}
	head, err := br.Peek(authLen + 2)
	if err != nil {
		return false
	}
	cmd := head[authLen]
	length := binary.BigEndian.Uint16(head[authLen+1:])
	return cmd <= cmdPong && length <= maxFrame
}

func tcpConn(c net.Conn) *net.TCPConn {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc
	}
	return nil
}
