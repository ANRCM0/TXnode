// Package httpproxy is the HTTP-proxy inbound of kaze v0.5.18: CONNECT tunnels
// plus absolute-URI forwarding, with Proxy-Authorization.
//
// Evidence:
//   - REPORT.md §6.9 (error strings, `Proxy-Authorization`), §22.1 (dynamic
//     matrix: right credentials -> 200 `proto=http`; wrong / missing -> 407 with
//     `http proxy: authentication failed`; `CONNECT 127.0.0.1:19081` tunnels),
//     dyn/k-http.log (the exact log lines quoted below).
//   - notes/rev-proto-tcp.md §5.3 (Handshake @0x9659a0, 3424 B): net/http
//     ReadRequest @0x965ba0, `Proxy-Authorization` MIMEHeader.Get @0x965bd0 ->
//     httpproxy.(*Handler).User @0x965bf3, CONNECT detection by comparing
//     `CONN`+`CT`+`T` (@0x965c22), scheme compare `http` (@0x965dd6),
//     httpproxy.ParseDest @0x967040, httpproxy.originHead @0x966700 (forwards the
//     request head to the origin), httpproxy.bufConn.Read @0x9671e0 +
//     Pending @0x967340 (the readRequest leftover is spliced back onto the
//     connection after CONNECT).
//
// String VAs in the sample (sha256 723d4e20…f900):
//
//	http proxy: bad destination                 @0xf71809
//	http proxy: authentication failed           @0xf78db0
//	http proxy: request head too large          @0xf7a62e
//	http proxy: request without a server        @0xf7d84c
//	http proxy: only http:// can be proxied without CONNECT @0xf91b6e
//	HTTP/1.1 200 Connection established         @0xf82098
package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Error strings are the binary's own literals.
var (
	// ErrAuthFailed ← "http proxy: authentication failed" @0xf78db0 (observed in
	// dyn/k-http.log as `handshake failed … err="http proxy: authentication failed"`).
	ErrAuthFailed = errors.New("http proxy: authentication failed")
	// ErrNoServer ← "http proxy: request without a server" @0xf7d84c.
	ErrNoServer = errors.New("http proxy: request without a server")
	// ErrHeadTooLarge ← "http proxy: request head too large" @0xf7a62e.
	ErrHeadTooLarge = errors.New("http proxy: request head too large")
	// ErrBadDestination ← "http proxy: bad destination" @0xf71809.
	ErrBadDestination = errors.New("http proxy: bad destination")
	// ErrScheme ← "http proxy: only http:// can be proxied without CONNECT"
	// @0xf91b6e.
	ErrScheme = errors.New("http proxy: only http:// can be proxied without CONNECT")
)

// Established is the CONNECT success line (@0xf82098).
const Established = "HTTP/1.1 200 Connection established"

// Options is the package contract (REPLICATION.md §3.2).
type Options struct {
	Users  []core.User
	NoAuth bool
	// MaxHead bounds the request head. UNVERIFIED: the value (8 KiB) is our
	// choice; the binary has an explicit "request head too large" branch but no
	// recoverable immediate.
	MaxHead int
}

// Handler is the HTTP-proxy inbound.
type Handler struct {
	users   map[string]*core.User // password (secret/uuid) -> user
	noAuth  bool
	maxHead int
}

var _ core.Handler = (*Handler)(nil)

// NewHandler validates Options and builds the handler.
func NewHandler(o Options) (*Handler, error) {
	h := &Handler{
		users:   make(map[string]*core.User, len(o.Users)),
		noAuth:  o.NoAuth,
		maxHead: o.MaxHead,
	}
	if h.maxHead <= 0 {
		h.maxHead = 8 << 10
	}
	for i := range o.Users {
		if o.Users[i].UUID == "" {
			continue
		}
		h.users[o.Users[i].UUID] = &o.Users[i]
	}
	if len(h.users) == 0 {
		h.noAuth = true
	}
	return h, nil
}

// User resolves a Proxy-Authorization value to a user (httpproxy.(*Handler).User
// @0x966f00, also called by the naive handler).
//
// curl sends the RFC 7617 form `Basic base64(user:password)`; the report's probe
// table writes the same header as `alice:secret`, so a bare `user:password` is
// accepted too. The user name is ignored, exactly like the SOCKS5 inbound: only
// the password selects the account (REPORT.md §20.5).
func (h *Handler) User(header string) (*core.User, bool) {
	if header == "" {
		return nil, false
	}
	value := header
	if len(value) >= 6 && strings.EqualFold(value[:6], "basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[6:]))
		if err != nil {
			return nil, false
		}
		value = string(raw)
	}
	_, pass, ok := strings.Cut(value, ":")
	if !ok {
		// No colon: treat the whole value as the secret.
		pass = value
	}
	user, found := h.users[pass]
	if !found {
		return nil, false
	}
	return user, true
}

// Handle performs the proxy handshake and returns the session for core to relay.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	br := bufio.NewReaderSize(conn, 4096)
	head, err := readHead(br, h.maxHead)
	if err != nil {
		if errors.Is(err, ErrHeadTooLarge) {
			_ = writeError(conn, http.StatusRequestHeaderFieldsTooLarge)
			return nil, ErrHeadTooLarge
		}
		return nil, &core.Stranger{Conn: conn, Err: err}
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return nil, err
	}

	user, err := h.authenticate(conn, req)
	if err != nil {
		return nil, err
	}
	userID := 0
	if user != nil {
		userID = user.ID
	}

	if req.Method == http.MethodConnect {
		// CONNECT authority: host:port, no scheme.
		dest, err := ParseDest(req.Host)
		if err != nil {
			_ = writeError(conn, http.StatusBadRequest)
			return nil, ErrBadDestination
		}
		if _, err := io.WriteString(conn, Established+"\r\n\r\n"); err != nil {
			return nil, err
		}
		return &core.Session{
			UserID: userID,
			Dest:   dest,
			Conn:   &replayConn{Conn: conn, r: br},
			Socket: tcpConn(conn),
		}, nil
	}

	// Plain request: it must be an absolute URI of scheme http, and the head has
	// to be re-emitted in origin form for the origin server
	// (httpproxy.originHead @0x966700 forwards the head verbatim).
	if s := req.URL.Scheme; s != "" && !strings.EqualFold(s, "http") {
		_ = writeError(conn, http.StatusBadRequest)
		return nil, ErrScheme
	}
	if req.URL.Host == "" {
		_ = writeError(conn, http.StatusBadRequest)
		return nil, ErrNoServer
	}
	dest, err := ParseDest(req.URL.Host)
	if err != nil {
		_ = writeError(conn, http.StatusBadRequest)
		return nil, ErrBadDestination
	}
	origin := originHead(req)
	return &core.Session{
		UserID: userID,
		Dest:   dest,
		Conn:   &replayConn{Conn: conn, r: br, head: origin},
		Socket: tcpConn(conn),
	}, nil
}

// authenticate enforces Proxy-Authorization when users are configured.
func (h *Handler) authenticate(conn net.Conn, req *http.Request) (*core.User, error) {
	header := req.Header.Get("Proxy-Authorization")
	if header == "" && !h.noAuth {
		_ = writeProxyAuthRequired(conn)
		return nil, ErrAuthFailed
	}
	if header == "" {
		return nil, nil
	}
	user, ok := h.User(header)
	if !ok {
		_ = writeProxyAuthRequired(conn)
		return nil, ErrAuthFailed
	}
	return user, nil
}

// ParseDest converts an authority or absolute URL to a destination
// (httpproxy.ParseDest @0x967040). A missing port defaults to 80.
func ParseDest(s string) (socks.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return socks.Addr{}, ErrBadDestination
	}
	// Only an absolute URI may omit the port; a CONNECT authority must carry one
	// ("http proxy: bad destination" otherwise).
	hadScheme := false
	if i := strings.Index(s, "://"); i >= 0 {
		hadScheme = true
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return socks.Addr{}, ErrBadDestination
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		if !hadScheme {
			return socks.Addr{}, ErrBadDestination
		}
		host = strings.Trim(s, "[]")
		port = "80"
		if host == "" {
			return socks.Addr{}, ErrBadDestination
		}
	}
	if host == "" {
		return socks.Addr{}, ErrBadDestination
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return socks.Addr{}, ErrBadDestination
	}
	return socks.Addr{Host: host, Port: uint16(p)}, nil
}

// originHead re-renders a proxied request in origin form (request line plus the
// headers the origin expects). The binary implements the same rewrite in
// httpproxy.originHead @0x966700.
func originHead(req *http.Request) []byte {
	var b strings.Builder
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	b.WriteString(req.Method)
	b.WriteByte(' ')
	b.WriteString(uri)
	b.WriteString(" HTTP/1.1\r\n")
	b.WriteString("Host: ")
	b.WriteString(req.URL.Host)
	b.WriteString("\r\n")
	for k, vs := range req.Header {
		if strings.EqualFold(k, "Proxy-Authorization") || strings.EqualFold(k, "Proxy-Connection") {
			continue
		}
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// readHead reads the request head, stopping at the blank line.
func readHead(r *bufio.Reader, max int) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := r.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				if buf.Len()+len(line) > max {
					return nil, ErrHeadTooLarge
				}
				buf.Write(line)
				continue
			}
			if errors.Is(err, io.EOF) && buf.Len() > 0 {
				// Head ended without the final blank line.
				buf.Write(line)
				return buf.Bytes(), nil
			}
			return nil, err
		}
		if buf.Len()+len(line) > max {
			return nil, ErrHeadTooLarge
		}
		buf.Write(line)
		if len(line) == 2 && line[0] == '\r' || len(line) == 1 && line[0] == '\n' {
			return buf.Bytes(), nil
		}
	}
}

func writeProxyAuthRequired(w io.Writer) error {
	_, err := io.WriteString(w, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
		"Proxy-Authenticate: Basic realm=\"kaze\"\r\n"+
		"Content-Length: 0\r\nConnection: close\r\n\r\n")
	return err
}

func writeError(w io.Writer, code int) error {
	text := http.StatusText(code)
	_, err := io.WriteString(w, "HTTP/1.1 "+strconv.Itoa(code)+" "+text+"\r\n"+
		"Content-Length: 0\r\nConnection: close\r\n\r\n")
	return err
}

// replayConn is httpproxy.bufConn (@0x9671e0): it serves buffered bytes first and
// then continues on the underlying connection.
type replayConn struct {
	net.Conn
	r    *bufio.Reader
	head []byte
}

// Pending reports how many bytes were already read past the handshake
// (httpproxy.(*bufConn).Pending @0x967340).
func (c *replayConn) Pending() int {
	n := c.r.Buffered() + len(c.head)
	return n
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(p, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.r.Read(p)
}

func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func tcpConn(c net.Conn) *net.TCPConn {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc
	}
	return nil
}
