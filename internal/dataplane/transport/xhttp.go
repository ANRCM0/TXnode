package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// Server side of XHTTP. Evidence: REPORT.md §7.3 (kebab-case options, modes
// auto/stream-one/stream-up/packet-up, query padding x_padding=N*'X',
// download-settings split, h3 refused) and notes/rev-transport.md §1.4.
// The sample's server is (*xhttpServer).ServeHTTP / session / notFound
// (0xacdde0 / 0xacd3a0 / 0xacdc60).

// XHTTP option keys, all kebab-case (Xray compatible).
const (
	xhttpModeKey       = "mode"
	xhttpPaddingKey    = "x-padding-bytes"
	xhttpMaxPostKey    = "sc-max-each-post-bytes"
	xhttpMinInterval   = "sc-min-posts-interval-ms"
	xhttpMaxBuffered   = "sc-max-buffered-posts"
	xhttpReuseMaxConc  = "max-concurrency"
	xhttpReuseMaxConns = "max-connections"
	xhttpSessionPlace  = "session-placement"
	xhttpSeqPlace      = "seq-placement"
	xhttpUplinkPlace   = "uplink-data-placement"
	xhttpUplinkMethod  = "uplink-http-method"
	xhttpPaddingObfs   = "x-padding-obfs-mode"
	xhttpDownloadSet   = "download-settings"
)

// xhttp modes.
const (
	xhttpAuto     = "auto"
	xhttpStream1  = "stream-one"
	xhttpStreamUp = "stream-up"
	xhttpPacketUp = "packet-up"
)

// xhttpOptions is the parsed option set the server (and the client) needs.
type xhttpOptions struct {
	mode              string
	padMin, padMax    int
	maxEachPostBytes  int
	minPostIntervalMs int
	maxBufferedPosts  int
}

// xhttpExtraIssues rejects the Xray options kaze does not implement. The
// strings are the sample's (notes/rev-transport.md §1.4; the panel package
// has the same helper as panel.xhttpExtraIssues).
func xhttpExtraIssues(m map[string]any) []string {
	var out []string
	get := func(k string) (string, bool) {
		v, ok := m[k]
		if !ok || v == nil {
			return "", false
		}
		return strings.TrimSpace(fmt.Sprint(v)), true
	}
	if _, ok := get(xhttpPaddingObfs); ok {
		out = append(out, "x-padding-obfs-mode is not supported: padding is sent the standard way, as a Referer query; remove it here and on the server")
	}
	for _, key := range []string{xhttpSessionPlace, xhttpSeqPlace} {
		if v, ok := get(key); ok {
			out = append(out, fmt.Sprintf("%s %q is not supported: the session and sequence go in the path", key, v))
		}
	}
	if v, ok := get(xhttpUplinkPlace); ok {
		out = append(out, fmt.Sprintf("uplink-data-placement %q is not supported: uploads go in the request body", v))
	}
	if v, ok := get(xhttpUplinkMethod); ok {
		if !isHTTPMethod(v) {
			out = append(out, fmt.Sprintf("uplink-http-method %q is not an HTTP method", v))
		}
	}
	return out
}

func isHTTPMethod(s string) bool {
	switch strings.ToUpper(s) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodHead, http.MethodDelete:
		return true
	}
	return false
}

// parseXHTTPOptions validates the option map. Errors use the sample's wording.
func parseXHTTPOptions(m map[string]any) (xhttpOptions, error) {
	o := xhttpOptions{
		mode:             xhttpAuto,
		padMin:           100,
		padMax:           1000,
		maxEachPostBytes: 1 << 20,
		maxBufferedPosts: 32,
	}
	if v, ok := m[xhttpModeKey]; ok && v != nil {
		o.mode = strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
	}
	switch o.mode {
	case xhttpAuto, xhttpStream1, xhttpStreamUp, xhttpPacketUp:
	case "":
		o.mode = xhttpAuto
	default:
		return o, fmt.Errorf("mode %q is not one of auto, stream-one, stream-up, packet-up", o.mode)
	}
	if v, ok := m[xhttpPaddingKey]; ok && v != nil {
		min, max, err := parseIntRange(fmt.Sprint(v))
		if err != nil {
			return o, fmt.Errorf("%q is not a number or a range like 100-1000", fmt.Sprint(v))
		}
		o.padMin, o.padMax = min, max
	}
	if v, ok := m[xhttpMaxPostKey]; ok && v != nil {
		min, _, err := parseIntRange(fmt.Sprint(v))
		if err != nil {
			return o, fmt.Errorf("%q is not a number or a range like 100-1000", fmt.Sprint(v))
		}
		if min > 1<<20 {
			return o, fmt.Errorf("XHTTP scMaxEachPostBytes %d is above kaze's limit of %d; larger uploads are refused", min, 1<<20)
		}
		o.maxEachPostBytes = min
	}
	if v, ok := m[xhttpMinInterval]; ok && v != nil {
		min, _, err := parseIntRange(fmt.Sprint(v))
		if err == nil {
			o.minPostIntervalMs = min
		}
	}
	if v, ok := m[xhttpMaxBuffered]; ok && v != nil {
		min, _, err := parseIntRange(fmt.Sprint(v))
		if err == nil {
			if min > 128 {
				return o, fmt.Errorf("XHTTP scMaxBufferedPosts %d is above kaze's limit of %d", min, 128)
			}
			o.maxBufferedPosts = min
		}
	}
	if _, a := m[xhttpReuseMaxConc]; a {
		if _, b := m[xhttpReuseMaxConns]; b {
			return o, errors.New("reuse-settings: max-concurrency and max-connections cannot both be set")
		}
	}
	if _, ok := m[xhttpDownloadSet]; ok {
		return o, errors.New("download-settings (a second server for the download) is not supported here; remove it")
	}
	if issues := xhttpExtraIssues(m); len(issues) > 0 {
		return o, errors.New(strings.Join(issues, "; "))
	}
	return o, nil
}

func parseIntRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '-'); i > 0 {
		a, err := strconv.Atoi(strings.TrimSpace(s[:i]))
		if err != nil {
			return 0, 0, err
		}
		b, err := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if err != nil {
			return 0, 0, err
		}
		if b < a {
			a, b = b, a
		}
		return a, b, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, err
	}
	return n, n, nil
}

// xhttpServer is the server transport state.
type xhttpServer struct {
	in   *Inbound
	next core.Handler
	opt  xhttpOptions
	log  interface {
		Debug(string, ...any)
	}

	mu       sync.Mutex
	sessions map[string]*xhttpSession
}

func newXHTTPServer(in *Inbound, next core.Handler) (core.Handler, error) {
	opt, err := parseXHTTPOptions(in.XHTTP)
	if err != nil {
		return nil, err
	}
	return &xhttpServer{in: in, next: next, opt: opt, log: in.logger(), sessions: map[string]*xhttpSession{}}, nil
}

func (s *xhttpServer) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveHTTP(ctx, conn, w, r)
	})
	if err := serveHTTPOnConn(conn, handler); err != nil {
		return nil, err
	}
	// The HTTP requests were served and relayed; see h2.go.
	return nil, &core.Stranger{Conn: conn, Quiet: true}
}

// sessionID extracts the UUID-shaped session id that follows the configured
// path. The sample generates ids as %x-%x-%x-%x-%x from 16 random bytes
// (REPORT.md §7.3); the server only checks the shape.
func (s *xhttpServer) sessionID(r *http.Request) string {
	base := strings.TrimSuffix(s.in.Path, "/")
	if base == "" {
		base = ""
	}
	p := strings.TrimPrefix(r.URL.Path, base)
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	if !uuidLike(p) {
		return ""
	}
	return p
}

// serveHTTP implements the three modes (auto behaves as stream-one for a
// single request, and as stream-up/packet-up when a download request pairs
// with an upload).
func (s *xhttpServer) serveHTTP(ctx context.Context, conn net.Conn, w http.ResponseWriter, r *http.Request) {
	if !pathAllowed(s.in.Path, r.URL.Path) {
		s.notFound(w, r)
		return
	}
	if !hostAllowed(s.in.Host, r.Host) {
		s.notFound(w, r)
		return
	}
	id := s.sessionID(r)
	fl, _ := w.(http.Flusher)

	switch s.opt.mode {
	case xhttpStream1:
		s.streamOne(ctx, conn, w, r)
		return
	case xhttpStreamUp, xhttpPacketUp:
		// fallthrough to the pair logic below
	case xhttpAuto:
		if r.Method == http.MethodGet && id != "" {
			s.pairDownload(ctx, conn, id, w, r)
			return
		}
		s.streamOne(ctx, conn, w, r)
		return
	}

	if r.Method == http.MethodGet {
		s.pairDownload(ctx, conn, id, w, r)
		return
	}
	// Upload side: hold the request open, feed its body to the paired
	// download.
	s.pairUpload(ctx, conn, id, w, r, fl)
}

// streamOne is the single-request both-ways mode: the request body is the
// uplink and the response body is the downlink.
func (s *xhttpServer) streamOne(ctx context.Context, conn net.Conn, w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	rc := http.NewResponseController(w)
	// HTTP/1.1 needs full duplex to read while writing.
	_ = rc.EnableFullDuplex()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	st := &xhttpConn{
		r:      r.Body,
		w:      w,
		fl:     fl,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
	}
	sess, err := s.next.Handle(ctx, st)
	if err != nil || sess == nil {
		return
	}
	if sess.Conn == nil {
		sess.Conn = st
	}
	if err := s.in.relaySession(ctx, sess); err != nil && !errors.Is(err, io.EOF) {
		s.log.Debug("xhttp stream ended", "err", err)
	}
}

// xhttpSession pairs the upload request(s) with the download request. Every
// upload body is copied into a pipe the session reads, so stream-up (one long
// POST) and packet-up (many POSTs) share the same code.
type xhttpSession struct {
	pr     *io.PipeReader
	pw     *io.PipeWriter
	ready  chan struct{}
	once   sync.Once
	closed chan struct{}
}

func (s *xhttpServer) lookup(id string) *xhttpSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		return nil
	}
	xs, ok := s.sessions[id]
	if !ok {
		pr, pw := io.Pipe()
		xs = &xhttpSession{pr: pr, pw: pw, ready: make(chan struct{}), closed: make(chan struct{})}
		s.sessions[id] = xs
	}
	return xs
}

func (s *xhttpServer) forget(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func (s *xhttpServer) pairUpload(ctx context.Context, conn net.Conn, id string, w http.ResponseWriter, r *http.Request, fl http.Flusher) {
	xs := s.lookup(id)
	if xs == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if fl != nil {
		fl.Flush()
	}
	// Feed the session's uplink until this request's body ends (stream-up
	// keeps one POST open for the whole session; packet-up ends per chunk).
	if _, err := io.Copy(xs.pw, r.Body); err != nil {
		return
	}
}

func (s *xhttpServer) pairDownload(ctx context.Context, conn net.Conn, id string, w http.ResponseWriter, r *http.Request) {
	xs := s.lookup(id)
	fl, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if xs == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	xs.once.Do(func() { close(xs.ready) })
	select {
	case <-xs.ready:
	case <-time.After(handshakeTimeout):
		return
	}
	// The session stream writes to the download and reads from the upload
	// pipe that every POST feeds.
	st := &duplexConn{
		reader: xs.pr,
		writer: w,
		flush:  fl,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
	}
	defer func() {
		close(xs.closed)
		_ = xs.pw.CloseWithError(io.EOF)
		s.forget(id)
	}()
	sess, err := s.next.Handle(ctx, st)
	if err != nil || sess == nil {
		return
	}
	if sess.Conn == nil {
		sess.Conn = st
	}
	if err := s.in.relaySession(ctx, sess); err != nil && !errors.Is(err, io.EOF) {
		s.log.Debug("xhttp session ended", "err", err)
	}
}

// notFound answers like a plain web server (REPORT.md §7.4:
// (*xhttpServer).notFound).
func (s *xhttpServer) notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(errorPage(http.StatusNotFound, "The requested URL was not found on this server."))
}

// xhttpConn adapts one HTTP request/response pair to net.Conn.
type xhttpConn struct {
	r      io.ReadCloser
	w      http.ResponseWriter
	fl     http.Flusher
	local  net.Addr
	remote net.Addr
}

func (c *xhttpConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *xhttpConn) LocalAddr() net.Addr              { return c.local }
func (c *xhttpConn) RemoteAddr() net.Addr             { return c.remote }
func (c *xhttpConn) SetDeadline(time.Time) error      { return nil }
func (c *xhttpConn) SetReadDeadline(time.Time) error  { return nil }
func (c *xhttpConn) SetWriteDeadline(time.Time) error { return nil }
func (c *xhttpConn) Close() error                     { return c.r.Close() }
func (c *xhttpConn) CloseWrite() error                { return c.r.Close() }

func (c *xhttpConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err == nil && c.fl != nil {
		c.fl.Flush()
	}
	return n, err
}

// duplexConn reads from one side and writes to the other (stream-up and
// packet-up pair the upload and download requests this way).
type duplexConn struct {
	reader io.Reader
	writer io.Writer
	flush  http.Flusher
	local  net.Addr
	remote net.Addr
}

func (c *duplexConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *duplexConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if err == nil && c.flush != nil {
		c.flush.Flush()
	}
	return n, err
}
func (c *duplexConn) Close() error                     { return nil }
func (c *duplexConn) CloseWrite() error                { return nil }
func (c *duplexConn) LocalAddr() net.Addr              { return c.local }
func (c *duplexConn) RemoteAddr() net.Addr             { return c.remote }
func (c *duplexConn) SetDeadline(time.Time) error      { return nil }
func (c *duplexConn) SetReadDeadline(time.Time) error  { return nil }
func (c *duplexConn) SetWriteDeadline(time.Time) error { return nil }

// uuidLike checks the UUID shape the sample's sessionID generator produces
// ("%x-%x-%x-%x-%x", REPORT.md §7.3). The regex in the binary is
// ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-...-[0-9a-fA-F]{12}$.
func uuidLike(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

var _ = url.Parse
