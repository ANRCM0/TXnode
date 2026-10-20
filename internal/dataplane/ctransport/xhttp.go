package ctransport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2"
)

// XHTTP client. Evidence: REPORT.md §7.3 and notes/rev-transport.md §1.4:
// options are kebab-case, the wire padding is the query parameter
// "x_padding=" followed by N 'X' characters (constructed in
// (*xhttp).header 0xb6a4c0), the session id is a UUID-shaped
// "%x-%x-%x-%x-%x" from 16 random bytes, and download-settings is a separate
// download server that stream-one cannot use.
//
// UNVERIFIED: the exact path layout (/{path}/{session}) and the packet-up seq
// query name; both ends are kaze, so the pair below is self-consistent.

type xhttpClient struct {
	t       *Transport
	mode    string
	padMin  int
	padMax  int
	maxPost int
	// download path/host when download-settings is configured (stream-up and
	// packet-up only).
	downPath string
	downHost string
	path     string
	host     string

	// rts caches one HTTP/2 client transport per underlying connection: a
	// connection must carry exactly one HTTP/2 preface, so every request that
	// uses a connection goes through the same transport.
	mu  sync.Mutex
	rts map[net.Conn]*http2.Transport
}

func newXHTTPClient(t *Transport) (*xhttpClient, error) {
	x := &xhttpClient{t: t, mode: xhttpAuto, padMin: 100, padMax: 1000, maxPost: 1 << 20}
	s := t.XHTTP
	if v := strings.ToLower(strings.TrimSpace(s.Str("mode"))); v != "" {
		x.mode = v
	}
	switch x.mode {
	case xhttpAuto, xhttpStream1, xhttpStreamUp, xhttpPacketUp:
	default:
		return nil, fmt.Errorf("mode %q is not one of auto, stream-one, stream-up, packet-up", x.mode)
	}
	if v := s.Str("x-padding-bytes"); v != "" {
		if lo, hi, err := parseIntRange(v); err == nil {
			x.padMin, x.padMax = lo, hi
		} else {
			return nil, fmt.Errorf("%q is not a number or a range like 100-1000", v)
		}
	}
	if v := s.Str("sc-max-each-post-bytes"); v != "" {
		if lo, _, err := parseIntRange(v); err == nil {
			if lo > 1<<20 {
				return nil, fmt.Errorf("XHTTP scMaxEachPostBytes %d is above kaze's limit of %d; larger uploads are refused", lo, 1<<20)
			}
			x.maxPost = lo
		}
	}
	if alpn := strings.ToLower(s.Str("alpn")); strings.Contains(alpn, "h3") {
		return nil, fmt.Errorf("XHTTP over HTTP/3 (alpn h3) is not supported; clients must use h2 or http/1.1")
	}
	if _, ok := s["x-padding-obfs-mode"]; ok {
		return nil, fmt.Errorf("x-padding-obfs-mode is not supported: padding is sent the standard way, as a Referer query; remove it here and on the server")
	}
	if _, ok := s["uplink-data-placement"]; ok {
		return nil, fmt.Errorf("uplink-data-placement %q is not supported: uploads go in the request body", s.Str("uplink-data-placement"))
	}
	if v, ok := s["uplink-http-method"]; ok {
		return nil, fmt.Errorf("uplink-http-method %q is not an HTTP method", fmt.Sprint(v))
	}
	x.path = strings.TrimSuffix(firstNonEmpty(s.Str("path"), t.Settings.Str("path"), "/"), "/")
	if x.path == "" {
		x.path = "/"
	}
	if d := subOpt(s, "download-settings", "download_settings"); len(d) > 0 {
		if x.mode == xhttpStream1 {
			return nil, fmt.Errorf("xhttp: download-settings sends the download elsewhere, which mode stream-one (one request both ways) cannot do: use stream-up or packet-up")
		}
		x.downPath = strings.TrimSuffix(firstNonEmpty(d.Str("path"), x.path), "/")
		x.downHost = d.Str("host")
	}
	return x, nil
}

func (t *Transport) dialXHTTP(ctx context.Context, conn net.Conn) (net.Conn, error) {
	x, err := newXHTTPClient(t)
	if err != nil {
		return nil, err
	}
	x.host = t.hostHeader(t.dest)
	if x.downHost == "" {
		x.downHost = x.host
	}
	if x.downPath == "" {
		x.downPath = x.path
	}

	session := newSessionID()
	switch x.mode {
	case xhttpStream1, xhttpAuto:
		return x.streamOne(ctx, conn, session)
	case xhttpStreamUp:
		return x.streamUp(ctx, conn, session)
	case xhttpPacketUp:
		return x.packetUp(ctx, conn, session)
	}
	return nil, fmt.Errorf("mode %q is not one of auto, stream-one, stream-up, packet-up", x.mode)
}

func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// header sets the XHTTP request headers of (*xhttp).header: Host,
// User-Agent (Mozilla), Referer, Content-Type: application/grpc, and the
// x_padding query of N 'X'.
func (x *xhttpClient) request(ctx context.Context, method, host, path string, body io.Reader) (*http.Request, error) {
	return x.requestQuery(ctx, method, host, path, "", body)
}

func (x *xhttpClient) requestSeq(ctx context.Context, method, host, path string, seq int, body io.Reader) (*http.Request, error) {
	return x.requestQuery(ctx, method, host, path, "seq="+strconv.Itoa(seq), body)
}

func (x *xhttpClient) requestQuery(ctx context.Context, method, host, path, extra string, body io.Reader) (*http.Request, error) {
	n := x.padMin
	if x.padMax > x.padMin {
		var b [2]byte
		if _, err := rand.Read(b[:]); err == nil {
			n += int(b[0]) % (x.padMax - x.padMin + 1)
		}
	}
	u := url.URL{Scheme: "https", Host: host, Path: path + "/" + ctxSessionID(ctx)}
	u.RawQuery = "x_padding=" + strings.Repeat("X", n)
	if extra != "" {
		u.RawQuery += "&" + extra
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Host = host
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://"+host+"/")
	req.Header.Set("Content-Type", "application/grpc")
	return req, nil
}

type sessionKey struct{}

func ctxSessionID(ctx context.Context) string {
	if v, ok := ctx.Value(sessionKey{}).(string); ok {
		return v
	}
	return "00000000-0000-0000-0000-000000000000"
}

func withSession(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionKey{}, id)
}

// streamOne: one POST carries both directions.
func (x *xhttpClient) streamOne(ctx context.Context, conn net.Conn, session string) (net.Conn, error) {
	ctx = withSession(ctx, session)
	pr, pw := io.Pipe()
	req, err := x.request(ctx, http.MethodPost, x.host, x.path, pr)
	if err != nil {
		return nil, err
	}
	h2 := x.t.alpnProtocol() == "h2"
	resp, err := x.roundTrip(conn, req, h2)
	if err != nil {
		return nil, fmt.Errorf("check path, host and mode against the server (and x-padding-bytes, if the server sets it): %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check path, host and mode against the server (and x-padding-bytes, if the server sets it): the server answered %q", resp.Status)
	}
	return &streamConn{reader: resp.Body, writer: pw, closer: resp.Body, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

// streamUp: a long-lived POST is the uplink, a GET is the downlink.
func (x *xhttpClient) streamUp(ctx context.Context, conn net.Conn, session string) (net.Conn, error) {
	upCtx := withSession(ctx, session)
	pr, pw := io.Pipe()
	upReq, err := x.request(upCtx, http.MethodPost, x.host, x.path, pr)
	if err != nil {
		return nil, err
	}
	h2 := x.t.alpnProtocol() == "h2"
	upReady := make(chan error, 1)
	go func() {
		resp, err := x.roundTrip(conn, upReq, h2)
		upReady <- err
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	if err := <-upReady; err != nil {
		return nil, fmt.Errorf("check path, host and mode against the server (and x-padding-bytes, if the server sets it): upload: %w", err)
	}
	// The download gets its own connection (Xray's splitHTTP sends it
	// separately, and download-settings can point it elsewhere): one socket
	// carries exactly one HTTP/2 preface.
	downConn, err := x.t.dialTransport(ctx, x.t.dest)
	if err != nil {
		return nil, err
	}
	downCtx := withSession(ctx, session)
	downReq, err := x.request(downCtx, http.MethodGet, x.downHost, x.downPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := x.roundTrip(downConn, downReq, h2)
	if err != nil {
		return nil, fmt.Errorf("check path, host and mode against the server (and x-padding-bytes, if the server sets it): download: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check path, host and mode against the server (and x-padding-bytes, if the server sets it): the server answered %q", resp.Status)
	}
	return &streamConn{reader: resp.Body, writer: pw, closer: resp.Body, local: downConn.LocalAddr(), remote: downConn.RemoteAddr()}, nil
}

// packetUp: each Write becomes its own POST; the downlink is a GET on a
// second connection.
func (x *xhttpClient) packetUp(ctx context.Context, conn net.Conn, session string) (net.Conn, error) {
	pr, pw := io.Pipe()
	go func() {
		seq := 0
		buf := make([]byte, x.maxPost)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				seq++
				body := &bodyReader{data: buf[:n]}
				reqCtx := withSession(ctx, session)
				req, rerr := x.requestSeq(reqCtx, http.MethodPost, x.host, x.path, seq, body)
				if rerr == nil {
					h2 := x.t.alpnProtocol() == "h2"
					if resp, rerr := x.roundTrip(conn, req, h2); rerr == nil {
						_, _ = io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
	downConn, err := x.t.dialTransport(ctx, x.t.dest)
	if err != nil {
		return nil, err
	}
	downCtx := withSession(ctx, session)
	downReq, err := x.request(downCtx, http.MethodGet, x.downHost, x.downPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := x.roundTrip(downConn, downReq, x.t.alpnProtocol() == "h2")
	if err != nil {
		return nil, fmt.Errorf("check path, host and mode against the server (and x-padding-bytes, if the server sets it): %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check path, host and mode against the server (and x-padding-bytes, if the server sets it): the server answered %q", resp.Status)
	}
	return &streamConn{reader: resp.Body, writer: pw, closer: resp.Body, local: downConn.LocalAddr(), remote: downConn.RemoteAddr()}, nil
}

// roundTrip sends one request over the already established connection.
func (x *xhttpClient) roundTrip(conn net.Conn, req *http.Request, h2 bool) (*http.Response, error) {
	if h2 {
		return x.transportFor(conn).RoundTrip(req)
	}
	br := bufio.NewReaderSize(conn, 4096)
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(br, req)
}

// transportFor returns the HTTP/2 transport of conn, creating it once.
func (x *xhttpClient) transportFor(conn net.Conn) *http2.Transport {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.rts == nil {
		x.rts = map[net.Conn]*http2.Transport{}
	}
	if rt, ok := x.rts[conn]; ok {
		return rt
	}
	rt := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return &stateConn{Conn: conn, state: tlsStateOf(conn)}, nil
		},
	}
	x.rts[conn] = rt
	return rt
}

// bodyReader is a one-shot request body.
type bodyReader struct {
	data []byte
	off  int
}

func (b *bodyReader) Read(p []byte) (int, error) {
	if b.off >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.off:])
	b.off += n
	return n, nil
}

// uuidLike checks the UUID shape the session id generator produces
// ("%x-%x-%x-%x-%x", REPORT.md §7.3).
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

const (
	xhttpAuto     = "auto"
	xhttpStream1  = "stream-one"
	xhttpStreamUp = "stream-up"
	xhttpPacketUp = "packet-up"
)
