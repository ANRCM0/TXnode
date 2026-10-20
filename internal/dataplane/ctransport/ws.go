package ctransport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
)

// Client side of WebSocket and HTTPUpgrade. Evidence:
// notes/rev-transport.md §1.3: dialWebSocket 0xb66060 -> wsHandshake
// 0xb66220 (16 random bytes -> base64 Sec-WebSocket-Key; checks Upgrade and
// Sec-WebSocket-Accept), dialHTTPUpgrade 0xb67740 -> upgradeRequest 0xb652e0 +
// readUpgrade 0xb65c60 (must answer 101; error text
// "%s: the server answered %q instead of switching protocols: check the path
// and Host against the server" @0xfa3292).

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

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

func (t *Transport) dialWebSocket(ctx context.Context, conn net.Conn) (net.Conn, error) {
	keyRaw := make([]byte, 16)
	if _, err := rand.Read(keyRaw); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw)
	path := t.wsPath()
	host := t.hostHeader(t.dest)
	u := &url.URL{Scheme: "https", Host: host, Path: path}
	if q := t.WS.Str("query", "headers.query"); q != "" {
		u.RawQuery = q
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	if ua := firstNonEmpty(t.WS.Str("headers.User-Agent", "userAgent"), t.Settings.Str("user-agent")); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	for k, v := range headerMap(t.WS, "headers") {
		switch strings.ToLower(k) {
		case "host", "upgrade", "connection", "sec-websocket-key", "sec-websocket-version":
			continue
		}
		req.Header.Set(k, v)
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 4096)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("%s: the server answered %q instead of switching protocols: check the path and Host against the server", u.String(), resp.Status)
	}
	if !hasToken(resp.Header, "Upgrade", "websocket") || !hasToken(resp.Header, "Connection", "upgrade") {
		return nil, errors.New("transport: not a WebSocket upgrade")
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), wsAccept(key); got != want {
		return nil, fmt.Errorf("WebSocket protocol violation: invalid Sec-WebSocket-Accept %q, key %q", got, key)
	}
	return &wsConn{Conn: conn, br: br}, nil
}

func (t *Transport) dialHTTPUpgrade(ctx context.Context, conn net.Conn) (net.Conn, error) {
	path := t.wsPath()
	host := t.hostHeader(t.dest)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, (&url.URL{Scheme: "http", Host: host, Path: path}).String(), nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	keyRaw := make([]byte, 16)
	if _, err := rand.Read(keyRaw); err == nil {
		req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(keyRaw))
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 4096)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("%s: the server answered %q instead of switching protocols: check the path and Host against the server", req.URL.String(), resp.Status)
	}
	return newPrefixConn(conn, buffered(br)), nil
}

func buffered(br *bufio.Reader) []byte {
	n := br.Buffered()
	if n == 0 {
		return nil
	}
	b, _ := br.Peek(n)
	return append([]byte(nil), b...)
}

func hasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func headerMap(o opt.Opt, key string) map[string]string {
	out := map[string]string{}
	m := o.Map(key)
	for k, v := range m {
		out[k] = fmt.Sprint(v)
	}
	return out
}

// wsAccept is the client's Sec-WebSocket-Accept check (sha1(key+GUID)).
func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsConn is the client WebSocket stream: masked writes, unmasked reads.
type wsConn struct {
	net.Conn
	br *bufio.Reader

	rmu     sync.Mutex
	readBuf []byte
	wmu     sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		op, payload, err := c.nextFrame()
		if err != nil {
			return 0, err
		}
		switch op {
		case 0x0, 0x1, 0x2:
			c.readBuf = payload
			if len(payload) == 0 {
				continue
			}
		case 0x9:
			if err := c.writeFrame(0xa, payload); err != nil {
				return 0, err
			}
		case 0xa:
		case 0x8:
			return 0, io.EOF
		default:
			return 0, errors.New("websocket: unknown opcode")
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) nextFrame() (op byte, payload []byte, err error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var hdr [2]byte
	if _, err = io.ReadFull(c.br, hdr[:]); err != nil {
		return
	}
	op = hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	n := int(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return
		}
		n = int(ext[0])<<8 | int(ext[1])
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return
		}
		v := uint64(0)
		for _, b := range ext {
			v = v<<8 | uint64(b)
		}
		if v > 1<<31 {
			err = errors.New("transport: oversized control frame")
			return
		}
		n = int(v)
	}
	if op >= 0x8 && n > 125 {
		err = errors.New("transport: oversized control frame")
		return
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(c.br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return
}

func (c *wsConn) writeFrame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var hdr [14]byte
	hdr[0] = 0x80 | op
	off := 2
	switch {
	case len(payload) < 126:
		hdr[1] = 0x80 | byte(len(payload))
	case len(payload) <= 0xffff:
		hdr[1] = 0x80 | 126
		hdr[2] = byte(len(payload) >> 8)
		hdr[3] = byte(len(payload))
		off = 4
	default:
		hdr[1] = 0x80 | 127
		for i := 7; i >= 0; i-- {
			hdr[2+i] = byte(len(payload) >> (8 * (7 - i)))
		}
		off = 10
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return fmt.Errorf("failed to generate masking key: %w", err)
	}
	copy(hdr[off:off+4], mask[:])
	off += 4
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	if _, err := c.Conn.Write(hdr[:off]); err != nil {
		return err
	}
	_, err := c.Conn.Write(masked)
	return err
}

func (c *wsConn) CloseWrite() error { return c.Conn.Close() }

// stateConn presents the TLS state of the secured connection to
// x/net/http2.
type stateConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c *stateConn) ConnectionState() tls.ConnectionState { return c.state }

func tlsStateOf(conn net.Conn) tls.ConnectionState {
	if s, ok := conn.(interface {
		ConnectionState() tls.ConnectionState
	}); ok {
		return s.ConnectionState()
	}
	return tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "h2"}
}

// dialH2 opens one HTTP/2 stream (the h2 transport) over the secured conn.
func (t *Transport) dialH2(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return t.h2Stream(ctx, conn, http.MethodPost, t.wsPath(), nil, false)
}

// dialGRPC opens one gRPC stream: POST to the gun path with
// Content-Type: application/grpc and 5-byte length-prefixed frames.
func (t *Transport) dialGRPC(ctx context.Context, conn net.Conn) (net.Conn, error) {
	service := strings.Trim(t.grpcServiceName(), "/")
	path := "/" + service + "/Tunnel"
	if service == "" {
		path = "/Tunnel"
	}
	return t.h2Stream(ctx, conn, http.MethodPost, path, nil, true)
}

// h2Stream issues one request whose body is the uplink and whose response is
// the downlink. Evidence: ctransport/h2.go, (*Transport).Dial H2/gRPC rows in
// REPORT.md §7.2.
func (t *Transport) h2Stream(ctx context.Context, conn net.Conn, method, path string, header http.Header, grpc bool) (net.Conn, error) {
	pr, pw := io.Pipe()
	host := t.hostHeader(t.dest)
	req, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, pr)
	if err != nil {
		return nil, err
	}
	req.Host = host
	if grpc {
		req.Header.Set("Content-Type", "application/grpc")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	rt := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return &stateConn{Conn: conn, state: tlsStateOf(conn)}, nil
		},
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("transport: the server answered %q for the %s stream", resp.Status, path)
	}
	var rd io.Reader = resp.Body
	if grpc {
		rd = &grpcReader{r: resp.Body}
	}
	var wr io.Writer = pw
	if grpc {
		wr = &grpcWriter{w: pw}
	}
	return &streamConn{reader: rd, writer: wr, closer: resp.Body, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

// grpcReader/writer implement the gRPC 5-byte length prefix.
type grpcReader struct {
	r   io.Reader
	cur []byte
}

func (g *grpcReader) Read(p []byte) (int, error) {
	for len(g.cur) == 0 {
		var hdr [5]byte
		if _, err := io.ReadFull(g.r, hdr[:]); err != nil {
			return 0, err
		}
		if hdr[0] != 0 {
			return 0, errors.New("transport: compressed gRPC messages are not supported")
		}
		n := int(hdr[1])<<24 | int(hdr[2])<<16 | int(hdr[3])<<8 | int(hdr[4])
		if n < 0 || n > 1<<20 {
			return 0, fmt.Errorf("transport: bad gRPC message length: %d", n)
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(g.r, msg); err != nil {
			return 0, fmt.Errorf("transport: unexpected gRPC message: %w", err)
		}
		g.cur = msg
	}
	n := copy(p, g.cur)
	g.cur = g.cur[n:]
	return n, nil
}

type grpcWriter struct{ w io.Writer }

func (g *grpcWriter) Write(p []byte) (int, error) {
	var hdr [5]byte
	n := len(p)
	hdr[1] = byte(n >> 24)
	hdr[2] = byte(n >> 16)
	hdr[3] = byte(n >> 8)
	hdr[4] = byte(n)
	if _, err := g.w.Write(hdr[:]); err != nil {
		return 0, err
	}
	if _, err := g.w.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// dialHTTPObfs is the simple-obfs HTTP/1.1 obfs: a POST with a browser header
// is sent first and the response head is dropped (obfsHTTP 0xb57240,
// Write 0xb57be0, skipHTTPHead 0xb58200).
func (t *Transport) dialHTTPObfs(ctx context.Context, conn net.Conn) (net.Conn, error) {
	host := t.hostHeader(t.dest)
	ua := firstNonEmpty(t.Settings.Str("plugin-opts.headers.User-Agent", "user-agent"), "Mozilla/5.0")
	req := "POST / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + ua +
		"\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 4096)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		return nil, fmt.Errorf("http obfuscation: the server did not answer with an HTTP header: %w", err)
	}
	_ = resp.Body.Close()
	return newPrefixConn(conn, buffered(br)), nil
}

// streamConn joins the two halves of an HTTP stream into a net.Conn.
type streamConn struct {
	reader io.Reader
	writer io.Writer
	closer io.Closer
	local  net.Addr
	remote net.Addr
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *streamConn) Close() error {
	if c.closer != nil {
		return c.closer.Close()
	}
	return nil
}
func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *streamConn) CloseWrite() error {
	if cw, ok := c.writer.(io.Closer); ok {
		return cw.Close()
	}
	return nil
}
