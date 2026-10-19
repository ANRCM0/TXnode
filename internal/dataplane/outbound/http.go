package outbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// httpOutbound is the HTTP proxy client: CONNECT for a TCP tunnel and the
// absolute-URI form for forward-proxy requests. In the sample it is
// core.(*ProxyOutbound) (httpConnect, catalog-strings.md #645
// "http outbound answered %s").
type httpOutbound struct {
	addr socks.Addr
	user string
	pass string
}

func newHTTP(s settings) (core.Outbound, error) {
	addr, err := serverAddr(s, "http")
	if err != nil {
		return nil, err
	}
	return &httpOutbound{addr: addr, user: s.str(keysUser...), pass: s.str(keysPassword...)}, nil
}

func (o *httpOutbound) Name() string { return "http" }

// proxyAuth renders the Proxy-Authorization header value.
func (o *httpOutbound) proxyAuth() string {
	if o.user == "" && o.pass == "" {
		return ""
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(o.user+":"+o.pass))
}

func (o *httpOutbound) DialTCP(ctx context.Context, dest socks.Addr) (net.Conn, error) {
	c, err := dialWithContext(ctx, o.addr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\n", dest.String())
	fmt.Fprintf(&b, "Host: %s\r\n", dest.String())
	if auth := o.proxyAuth(); auth != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", auth)
	}
	b.WriteString("Proxy-Connection: keep-alive\r\n\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(c, 4096)
	tp := textproto.NewReader(br)
	status, err := tp.ReadLine()
	if err != nil {
		c.Close()
		return nil, err
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		c.Close()
		return nil, err
	}
	code, err := parseHTTPStatus(status)
	if err != nil {
		c.Close()
		return nil, err
	}
	if code != 200 {
		c.Close()
		return nil, fmt.Errorf("http outbound answered %s", status)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: c, br: br}, nil
	}
	return c, nil
}

// parseHTTPStatus extracts the numeric status code from "HTTP/1.1 200 …".
func parseHTTPStatus(line string) (int, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0, fmt.Errorf("http outbound answered a bad status line: %q", line)
	}
	var code int
	if _, err := fmt.Sscanf(fields[1], "%d", &code); err != nil {
		return 0, fmt.Errorf("http outbound answered a bad status line: %q", line)
	}
	return code, nil
}

// forwardRequest sends one absolute-URI request through the proxy (the
// non-CONNECT half of an HTTP proxy outbound) and returns the conn positioned
// at the response, plus the status line and headers. The caller owns the conn.
func (o *httpOutbound) forwardRequest(ctx context.Context, method string, dest socks.Addr, path string, header map[string]string) (net.Conn, string, map[string]string, error) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	c, err := dialWithContext(ctx, o.addr)
	if err != nil {
		return nil, "", nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s http://%s%s HTTP/1.1\r\n", method, dest.String(), path)
	fmt.Fprintf(&b, "Host: %s\r\n", dest.String())
	if auth := o.proxyAuth(); auth != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", auth)
	}
	b.WriteString("Proxy-Connection: keep-alive\r\n")
	b.WriteString("Connection: close\r\n")
	for k, v := range header {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		c.Close()
		return nil, "", nil, err
	}
	br := bufio.NewReaderSize(c, 4096)
	tp := textproto.NewReader(br)
	status, err := tp.ReadLine()
	if err != nil {
		c.Close()
		return nil, "", nil, err
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		c.Close()
		return nil, "", nil, err
	}
	out := map[string]string{}
	for k, v := range hdr {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	_ = c.SetDeadline(time.Time{})
	return &bufferedConn{Conn: c, br: br}, status, out, nil
}

// DialHTTP is the absolute-URI entry point exported for node/tests.
func (o *httpOutbound) DialHTTP(ctx context.Context, dest socks.Addr, method, path string, header map[string]string) (net.Conn, string, error) {
	c, status, _, err := o.forwardRequest(ctx, method, dest, path, header)
	if err != nil {
		return nil, "", err
	}
	return c, status, nil
}

// bufferedConn returns buffered bytes first, then the socket.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.br.Read(p) }

// bufferedConn must keep the CloseWrite capability of the socket.
func (b *bufferedConn) CloseWrite() error { return core.CloseWrite(b.Conn) }

var _ = errors.New
