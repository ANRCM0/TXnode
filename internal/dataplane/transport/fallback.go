package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Fallback is the three-level answer of REPORT.md §7.9 and
// notes/rev-transport.md §7.2: a file from fallback_dir, then the in-memory
// decoy site, then a bare 444/403-style close for strangers.
//
// The sample's methods map one-to-one: NewFallback 0xab0a80,
// (*Fallback).ServeHTTP 0xab14a0, ServeConn 0xab1500, Expect 0xab1640,
// Settle 0xab18c0, take 0xab1a20, relay 0xab1d00, warn 0xab2300.
type Fallback struct {
	// Address is fallback: "host:port", "http://host[:port]" or
	// "https://host[:port]".
	Address string
	// Dir is fallback_dir, a directory served for matching requests.
	Dir string
	// Logger receives the warn lines.
	Logger *slog.Logger

	site  *decoySite
	proto string
	mu    sync.Mutex
}

// FallbackConfig is the constructor argument.
type FallbackConfig struct {
	Address string
	Dir     string
	Logger  *slog.Logger
}

// NewFallback validates the configuration. The error wording follows the
// string table ("fallback_dir %q is not a directory this process can read",
// "fallback %q: write host:port of a web server, or http://host[:port] or
// https://host[:port] of a site to show").
func NewFallback(cfg FallbackConfig) (*Fallback, error) {
	f := &Fallback{Address: cfg.Address, Dir: cfg.Dir, Logger: cfg.Logger, site: newDecoySite()}
	if f.Logger == nil {
		f.Logger = slog.Default()
	}
	if cfg.Dir != "" {
		st, err := os.Stat(cfg.Dir)
		if err != nil || !st.IsDir() {
			return nil, fmt.Errorf("fallback_dir %q is not a directory this process can read", cfg.Dir)
		}
	}
	if cfg.Address != "" {
		if _, err := normalizeFallbackAddress(cfg.Address); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func normalizeFallbackAddress(s string) (string, error) {
	orig := s
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u := strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
		if i := strings.IndexByte(u, '/'); i >= 0 {
			u = u[:i]
		}
		if u == "" {
			return "", fmt.Errorf("fallback %q: write host:port of a web server, or http://host[:port] or https://host[:port] of a site to show", orig)
		}
		if _, _, err := net.SplitHostPort(u); err != nil {
			u = net.JoinHostPort(u, defaultFallbackPort(s))
		}
		return u, nil
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		if strings.ContainsAny(s, " /") {
			return "", fmt.Errorf("fallback %q: write host:port of a web server, or http://host[:port] or https://host[:port] of a site to show", orig)
		}
		return net.JoinHostPort(s, "80"), nil
	}
	return s, nil
}

func defaultFallbackPort(s string) string {
	if strings.HasPrefix(s, "https://") {
		return "443"
	}
	return "80"
}

// Expect records what the first bytes should look like ("tls" or "http").
func (f *Fallback) Expect(proto string) {
	f.mu.Lock()
	f.proto = strings.ToLower(strings.TrimSpace(proto))
	f.mu.Unlock()
}

// ServeHTTP serves the fallback for an HTTP request: the directory first, the
// decoy site otherwise.
func (f *Fallback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.Dir != "" {
		name := filepath.Clean("/" + r.URL.Path)
		full := filepath.Join(f.Dir, name)
		if within(f.Dir, full) {
			if st, err := os.Stat(full); err == nil && !st.IsDir() {
				http.ServeFile(w, r, full)
				return
			}
		}
	}
	f.site.ServeHTTP(w, r)
}

// ServeConn answers a raw connection: it reads the head (Settle), forwards to
// fallback when configured, and otherwise writes the decoy page or closes.
func (f *Fallback) ServeConn(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReaderSize(c, 4096)
	head, _ := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if len(head) == 0 {
		return
	}
	// Non-HTTP bytes go to the upstream site unchanged (a real server would
	// answer TLS or garbage); HTTP gets the decoy site.
	if head[0] != 'G' && head[0] != 'P' && head[0] != 'H' && head[0] != 'D' {
		if f.Address != "" {
			f.relay(c, br)
			return
		}
		// 444: close without an answer, the sample's cheapest refusal.
		return
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		f.writePage(c, http.StatusBadRequest, "Bad Request")
		return
	}
	// Serve the request from the decoy site or the directory.
	rec := &connResponse{c: c}
	if f.Dir != "" {
		full := filepath.Join(f.Dir, filepath.Clean("/"+req.URL.Path))
		if within(f.Dir, full) {
			if st, err := os.Stat(full); err == nil && !st.IsDir() {
				http.ServeFile(rec, req, full)
				return
			}
		}
	}
	f.site.ServeHTTP(rec, req)
}

func (f *Fallback) writePage(c net.Conn, code int, msg string) {
	body := errorPage(code, msg)
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		code, http.StatusText(code), len(body))
	_, _ = c.Write(body)
}

// relay forwards the connection to the fallback address after replaying the
// buffered head.
func (f *Fallback) relay(c net.Conn, br *bufio.Reader) {
	addr, err := normalizeFallbackAddress(f.Address)
	if err != nil {
		f.Logger.Warn("fallback is badly configured", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	up, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		f.Logger.Warn("fallback is not reachable", "dest", f.Address, "err", err)
		f.writePage(c, http.StatusBadGateway, "Bad Gateway")
		return
	}
	defer up.Close()
	go func() {
		_, _ = io.Copy(up, br)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	_, _ = io.Copy(c, up)
}

func (f *Fallback) warn(msg string, args ...any) {
	f.Logger.Warn(msg, args...)
}

// within reports whether path is inside root (fallback_dir traversal guard).
func within(root, path string) bool {
	r, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	return p == r || strings.HasPrefix(p, r+string(os.PathSeparator))
}

// Settle waits until at least n bytes arrived or the deadline expires, without
// consuming them (the sample's Settle buffers the head of a stranger).
func (f *Fallback) Settle(c net.Conn, n int, d time.Duration) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, n)
	got, err := io.ReadFull(c, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return buf[:got], err
	}
	return buf[:got], nil
}

// connResponse adapts a raw connection to http.ResponseWriter so the decoy
// site can answer without a server.
type connResponse struct {
	c       net.Conn
	headers http.Header
	code    int
	wrote   bool
}

func (w *connResponse) Header() http.Header {
	if w.headers == nil {
		w.headers = http.Header{}
	}
	return w.headers
}

func (w *connResponse) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.code = code
	if w.headers == nil {
		w.headers = http.Header{}
	}
	if w.headers.Get("Content-Type") == "" {
		w.headers.Set("Content-Type", "text/html; charset=utf-8")
	}
	w.headers.Set("Connection", "close")
	fmt.Fprintf(w.c, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	_ = w.headers.Write(w.c)
	_, _ = io.WriteString(w.c, "\r\n")
}

func (w *connResponse) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.c.Write(p)
}
