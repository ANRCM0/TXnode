package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// gRPC transport. Evidence: REPORT.md §7.2 (gRPC: grpcPath 0xb54720,
// Content-Type: application/grpc, length-prefixed frames, "bad gRPC message
// length") and notes/rev-transport.md §1.3. The string table also carries
// "transport: unexpected gRPC message", "transport: compressed gRPC messages
// are not supported" and the grpcPaths slice.

// grpcMaxMessage is the largest length prefix accepted (the sample refuses
// oversized frames instead of allocating them).
const grpcMaxMessage = 1 << 20

// grpcPaths returns the accepted request paths for a service name. The sample
// keeps a slice (transport.grpcPaths) because gun clients differ on the
// suffix; the service name is the configured grpcSettings.serviceName.
func grpcPaths(service string) []string {
	service = strings.Trim(service, "/")
	if service == "" {
		return []string{"/Tunnel", "/Tun", "/"}
	}
	return []string{"/" + service + "/Tunnel", "/" + service + "/Tun", "/" + service}
}

type grpcHandler struct {
	in   *Inbound
	next core.Handler
}

func (h *grpcHandler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	paths := grpcPaths(h.in.ServiceName)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !pathIn(paths, r.URL.Path) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/grpc") {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		fl, ok := w.(http.Flusher)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		fl.Flush()
		gc := &grpcConn{body: r.Body, w: w, fl: fl, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
		sess, err := h.next.Handle(ctx, gc)
		if err != nil || sess == nil {
			return
		}
		if sess.Conn == nil {
			sess.Conn = gc
		}
		if err := h.in.relaySession(ctx, sess); err != nil && !errors.Is(err, io.EOF) {
			h.in.logger().Debug("gRPC stream ended", "err", err)
		}
	})
	if err := serveHTTPOnConn(conn, handler); err != nil {
		return nil, err
	}
	// The streams were relayed one by one; see h2.go for the return value.
	return nil, &core.Stranger{Conn: conn, Quiet: true}
}

func pathIn(paths []string, got string) bool {
	for _, p := range paths {
		if pathAllowed(p, got) {
			return true
		}
	}
	return false
}

// grpcConn carries the gRPC length-prefixed message stream as a net.Conn.
// Evidence: (*grpcConn).Read/Write/Close at 0xab... (the sample keeps a
// grpcConn type; see the type list "github.com/ANRCM0/TX-Node/internal/dataplane/transport.grpcConn").
type grpcConn struct {
	body   io.ReadCloser
	w      http.ResponseWriter
	fl     http.Flusher
	local  net.Addr
	remote net.Addr

	pending []byte
}

func (c *grpcConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		var hdr [5]byte
		if _, err := io.ReadFull(c.body, hdr[:]); err != nil {
			return 0, err
		}
		if hdr[0] != 0 {
			return 0, errors.New("transport: compressed gRPC messages are not supported")
		}
		n := binary.BigEndian.Uint32(hdr[1:])
		if n > grpcMaxMessage {
			return 0, fmt.Errorf("transport: bad gRPC message length: %d", n)
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c.body, msg); err != nil {
			return 0, fmt.Errorf("transport: unexpected gRPC message: %w", err)
		}
		c.pending = msg
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *grpcConn) Write(p []byte) (int, error) {
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(p)))
	if _, err := c.w.Write(hdr[:]); err != nil {
		return 0, err
	}
	if _, err := c.w.Write(p); err != nil {
		return 0, err
	}
	c.fl.Flush()
	return len(p), nil
}

func (c *grpcConn) Close() error { return c.body.Close() }

func (c *grpcConn) LocalAddr() net.Addr  { return c.local }
func (c *grpcConn) RemoteAddr() net.Addr { return c.remote }

func (c *grpcConn) SetDeadline(t time.Time) error      { return nil }
func (c *grpcConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *grpcConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *grpcConn) CloseWrite() error { return c.body.Close() }
