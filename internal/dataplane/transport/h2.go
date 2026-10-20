package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// h2Handler serves the H2 transport: TLS ALPN h2 plus x/net/http2's
// Server.serveConn, with the request/response pair exposed as a stream.
// Evidence: REPORT.md §7.2 (H2 row) and notes/rev-transport.md §1.3,
// §4.3 ((*h2Stream) adapter).
type h2Handler struct {
	in   *Inbound
	next core.Handler
}

func (h *h2Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	// Each HTTP/2 stream is a session of its own, so the connection is served
	// in place and the sessions are handed to the relay hook.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			// naive: HTTP/2 CONNECT with Basic auth. The protocol handler
			// recognises this stream through its structural interface.
			stream, err := newHTTPStream(w, r)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer stream.Close()
			cs := &connectStream{httpStream: stream, auth: r.Header.Get("Proxy-Authorization"), authority: connectAuthority(r), padding: r.Header.Get("Padding") != ""}
			sess, err := h.next.Handle(ctx, cs)
			if err != nil || sess == nil {
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			if sess.Conn == nil {
				sess.Conn = cs
			}
			if err := h.in.relaySession(ctx, sess); err != nil && !errors.Is(err, io.EOF) {
				h.in.logger().Debug("h2 connect ended", "err", err)
			}
			return
		}
		if !h.in.pathOK(r.URL.Path) || !hostAllowed(h.in.Host, r.Host) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		stream, err := newHTTPStream(w, r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer stream.Close()
		// Answer before reading the body: the client's RoundTrip returns when
		// the response head arrives, and only then does it feed the uplink.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		stream.flusher.Flush()
		sess, err := h.next.Handle(ctx, stream)
		if err != nil {
			return
		}
		if sess == nil {
			return
		}
		if sess.Conn == nil {
			sess.Conn = stream
		}
		if err := h.in.relaySession(ctx, sess); err != nil && !errors.Is(err, io.EOF) {
			h.in.logger().Debug("h2 stream ended", "err", err)
		}
	})
	if err := serveHTTPOnConn(conn, handler); err != nil {
		return nil, err
	}
	// Every stream of this connection was served and relayed through
	// Inbound.Relay/ServeSession; there is no single session to hand back, so
	// report the connection as consumed (core closes it without counting a
	// failed handshake).
	return nil, &core.Stranger{Conn: conn, Quiet: true}
}

func (i *Inbound) pathOK(path string) bool {
	return pathAllowed(i.Path, path)
}

// connectStream adapts an HTTP/2 CONNECT request to the naive inbound: the
// request body is the uplink and the response writer is the downlink. The
// methods after net.Conn match naive.Stream structurally.
type connectStream struct {
	*httpStream
	auth      string
	authority string
	padding   bool
}

func (c *connectStream) ProxyAuthorization() string { return c.auth }
func (c *connectStream) Authority() string          { return c.authority }
func (c *connectStream) PaddingRequested() bool     { return c.padding }
func (c *connectStream) Accept() net.Conn {
	c.rw.WriteHeader(http.StatusOK)
	c.flusher.Flush()
	return c
}
func (c *connectStream) AcceptPadding(value string) net.Conn {
	c.rw.Header().Set("Padding", value)
	return c.Accept()
}

func connectAuthority(r *http.Request) string {
	if authority := r.Header.Get("-connect-authority"); authority != "" {
		return authority
	}
	if r.Host != "" {
		return r.Host
	}
	if r.URL != nil {
		return r.URL.Host
	}
	return ""
}
