package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Shared HTTP transport plumbing for the h2, gRPC, XHTTP and mux transports.
// Evidence: notes/rev-transport.md §1.3 (H2 = TLS ALPN h2 +
// x/net/http2.(*Server).serveConn 0x74d600), §4.1 (mux kind 2), §7.5
// ((*Config).webTLS / (*webConn) so the standard library negotiates h2 on a
// listener kaze already decrypted).

// connTLSState returns the TLS state of a connection, if it is a TLS stream.
func connTLSState(c net.Conn) (tls.ConnectionState, bool) {
	type stater interface {
		ConnectionState() tls.ConnectionState
	}
	if s, ok := c.(stater); ok {
		return s.ConnectionState(), true
	}
	return tls.ConnectionState{}, false
}

// isH2 reports whether the connection negotiated h2.
func isH2(c net.Conn) bool {
	st, ok := connTLSState(c)
	return ok && st.NegotiatedProtocol == "h2"
}

// serveHTTP2 runs an HTTP/2 server over one connection.
func serveHTTP2(c net.Conn, handler http.Handler) error {
	srv := &http2.Server{}
	srv.ServeConn(c, &http2.ServeConnOpts{
		Handler:    handler,
		BaseConfig: &http.Server{ReadHeaderTimeout: handshakeTimeout},
	})
	return nil
}

// serveHTTP1 runs an HTTP/1.1 server over one connection.
func serveHTTP1(c net.Conn, handler http.Handler) error {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: handshakeTimeout,
		BaseContext:       func(net.Listener) context.Context { return context.Background() },
	}
	ln := &oneConnListener{conn: c, addr: c.LocalAddr(), done: make(chan struct{})}
	defer ln.Close()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// serveHTTPOnConn picks h2 or HTTP/1.1 from the negotiated ALPN.
//
// The sample decides per transport (h2 always h2; xhttp h2 when the client
// offers it), which is exactly what ALPN reports here. The handshake is forced
// first: ConnectionState is empty until crypto/tls has read the ClientHello.
func serveHTTPOnConn(c net.Conn, handler http.Handler) error {
	if h, ok := c.(interface{ Handshake() error }); ok {
		if err := h.Handshake(); err != nil {
			return err
		}
	} else if h, ok := c.(interface{ HandshakeContext(context.Context) error }); ok {
		if err := h.HandshakeContext(context.Background()); err != nil {
			return err
		}
	}
	if isH2(c) {
		return serveHTTP2(c, handler)
	}
	return serveHTTP1(c, handler)
}

// httpStream adapts one request/response pair to net.Conn: Read drains the
// request body, Write appends DATA frames through the ResponseWriter.
//
// Evidence: (*h2Stream).Read/Write/Close/LocalAddr/RemoteAddr/SetDeadline at
// 0x775d40-0x776420 (notes/rev-transport.md §4.3).
type httpStream struct {
	body    io.ReadCloser
	rw      http.ResponseWriter
	flusher http.Flusher
	rc      *http.ResponseController

	local, remote net.Addr

	closeOnce sync.Once
	closed    chan struct{}
}

func newHTTPStream(w http.ResponseWriter, r *http.Request) (*httpStream, error) {
	fl, ok := w.(http.Flusher)
	if !ok {
		return nil, errors.New("transport: the HTTP server does not flush")
	}
	s := &httpStream{
		body:    r.Body,
		rw:      w,
		flusher: fl,
		rc:      http.NewResponseController(w),
		local:   addrOf(r.Context(), true),
		remote:  addrOf(r.Context(), false),
		closed:  make(chan struct{}),
	}
	if r.RemoteAddr != "" {
		if a, err := net.ResolveTCPAddr("tcp", r.RemoteAddr); err == nil {
			s.remote = a
		}
	}
	return s, nil
}

func addrOf(ctx context.Context, local bool) net.Addr {
	if c, ok := ctx.Value(http.LocalAddrContextKey).(net.Addr); ok && local {
		return c
	}
	return nil
}

func (s *httpStream) Read(p []byte) (int, error) {
	n, err := s.body.Read(p)
	if err == io.EOF {
		select {
		case <-s.closed:
		default:
		}
	}
	return n, err
}

func (s *httpStream) Write(p []byte) (int, error) {
	select {
	case <-s.closed:
		return 0, net.ErrClosed
	default:
	}
	n, err := s.rw.Write(p)
	if err == nil {
		s.flusher.Flush()
	}
	return n, err
}

func (s *httpStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		err = s.body.Close()
	})
	return err
}

func (s *httpStream) LocalAddr() net.Addr {
	if s.local != nil {
		return s.local
	}
	return dummyAddr("http-local")
}

func (s *httpStream) RemoteAddr() net.Addr {
	if s.remote != nil {
		return s.remote
	}
	return dummyAddr("http-remote")
}

func (s *httpStream) SetDeadline(t time.Time) error {
	_ = s.rc.SetReadDeadline(t)
	return s.rc.SetWriteDeadline(t)
}

func (s *httpStream) SetReadDeadline(t time.Time) error  { return s.rc.SetReadDeadline(t) }
func (s *httpStream) SetWriteDeadline(t time.Time) error { return s.rc.SetWriteDeadline(t) }

func (s *httpStream) CloseWrite() error { return s.body.Close() }

type dummyAddr string

func (a dummyAddr) Network() string { return "http" }
func (a dummyAddr) String() string  { return string(a) }
