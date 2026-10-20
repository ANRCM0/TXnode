package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/mux"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// ServeMuxH2 is the h2/gRPC half of a mux port: mux.Serve sniffs kind 2 and
// hands the connection here when the node wires mux.H2Conn to it.
//
// Evidence: mux.Serve's kind 2 branch calls golang.org/x/net/http2
// (*Server).serveConn (notes/rev-transport.md §4.1, 0x74d600); each stream
// starts with the SOCKS address header like the smux/yamux streams
// (readStreamRequest 0x774de0).
func ServeMuxH2(ctx context.Context, conn net.Conn, parent *core.Session, relay func(context.Context, *core.Session) error) error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stream, err := newHTTPStream(w, r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer stream.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		stream.flusher.Flush()
		flags, dest, err := mux.ReadStreamRequest(stream)
		if err != nil {
			return
		}
		if relay == nil {
			return
		}
		sess := &core.Session{Conn: stream, Dest: dest}
		if parent != nil {
			// Streams inherit the accounted parent: user, egress address and
			// lease stay on the mux connection.
			sess.UserID = parent.UserID
			sess.Local = parent.Local
		}
		if flags&mux.FlagUDP != 0 {
			sess.Conn = nil
			sess.Packets = mux.NewServerPackets(stream, flags, dest)
			if flags&mux.FlagAddr != 0 {
				sess.Dest = socks.Addr{}
			}
		}
		if err := relay(ctx, sess); err != nil && !errors.Is(err, io.EOF) {
			return
		}
	})
	return serveHTTPOnConn(conn, handler)
}
