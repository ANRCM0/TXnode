package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// Server side of the simple-obfs HTTP transport: the client opens with a
// POST carrying browser headers (obfsHTTP 0xb57240, Write 0xb57be0), the
// server answers an HTTP head and everything after it is the stream
// (skipHTTPHead 0xb58200). The sample keeps this in transport/obfs.go.
type obfsHandler struct {
	in   *Inbound
	next core.Handler
}

func (h *obfsHandler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(conn, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("http obfuscation: the client sent no HTTP header: %w", err)
	}
	if !pathAllowed(h.in.Path, req.URL.Path) {
		err := fmt.Errorf("the request is for %q, not the node's path", req.URL.Path)
		writeHTTPError(conn, http.StatusNotFound, err.Error())
		return nil, err
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	return h.next.Handle(ctx, newPrefixConn(conn, bufferedBytes(br)))
}
