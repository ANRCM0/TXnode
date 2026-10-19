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

// Server side of HTTPUpgrade. Evidence: REPORT.md §7.2 and
// notes/rev-transport.md §1.3: the client sends "GET /" plus custom headers
// and the server must answer 101; after the response head the connection is a
// plain byte stream. The client's error wording is
// "%s: the server answered %q instead of switching protocols: check the path
// and Host against the server" (0xfa3292).
type upgradeHandler struct {
	in   *Inbound
	next core.Handler
}

func (h *upgradeHandler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	in := h.in
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(conn, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("invalid Upgrade request header: %q", err)
	}
	if req.Method != http.MethodGet {
		err := fmt.Errorf("invalid Upgrade request header: %q", req.Method)
		writeHTTPError(conn, http.StatusBadRequest, err.Error())
		return nil, err
	}
	if !pathAllowed(in.Path, req.URL.Path) {
		err := fmt.Errorf("the request is for %q, not the node's path", req.URL.Path)
		writeHTTPError(conn, http.StatusNotFound, err.Error())
		return nil, err
	}
	if !hostAllowed(in.Host, req.Host) {
		err := fmt.Errorf("the request is for host %q, not the node's host", req.Host)
		writeHTTPError(conn, http.StatusNotFound, err.Error())
		return nil, err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
	if key := req.Header.Get("Sec-WebSocket-Key"); key != "" {
		resp += "Sec-WebSocket-Accept: " + wsAccept(key) + "\r\n"
	}
	resp += "\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	return h.next.Handle(ctx, newPrefixConn(conn, bufferedBytes(br)))
}

func bufferedBytes(br *bufio.Reader) []byte {
	n := br.Buffered()
	if n == 0 {
		return nil
	}
	b, _ := br.Peek(n)
	return append([]byte(nil), b...)
}
