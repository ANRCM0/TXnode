package transport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// Server-side WebSocket (RFC 6455). Evidence: REPORT.md §7.2 and
// notes/rev-transport.md §1.3: the sample's dialWebSocket/wsHandshake
// validate "Upgrade: websocket" and Sec-WebSocket-Accept =
// base64(sha1(key + GUID)), GUID 258EAFA5-E914-47DA-95CA-C5AB0DC85B11 at
// 0xf7d9d8; frames are binary with payload = stream.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xa
)

// wsAccept computes Sec-WebSocket-Accept for a Sec-WebSocket-Key.
func wsAccept(key string) string {
	h := sha1.New()
	io.WriteString(h, key)
	io.WriteString(h, wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type wsHandler struct {
	in   *Inbound
	next core.Handler
}

func (h *wsHandler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	in := h.in
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(conn, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("transport: not a WebSocket upgrade: %w", err)
	}
	if err := checkWSRequest(req, in.Path, in.Host); err != nil {
		writeHTTPError(conn, http.StatusBadRequest, err.Error())
		return nil, err
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		err := errors.New("WebSocket protocol violation: missing Sec-WebSocket-Key")
		writeHTTPError(conn, http.StatusBadRequest, err.Error())
		return nil, err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	wc := &wsConn{Conn: conn, br: br, server: true}
	return h.next.Handle(ctx, wc)
}

func checkWSRequest(req *http.Request, path, host string) error {
	if req.Method != http.MethodGet {
		return fmt.Errorf("transport: not a WebSocket upgrade: method %s", req.Method)
	}
	if !headerHas(req.Header, "Upgrade", "websocket") {
		return fmt.Errorf("WebSocket protocol violation: Upgrade header %q does not contain websocket", req.Header.Get("Upgrade"))
	}
	if !headerHas(req.Header, "Connection", "upgrade") {
		return fmt.Errorf("WebSocket protocol violation: Connection header %q does not contain Upgrade", req.Header.Get("Connection"))
	}
	if v := req.Header.Get("Sec-WebSocket-Version"); v != "" && v != "13" {
		return fmt.Errorf("unsupported WebSocket version %q", v)
	}
	if !pathAllowed(path, req.URL.Path) {
		return fmt.Errorf("the request is for %q, not the node's path", req.URL.Path)
	}
	if !hostAllowed(host, req.Host) {
		return fmt.Errorf("the request is for host %q, not the node's host", req.Host)
	}
	return nil
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func writeHTTPError(c net.Conn, code int, msg string) {
	body := errorPage(code, msg)
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		code, http.StatusText(code), len(body))
	_, _ = c.Write(body)
}

// wsConn turns the WebSocket frame stream into a net.Conn.
type wsConn struct {
	net.Conn
	br     *bufio.Reader
	server bool

	rmu     sync.Mutex
	readBuf []byte // payload of the current data frame
	readFin bool

	wmu sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		fin, op, payload, err := c.nextFrame()
		if err != nil {
			return 0, err
		}
		switch op {
		case opContinuation, opBinary, opText:
			c.readBuf = payload
			c.readFin = fin
			if len(payload) == 0 && fin {
				continue
			}
		case opPing:
			if err := c.writeFrame(opPong, payload); err != nil {
				return 0, err
			}
		case opPong:
			// ignore
		case opClose:
			_ = c.writeFrame(opClose, payload)
			c.Conn.Close()
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("websocket: unknown opcode %#x", op)
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(opBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error {
	c.wmu.Lock()
	_ = c.writeFrameLocked(opClose, nil)
	c.wmu.Unlock()
	return c.Conn.Close()
}

func (c *wsConn) nextFrame() (fin bool, op byte, payload []byte, err error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var hdr [2]byte
	if _, err = io.ReadFull(c.br, hdr[:]); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	op = hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	n := int(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return
		}
		n = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return
		}
		v := binary.BigEndian.Uint64(ext[:])
		if v > 1<<31 {
			err = errors.New("transport: oversized control frame")
			return
		}
		n = int(v)
	}
	if op >= opClose && n > 125 {
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
	} else if c.server {
		// RFC 6455 §5.1: clients must mask.
		err = errors.New("websocket: client sent an unmasked frame")
		return
	}
	return
}

func (c *wsConn) writeFrame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeFrameLocked(op, payload)
}

func (c *wsConn) writeFrameLocked(op byte, payload []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | op
	off := 2
	switch {
	case len(payload) < 126:
		hdr[1] = byte(len(payload))
	case len(payload) <= 0xffff:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(payload)))
		off = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(len(payload)))
		off = 10
	}
	if c.server {
		_, err := c.Conn.Write(hdr[:off])
		if err != nil {
			return err
		}
		_, err = c.Conn.Write(payload)
		return err
	}
	// client frames are masked
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return fmt.Errorf("failed to generate masking key: %w", err)
	}
	hdr[1] |= 0x80
	hdr[off] = mask[0]
	hdr[off+1] = mask[1]
	hdr[off+2] = mask[2]
	hdr[off+3] = mask[3]
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

// CloseWrite half-closes the stream (a data frame carrying FIN only).
func (c *wsConn) CloseWrite() error { return c.Conn.Close() }
