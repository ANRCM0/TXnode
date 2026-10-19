package outbound

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
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// wsGUID is RFC 6455's accept salt; transport.dialWebSocket uses the same
// constant (REPORT.md §7.2).
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// wsConn adapts a websocket stream to net.Conn: Write sends one binary frame,
// Read reassembles data frames and transparently answers pings. It is the
// fallback used when ctransport is not wired (network=ws and the SIP003
// v2ray-plugin, whose only supported mode is websocket).
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader

	wmu    sync.Mutex
	rmu    sync.Mutex
	remain []byte
	closed bool
}

// wsClient performs the RFC 6455 upgrade on c.
func wsClient(ctx context.Context, c net.Conn, path, host string, headers map[string]string, alpn []string) (*wsConn, error) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if host == "" {
		host = c.RemoteAddr().String()
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes[:])

	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	b.WriteString("User-Agent: Mozilla/5.0\r\n")
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	}
	if _, err := io.WriteString(c, b.String()); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(c, 4096)
	tp := textproto.NewReader(br)
	status, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}
	if !strings.Contains(status, " 101 ") {
		return nil, fmt.Errorf("websocket: the server answered %q instead of 101 (check the path and Host against the server)", status)
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	want := base64.StdEncoding.EncodeToString(sha1Sum(key + wsGUID))
	if got := hdr.Get("Sec-WebSocket-Accept"); got != want {
		return nil, fmt.Errorf("websocket: Sec-WebSocket-Accept %q does not match the key", got)
	}
	_ = c.SetDeadline(time.Time{})
	return &wsConn{conn: c, br: br}, nil
}

func sha1Sum(s string) []byte {
	h := sha1.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func (w *wsConn) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for {
		if len(w.remain) > 0 {
			n := copy(p, w.remain)
			w.remain = w.remain[n:]
			return n, nil
		}
		op, payload, err := w.readFrame()
		if err != nil {
			return 0, err
		}
		switch op {
		case wsOpBinary, wsOpText, wsOpContinuation:
			if len(payload) == 0 {
				continue
			}
			n := copy(p, payload)
			if n < len(payload) {
				w.remain = append(w.remain[:0], payload[n:]...)
			}
			return n, nil
		case wsOpPing:
			w.writeFrameLocked(wsOpPong, payload)
		case wsOpPong:
			// ignore
		case wsOpClose:
			return 0, io.EOF
		}
	}
}

// readFrame reads one frame, unmasking the payload.
func (w *wsConn) readFrame() (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	op := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	n := int(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return 0, nil, err
		}
		v := binary.BigEndian.Uint64(ext[:])
		if v > 1<<20 {
			return 0, nil, errors.New("websocket: frame too large")
		}
		n = int(v)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.br, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(w.br, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return op, payload, nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if err := w.writeFrameLocked(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeFrameLocked writes one masked client frame. The caller holds wmu (or
// owns the conn, as in the pong path).
func (w *wsConn) writeFrameLocked(op byte, p []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | op
	l := len(p)
	switch {
	case l < 126:
		hdr[1] = 0x80 | byte(l)
		hdr[0+2] = 0 // placeholder, replaced below
		var mask [4]byte
		wsRandom(mask[:])
		offset := 2
		copy(hdr[offset:], mask[:])
		buf := make([]byte, offset+4+l)
		copy(buf, hdr[:offset+4])
		for i := 0; i < l; i++ {
			buf[offset+4+i] = p[i] ^ mask[i%4]
		}
		_, err := w.conn.Write(buf)
		return err
	case l <= 0xffff:
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(l))
		var mask [4]byte
		wsRandom(mask[:])
		buf := make([]byte, 8+l)
		copy(buf, hdr[:4])
		copy(buf[4:8], mask[:])
		for i := 0; i < l; i++ {
			buf[8+i] = p[i] ^ mask[i%4]
		}
		_, err := w.conn.Write(buf)
		return err
	default:
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(l))
		var mask [4]byte
		wsRandom(mask[:])
		buf := make([]byte, 14+l)
		copy(buf, hdr[:10])
		copy(buf[10:14], mask[:])
		for i := 0; i < l; i++ {
			buf[14+i] = p[i] ^ mask[i%4]
		}
		_, err := w.conn.Write(buf)
		return err
	}
}

func wsRandom(p []byte) {
	if _, err := rand.Read(p); err != nil {
		// crypto/rand should not fail; a zero mask is still a valid (if
		// predictable) mask for a fallback transport.
		for i := range p {
			p[i] = 0
		}
	}
}

func (w *wsConn) CloseWrite() error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	_ = w.writeFrameLocked(wsOpClose, []byte{0x03, 0xe8})
	return nil
}

func (w *wsConn) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	_ = w.CloseWrite()
	return w.conn.Close()
}

func (w *wsConn) LocalAddr() net.Addr                { return w.conn.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr               { return w.conn.RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error      { return w.conn.SetDeadline(t) }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

var _ net.Conn = (*wsConn)(nil)

// ensure net/http is linked for the textproto helpers used above.
var _ = http.MethodGet
