package mieru

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// maxStreamChunk is the plaintext size of one stream segment.
const maxStreamChunk = 16 << 10

// streamConn is the net.Conn the node relays: it decrypts inbound segments and
// seals outbound ones.
type streamConn struct {
	h    *Handler
	Conn net.Conn

	cipher *segmentCipher
	user   core.User

	rmu  sync.Mutex
	rbuf []byte

	wmu sync.Mutex
	seq uint32
}

var _ net.Conn = (*streamConn)(nil)

// Read returns plaintext from the current segment, reading more segments as
// needed.
func (c *streamConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		seg, err := readSegment(c.Conn)
		if err != nil {
			return 0, err
		}
		parsed, err := c.cipher.open(seg)
		if err != nil {
			return 0, err
		}
		if !withinWindow(parsed.ts) {
			return 0, errors.New("mieru: segment outside the time window")
		}
		if !c.h.checkReplay(parsed.ts, parsed.seq) {
			return 0, errors.New("mieru: replayed segment")
		}
		switch parsed.code {
		case segData:
			c.rbuf = parsed.payload
		case segClose:
			return 0, io.EOF
		default:
			// Unknown segment codes are ignored rather than trusted.
			continue
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// Write seals p into one or more data segments.
func (c *streamConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxStreamChunk {
			chunk = chunk[:maxStreamChunk]
		}
		seg := c.cipher.seal(segData, uint32(time.Now().Unix()), c.seq, chunk)
		c.seq++
		if _, err := c.Conn.Write(seg); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Close sends a close segment and closes the transport connection.
func (c *streamConn) Close() error {
	c.wmu.Lock()
	seg := c.cipher.seal(segClose, uint32(time.Now().Unix()), c.seq, nil)
	c.seq++
	_, _ = c.Conn.Write(seg)
	c.wmu.Unlock()
	return c.Conn.Close()
}

func (c *streamConn) LocalAddr() net.Addr  { return c.Conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.Conn.RemoteAddr() }

func (c *streamConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
