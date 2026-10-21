package naive

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// Naive frames the first eight writes in each direction as a BE16 payload
// length, one padding-length byte, payload and padding. Subsequent data is raw.
// Wire baseline: sing-box v1.14.3 protocol/naive/inbound_conn.go.
type paddingConn struct {
	net.Conn
	readMu, writeMu sync.Mutex
	readFrames      int
	writeFrames     int
	remaining       int
	discard         int
}

func (c *paddingConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for c.remaining == 0 {
		if c.discard > 0 {
			var padding [255]byte
			if _, err := io.ReadFull(c.Conn, padding[:c.discard]); err != nil {
				return 0, err
			}
			c.discard = 0
		}
		if c.readFrames == 8 {
			return c.Conn.Read(p)
		}
		var header [3]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		c.remaining = int(binary.BigEndian.Uint16(header[:2]))
		c.discard = int(header[2])
		c.readFrames++
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}

func (c *paddingConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		if c.writeFrames == 8 {
			n, err := c.Conn.Write(p)
			return total + n, err
		}
		size := len(p)
		if size > 65535 {
			size = 65535
		}
		padding := randN(256)
		frame := make([]byte, 3+size+padding)
		binary.BigEndian.PutUint16(frame[:2], uint16(size))
		frame[2] = byte(padding)
		copy(frame[3:], p[:size])
		sent := 0
		for sent < len(frame) {
			n, err := c.Conn.Write(frame[sent:])
			if n < 0 || n > len(frame)-sent {
				n, err = 0, io.ErrShortWrite
			}
			sent += n
			if err == nil && n == 0 {
				err = io.ErrShortWrite
			}
			if err != nil {
				_ = c.Conn.Close()
				payload := sent - 3
				if payload < 0 {
					payload = 0
				} else if payload > size {
					payload = size
				}
				return total + payload, err
			}
		}
		c.writeFrames++
		total += size
		p = p[size:]
	}
	return total, nil
}

func (c *paddingConn) CloseWrite() error { return core.CloseWrite(c.Conn) }
