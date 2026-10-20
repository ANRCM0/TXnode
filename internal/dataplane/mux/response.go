package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

func writeFull(w io.Writer, p []byte) error {
	_, err := writeFullCount(w, p)
	return err
}

func writeFullCount(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return total, io.ErrShortWrite
		}
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

// Do not read ahead into the first response payload.
type responseByteReader struct{ io.Reader }

func (r responseByteReader) ReadByte() (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(r.Reader, b[:])
	return b[0], err
}

func readStreamResponse(r io.Reader) error {
	reader := responseByteReader{Reader: r}
	status, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if status == 0 {
		return nil
	}
	if status != 1 {
		return fmt.Errorf("mux: unknown stream status %d", status)
	}
	length, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	if length > 4096 {
		return fmt.Errorf("mux: stream error message too long")
	}
	message := make([]byte, int(length))
	if _, err := io.ReadFull(r, message); err != nil {
		return err
	}
	return fmt.Errorf("mux: remote error: %s", message)
}

type responseConn struct {
	net.Conn
	responseRead bool
	readMu       sync.Mutex
}

func (c *responseConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if !c.responseRead {
		if err := readStreamResponse(c.Conn); err != nil {
			return 0, err
		}
		c.responseRead = true
	}
	return c.Conn.Read(p)
}

func (c *responseConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}
