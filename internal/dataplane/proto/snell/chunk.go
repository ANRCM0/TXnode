package snell

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// chunkCoder seals and opens the chunk container.
//
// Evidence for the limits: a chunk is at most 16383 bytes (handshake compares
// with 0x3fff, notes/rev-proto-udp.md §4.1) and a chunk that does not decrypt
// yields "snell: a chunk does not decrypt".
//
// The nonce is a 12-byte counter starting at zero and incremented per chunk in
// each direction. UNVERIFIED: the sample's nonce construction was not decoded;
// a per-direction counter is the only scheme compatible with a single
// connection-wide AEAD instance and no per-chunk IV on the wire.
type chunkCoder struct {
	aead cipher.AEAD
	rw   io.ReadWriter

	rmu sync.Mutex
	rn  uint64
	wmu sync.Mutex
	wn  uint64
}

func newChunkCoder(aead cipher.AEAD, rw io.ReadWriter) *chunkCoder {
	return &chunkCoder{aead: aead, rw: rw}
}

// nonce builds the 12-byte counter nonce.
func chunkNonce(n uint64) [12]byte {
	var out [12]byte
	binary.BigEndian.PutUint64(out[4:], n)
	return out
}

// ReadChunk reads and opens one chunk.
func (c *chunkCoder) ReadChunk() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var sizeBuf [2]byte
	if _, err := io.ReadFull(c.rw, sizeBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(sizeBuf[:]))
	if n < tagLen {
		return nil, ErrBadChunk
	}
	if n > maxChunk+tagLen {
		return nil, ErrChunkTooLarge
	}
	sealed := make([]byte, n)
	if _, err := io.ReadFull(c.rw, sealed); err != nil {
		return nil, err
	}
	nonce := chunkNonce(c.rn)
	c.rn++
	plain, err := c.aead.Open(nil, nonce[:], sealed, nil)
	if err != nil {
		return nil, ErrBadChunk
	}
	return plain, nil
}

// WriteChunk seals and writes one chunk.
func (c *chunkCoder) WriteChunk(p []byte) error {
	if len(p) > maxChunk {
		return ErrChunkTooLarge
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	nonce := chunkNonce(c.wn)
	c.wn++
	sealed := c.aead.Seal(nil, nonce[:], p, nil)
	if len(sealed) > 0xffff {
		return ErrChunkTooLarge
	}
	var sizeBuf [2]byte
	binary.BigEndian.PutUint16(sizeBuf[:], uint16(len(sealed)))
	if _, err := c.rw.Write(sizeBuf[:]); err != nil {
		return err
	}
	_, err := c.rw.Write(sealed)
	return err
}

// streamConn is the net.Conn the node relays on a CONNECT stream: it turns
// Read/Write into chunk operations.
type streamConn struct {
	net.Conn
	coder *chunkCoder

	rmu  sync.Mutex
	rbuf []byte
}

var _ net.Conn = (*streamConn)(nil)

// Read returns plaintext, pulling chunks as needed.
func (c *streamConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		chunk, err := c.coder.ReadChunk()
		if err != nil {
			return 0, err
		}
		if len(chunk) == 0 {
			continue
		}
		c.rbuf = chunk
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// Write splits p into chunks of at most 16383 bytes.
func (c *streamConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}
		if err := c.coder.WriteChunk(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// CloseWrite half-closes when the transport is a TCP socket.
func (c *streamConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
