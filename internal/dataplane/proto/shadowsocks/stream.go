package shadowsocks

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// Chunking constants from SIP004. The writer splits payloads at 0x3FFF and the
// reader rejects anything larger.
const (
	maxChunk = 0x3fff
	// fixedHeaderLen is 11 plaintext bytes (type 1 + timestamp 8 + length 2),
	// which becomes 27 on the wire with a 16-byte tag — the `0x1b` (27) immediate
	// observed in ss.(*Handler).handshake2022 @0xb18aa0 (notes §4.3).
	fixedHeaderLen = 11
)

// fixed header types of SIP022.
const (
	headerClientStream = 0
	headerServerStream = 1
)

// chunkWriter encrypts a byte stream into AEAD chunks. When salt is non-nil it is
// written before the first chunk (the request/response salt). When header is true
// the stream is SIP022: an 11-byte fixed header carrying the first chunk length is
// emitted before the first payload.
type chunkWriter struct {
	w          io.Writer
	aead       cipher.AEAD
	nonce      nonceCounter
	salt       []byte
	is2022     bool
	streamType byte
	// requestSalt is embedded in the 2022 server response fixed header
	// (type | epoch | request salt | length), unlike the 11-byte client header.
	requestSalt []byte
	started     bool
	first      bool
	buf        []byte
	err        error
}

func newChunkWriter(w io.Writer, aead cipher.AEAD, salt []byte, is2022 bool, streamType byte) *chunkWriter {
	return &chunkWriter{
		w:          w,
		aead:       aead,
		nonce:      newNonceCounter(aead.NonceSize()),
		salt:       salt,
		is2022:     is2022,
		streamType: streamType,
		first:      true,
		buf:        make([]byte, 0, maxChunk+2+aead.Overhead()),
	}
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		if err := w.writeChunk(p[:n]); err != nil {
			w.err = err
			return total, err
		}
		total += n
		p = p[n:]
	}
	if total == 0 {
		// A zero-length write still has to establish the salt and (for 2022) the
		// fixed header, otherwise an empty response leaves the client hanging.
		if err := w.start(nil); err != nil {
			w.err = err
			return 0, err
		}
	}
	return total, nil
}

func (w *chunkWriter) writeChunk(p []byte) error {
	if err := w.start(p); err != nil {
		return err
	}
	w.buf = w.buf[:0]
	if w.is2022 && w.first {
		// The fixed header already carries this chunk's length.
		w.first = false
		w.buf = w.aead.Seal(w.buf, w.nonce.get(), p, nil)
		w.nonce.inc()
		_, err := w.w.Write(w.buf)
		return err
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(p)))
	w.buf = w.aead.Seal(w.buf, w.nonce.get(), length[:], nil)
	w.nonce.inc()
	w.buf = w.aead.Seal(w.buf, w.nonce.get(), p, nil)
	w.nonce.inc()
	_, err := w.w.Write(w.buf)
	return err
}

// start emits the salt and, for SIP022, the fixed header for the first chunk.
func (w *chunkWriter) start(first []byte) error {
	if w.started {
		return nil
	}
	w.started = true
	if len(w.salt) > 0 {
		if _, err := w.w.Write(w.salt); err != nil {
			return err
		}
	}
	if !w.is2022 {
		return nil
	}
	hdrLen := fixedHeaderLen
	if len(w.requestSalt) > 0 {
		hdrLen += len(w.requestSalt)
	}
	hdr := make([]byte, hdrLen)
	hdr[0] = w.streamType
	binary.BigEndian.PutUint64(hdr[1:9], uint64(nowUnix()))
	off := 9
	copy(hdr[off:], w.requestSalt)
	off += len(w.requestSalt)
	binary.BigEndian.PutUint16(hdr[off:off+2], uint16(len(first)))
	sealed := w.aead.Seal(nil, w.nonce.get(), hdr, nil)
	w.nonce.inc()
	_, err := w.w.Write(sealed)
	return err
}

// chunkReader decrypts a chunked AEAD stream.
type chunkReader struct {
	r     io.Reader
	aead  cipher.AEAD
	nonce nonceCounter

	lengthBuf  []byte
	payloadBuf []byte
	left       int
	off        int
	// firstLen >= 0 means the next payload's length came from a SIP022 fixed
	// header instead of a length chunk.
	firstLen int
	err      error
}

func newChunkReader(r io.Reader, aead cipher.AEAD, firstLen int) *chunkReader {
	return &chunkReader{
		r:          r,
		aead:       aead,
		nonce:      newNonceCounter(aead.NonceSize()),
		lengthBuf:  make([]byte, 2+aead.Overhead()),
		payloadBuf: make([]byte, maxChunk+aead.Overhead()),
		firstLen:   firstLen,
	}
}

// skip advances the nonce counter, for formats that spend a nonce before the
// first payload chunk (SIP022 spends nonce 0 on the fixed header).
func (c *chunkReader) skip(n int) {
	for i := 0; i < n; i++ {
		c.nonce.inc()
	}
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for {
		if c.left > 0 {
			n := copy(p, c.payloadBuf[c.off:c.off+c.left])
			c.off += n
			c.left -= n
			return n, nil
		}
		if c.err != nil {
			return 0, c.err
		}
		if err := c.next(); err != nil {
			c.err = err
			return 0, err
		}
	}
}

func (c *chunkReader) next() error {
	if c.firstLen >= 0 {
		n := c.firstLen
		c.firstLen = -1
		if n == 0 {
			return nil
		}
		if err := c.readPayload(n); err != nil {
			return err
		}
		return nil
	}
	if _, err := io.ReadFull(c.r, c.lengthBuf); err != nil {
		return err
	}
	plain, err := c.aead.Open(c.lengthBuf[:0], c.nonce.get(), c.lengthBuf, nil)
	if err != nil {
		return errCorruptLength
	}
	c.nonce.inc()
	n := int(binary.BigEndian.Uint16(plain))
	if n == 0 || n > maxChunk {
		return errCorruptLength
	}
	return c.readPayload(n)
}

func (c *chunkReader) readPayload(n int) error {
	if n > maxChunk {
		return errCorruptPayload
	}
	buf := c.payloadBuf[:n+c.aead.Overhead()]
	if _, err := io.ReadFull(c.r, buf); err != nil {
		return err
	}
	plain, err := c.aead.Open(buf[:0], c.nonce.get(), buf, nil)
	if err != nil {
		return errCorruptPayload
	}
	c.nonce.inc()
	c.payloadBuf = plain
	c.left = len(plain)
	c.off = 0
	return nil
}

// aeadConn is the session connection: decrypted reads, encrypted writes. It
// forwards the net.Conn bookkeeping (addresses, deadlines) to the raw connection.
type aeadConn struct {
	io.Reader
	w    *chunkWriter
	conn interface {
		io.Closer
		CloseWrite() error
	}
	netConn net.Conn
}

func (c *aeadConn) LocalAddr() net.Addr                { return c.netConn.LocalAddr() }
func (c *aeadConn) RemoteAddr() net.Addr               { return c.netConn.RemoteAddr() }
func (c *aeadConn) SetDeadline(t time.Time) error      { return c.netConn.SetDeadline(t) }
func (c *aeadConn) SetReadDeadline(t time.Time) error  { return c.netConn.SetReadDeadline(t) }
func (c *aeadConn) SetWriteDeadline(t time.Time) error { return c.netConn.SetWriteDeadline(t) }

func (c *aeadConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *aeadConn) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *aeadConn) CloseWrite() error {
	if c.conn != nil {
		return c.conn.CloseWrite()
	}
	return nil
}
