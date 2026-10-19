// VMess body codec (chunk stream) and the response header.
//
// Evidence:
//
//	vmess.(*vmessConn).header   @0xb4b3e0  response header encode
//	vmess.(*ClientConn).response @0xb48640 response header decode
//	vmess.newCodecLen           @0xb45320  codec construction
//	vmess.(*bodyReader).readChunk @0xb45860
//	vmess.(*bodyWriter).appendChunk @0xb46060
//
// Response header (0xb4b3e0 writes exactly four plaintext bytes
// {responseV,0,0,0} at +0, +1..3 zeroed, and a two-byte length block holding
// 0x0004 at 0xb4b471):
//
//	sealedLen = AEAD(KDF16(sha256(reqKey),"AEAD Resp Header Len Key"),
//	                 nonce=KDF(sha256(reqIV),"AEAD Resp Header Len IV")[:12],
//	                 plaintext=BE16(4), AD=nil)
//	sealedHdr = AEAD(KDF16(sha256(reqKey),"AEAD Resp Header Key"),
//	                 nonce=KDF(sha256(reqIV),"AEAD Resp Header IV")[:12],
//	                 plaintext=[responseV,0,0,0], AD=nil)
//
// The client decoder (0xb48851) passes an empty additional-data slice and only
// requires a plaintext of at least four bytes whose first byte equals the
// response V it sent (0xb48a89 cmp rbx,4 / 0xb48a9a cmp [conn+0x50],cl).
//
// Body chunk (both directions):
//
//	length  : BE16(payload length), sealed when option bit 0x10 is set
//	          (key = KDF16(bodyKey,"auth_len"), label 0x6e656c5f68747561)
//	payload : sealed with the body AEAD, AD=nil
//	nonce   : the 12-byte IV with bytes [0:2] replaced by BE16(counter); the
//	          counter increments on every Seal/Open (0xb45986, 0xb460d0) and a
//	          counter of 0xffff marks the codec broken (0xb45992/0xb460df).
//
// "none" and "zero" have no body AEAD: the two-byte length and the payload are
// sent in the clear (newAEAD returns nil for 5 and 6, 0xb452b4).
package vmess

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/sha3"
	"net"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// codec is one direction of the chunk stream.
type codec struct {
	data    cipher.AEAD
	lenAEAD cipher.AEAD
	iv      [12]byte
	nonce   [12]byte
	count   uint16
	wraps   bool

	// Chunk masking (option 0x04) and global padding (option 0x08) draw from a
	// SHAKE128 stream seeded with bodyKey||bodyIV (newCodecLen @0xb45320 built a
	// 168-byte SHAKE state and wrote the 32-byte seed).
	mask bool
	pad  bool
	xof  io.Reader
}

// newCodec builds one direction (vmess.newCodecLen @0xb45320).
func newCodec(sec byte, key [16]byte, iv [16]byte, option byte) (*codec, error) {
	c := &codec{}
	copy(c.iv[:], iv[:12])
	copy(c.nonce[:], iv[:12])
	data, err := newAEAD(sec, key[:])
	if err != nil {
		return nil, err
	}
	c.data = data
	if option&(OptionChunkMasking|OptionGlobalPadding) != 0 {
		sh := sha3.NewShake128()
		_, _ = sh.Write(key[:])
		_, _ = sh.Write(iv[:])
		c.xof = sh
		c.mask = option&OptionChunkMasking != 0
		c.pad = option&OptionGlobalPadding != 0
	}
	if data != nil && option&OptionAuthLength != 0 {
		la, err := newAEAD(sec, kdf16(key[:], []byte(kdfAuthLen)))
		if err != nil {
			return nil, err
		}
		c.lenAEAD = la
	}
	return c, nil
}

// next returns the nonce for one AEAD operation and advances the counter.
func (c *codec) next() ([]byte, error) {
	if c.wraps {
		return nil, ErrChunkLimit
	}
	binary.BigEndian.PutUint16(c.nonce[:2], c.count)
	if c.count == 0xffff {
		c.wraps = true
	}
	c.count++
	return c.nonce[:], nil
}

// encodeLen applies masking and padding to a payload length. It returns the
// length to put on the wire and how many zero bytes follow the payload.
func (c *codec) encodeLen(n int) (wire, pad int, err error) {
	pad = 0
	if c.pad {
		var b [2]byte
		if _, err := io.ReadFull(c.xof, b[:]); err != nil {
			return 0, 0, err
		}
		pad = int(binary.BigEndian.Uint16(b[:]) & 0x3f)
	}
	wire = n + pad
	if c.mask {
		var b [2]byte
		if _, err := io.ReadFull(c.xof, b[:]); err != nil {
			return 0, 0, err
		}
		wire ^= int(binary.BigEndian.Uint16(b[:]))
	}
	return wire, pad, nil
}

// decodeLen reverses encodeLen.
func (c *codec) decodeLen(wire int) (n, pad int, err error) {
	// The XOF is shared with the writer, so the draws happen in the writer's
	// order: padding first, then the length mask.
	if c.pad {
		var b [2]byte
		if _, err := io.ReadFull(c.xof, b[:]); err != nil {
			return 0, 0, err
		}
		pad = int(binary.BigEndian.Uint16(b[:]) & 0x3f)
	}
	n = wire
	if c.mask {
		var b [2]byte
		if _, err := io.ReadFull(c.xof, b[:]); err != nil {
			return 0, 0, err
		}
		n ^= int(binary.BigEndian.Uint16(b[:]))
	}
	if n < pad {
		return 0, 0, ErrCorruptChunk
	}
	return n - pad, pad, nil
}

// sealLen seals the two-byte payload length when the authenticated length
// option is active.
func (c *codec) sealLen(n int) ([]byte, error) {
	var lp [2]byte
	binary.BigEndian.PutUint16(lp[:], uint16(n))
	if c.lenAEAD == nil {
		return lp[:], nil
	}
	nonce, err := c.next()
	if err != nil {
		return nil, err
	}
	return c.lenAEAD.Seal(nil, nonce, lp[:], nil), nil
}

// sealChunk seals the payload.
func (c *codec) sealChunk(p []byte) ([]byte, error) {
	if c.data == nil {
		return p, nil
	}
	nonce, err := c.next()
	if err != nil {
		return nil, err
	}
	return c.data.Seal(nil, nonce, p, nil), nil
}

// openLen opens the length block.
func (c *codec) openLen(b []byte) (int, error) {
	if c.lenAEAD == nil {
		return int(binary.BigEndian.Uint16(b)), nil
	}
	nonce, err := c.next()
	if err != nil {
		return 0, err
	}
	plain, err := c.lenAEAD.Open(nil, nonce, b, nil)
	if err != nil || len(plain) != 2 {
		return 0, ErrCorruptChunk
	}
	return int(binary.BigEndian.Uint16(plain)), nil
}

// openChunk opens the payload.
func (c *codec) openChunk(b []byte) ([]byte, error) {
	if c.data == nil {
		return b, nil
	}
	nonce, err := c.next()
	if err != nil {
		return nil, err
	}
	plain, err := c.data.Open(b[:0], nonce, b, nil)
	if err != nil {
		return nil, ErrShortChunk
	}
	return plain, nil
}

// overhead is the tag size of the payload AEAD.
func (c *codec) overhead() int {
	if c.data == nil {
		return 0
	}
	return c.data.Overhead()
}

// lenSize is the wire size of the length block.
func (c *codec) lenSize() int {
	if c.lenAEAD == nil {
		return 2
	}
	return 2 + c.lenAEAD.Overhead()
}

// vmessConn is the relayed connection: it writes the response header before the
// first byte and chunk-encodes both directions.
type vmessConn struct {
	conn     net.Conn
	respV    byte
	option   byte
	security byte

	wKey, wIV [16]byte // sha256(request body key/IV)[:16]
	rKey, rIV [16]byte // raw request body key/IV

	wr, rd *codec

	hdrOnce    sync.Once
	hdrErr     error
	hdrWritten bool

	wmu  sync.Mutex
	rmu  sync.Mutex
	rbuf []byte
}

// Write sends the response header (once) and then one or more chunks.
func (v *vmessConn) Write(p []byte) (int, error) {
	v.wmu.Lock()
	defer v.wmu.Unlock()
	v.hdrOnce.Do(func() {
		v.hdrErr = v.writeResponseHeader()
		v.hdrWritten = v.hdrErr == nil
	})
	if v.hdrErr != nil {
		return 0, v.hdrErr
	}
	if v.wr == nil {
		return v.conn.Write(p)
	}
	written := 0
	for p = p[:]; len(p) > 0; {
		n := len(p)
		if n > 0xffff {
			n = 0xffff
		}
		wire, pad, err := v.wr.encodeLen(n)
		if err != nil {
			return written, err
		}
		lp, err := v.wr.sealLen(wire)
		if err != nil {
			return written, err
		}
		payload := p[:n]
		if pad > 0 {
			payload = append(append([]byte(nil), payload...), make([]byte, pad)...)
		}
		body, err := v.wr.sealChunk(payload)
		if err != nil {
			return written, err
		}
		buf := make([]byte, 0, len(lp)+len(body))
		buf = append(buf, lp...)
		buf = append(buf, body...)
		if _, err := v.conn.Write(buf); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// writeResponseHeader encodes the four-byte response header (0xb4b3e0).
func (v *vmessConn) writeResponseHeader() error {
	lenKey := kdf16(v.wKey[:], []byte(kdfRespLenKey))
	lenIV := kdf(v.wIV[:], []byte(kdfRespLenIV))[:12]
	lenAEAD, err := newGCM(lenKey)
	if err != nil {
		return err
	}
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], 4)
	sealedLen := lenAEAD.Seal(nil, lenIV, lenPlain[:], nil)

	hdrKey := kdf16(v.wKey[:], []byte(kdfRespKey))
	hdrIV := kdf(v.wIV[:], []byte(kdfRespIV))[:12]
	hdrAEAD, err := newGCM(hdrKey)
	if err != nil {
		return err
	}
	hdrPlain := [4]byte{v.respV, 0, 0, 0}
	sealedHdr := hdrAEAD.Seal(nil, hdrIV, hdrPlain[:], nil)

	out := make([]byte, 0, len(sealedLen)+len(sealedHdr))
	out = append(out, sealedLen...)
	out = append(out, sealedHdr...)
	_, err = v.conn.Write(out)
	return err
}

// Read returns payload bytes from the chunk stream.
func (v *vmessConn) Read(p []byte) (int, error) {
	v.rmu.Lock()
	defer v.rmu.Unlock()
	if v.rd == nil {
		return v.conn.Read(p)
	}
	for {
		if len(v.rbuf) > 0 {
			n := copy(p, v.rbuf)
			v.rbuf = v.rbuf[n:]
			return n, nil
		}
		if err := v.readChunk(); err != nil {
			return 0, err
		}
		if len(v.rbuf) == 0 {
			// zero-length chunk: keep reading
			continue
		}
	}
}

// readChunk reads one chunk into v.rbuf (0xb45860).
func (v *vmessConn) readChunk() error {
	lb := make([]byte, v.rd.lenSize())
	if _, err := io.ReadFull(v.conn, lb); err != nil {
		return err
	}
	wire, err := v.rd.openLen(lb)
	if err != nil {
		return err
	}
	if wire == 0 {
		return io.EOF
	}
	n, pad, err := v.rd.decodeLen(wire)
	if err != nil {
		return err
	}
	if n < 0 || n+pad > 0xffff {
		return ErrCorruptChunk
	}
	buf := make([]byte, n+pad+v.rd.overhead())
	if _, err := io.ReadFull(v.conn, buf); err != nil {
		return err
	}
	plain, err := v.rd.openChunk(buf)
	if err != nil {
		return err
	}
	if pad > 0 && len(plain) >= pad {
		plain = plain[:len(plain)-pad]
	}
	v.rbuf = plain
	return nil
}

func (v *vmessConn) Close() error                       { return v.conn.Close() }
func (v *vmessConn) LocalAddr() net.Addr                { return v.conn.LocalAddr() }
func (v *vmessConn) RemoteAddr() net.Addr               { return v.conn.RemoteAddr() }
func (v *vmessConn) SetDeadline(t time.Time) error      { return v.conn.SetDeadline(t) }
func (v *vmessConn) SetReadDeadline(t time.Time) error  { return v.conn.SetReadDeadline(t) }
func (v *vmessConn) SetWriteDeadline(t time.Time) error { return v.conn.SetWriteDeadline(t) }

// CloseWrite flushes and half-closes.
func (v *vmessConn) CloseWrite() error {
	v.wmu.Lock()
	defer v.wmu.Unlock()
	v.hdrOnce.Do(func() {
		v.hdrErr = v.writeResponseHeader()
		v.hdrWritten = v.hdrErr == nil
	})
	if v.hdrErr != nil {
		return v.hdrErr
	}
	return core.CloseWrite(v.conn)
}

// ReadsFrom / WritesTo keep splice paths reachable; the response header must
// still be flushed first, so WritesTo reports the raw connection only after it
// has been written.
func (v *vmessConn) WritesTo() net.Conn {
	v.wmu.Lock()
	defer v.wmu.Unlock()
	if v.hdrWritten {
		return v.conn
	}
	return v
}

var _ net.Conn = (*vmessConn)(nil)

// ---------------------------------------------------------------------------
// UDP

// packetStream carries VMess datagrams. The destination is fixed by the
// request header: kaze does not repeat the address per datagram
// ((*packetStream).ReadPacket @0xb4bea0 returns the stored addr from +8/+0x10
// and the stored port from +0x18).
type packetStream struct {
	conn *vmessConn
	dest socks.Addr
	mu   sync.Mutex
}

const (
	// 0xb4c045: payloads above 16000 bytes (0x3e80) are dropped, as are empty
	// ones (0xb4c040).
	udpMaxPayload = 16000
	// 0x45d964b800 / 0x6fc23ac00.
	udpReadTimeout  = 300 * time.Second
	udpWriteTimeout = 30 * time.Second
)

// ReadPacket reads one datagram (0xb4bea0).
func (s *packetStream) ReadPacket(p []byte) (int, socks.Addr, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(udpReadTimeout))
	s.conn.rmu.Lock()
	defer s.conn.rmu.Unlock()
	if len(s.conn.rbuf) > 0 {
		n := copy(p, s.conn.rbuf)
		s.conn.rbuf = s.conn.rbuf[n:]
		return n, s.dest, nil
	}
	if err := s.conn.readChunk(); err != nil {
		return 0, s.dest, err
	}
	n := copy(p, s.conn.rbuf)
	if n < len(s.conn.rbuf) {
		s.conn.rbuf = s.conn.rbuf[n:]
		return n, s.dest, io.ErrShortBuffer
	}
	s.conn.rbuf = nil
	return n, s.dest, nil
}

// WritePacket writes one datagram (0xb4bfe0).
func (s *packetStream) WritePacket(p []byte, addr socks.Addr) error {
	if len(p) == 0 || len(p) > udpMaxPayload {
		return nil
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
	_, err := s.conn.Write(p)
	return err
}

// Close closes the flow.
func (s *packetStream) Close() error { return s.conn.Close() }

var _ core.PacketStream = (*packetStream)(nil)
