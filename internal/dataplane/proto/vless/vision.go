// Vision framing (xtls-rprx-vision).
//
// Evidence: REPORT.md §17.3.2; notes/rev-proto-tcp.md §1.4;
// notes/rev-round2-proto.md §B.2–§B.3; notes/rev-round2b-proto.md §1.1–§1.6.
//
// Frame layout written by (*visionConn).appendFrame @0xb3b620:
//
//	H[0]     cmd                        0xb3b7dc  mov [rbx+rax-5], r8b
//	H[1..2]  payload length, big endian 0xb3b7e9  mov [rbx+rax-4], r8w
//	H[3]     padding length high byte   0xb3b7f6  mov [rbx+rax-2], dl
//	H[4]     padding length low byte    0xb3b7fa  mov [rbx+rax-1], r8b
//	payload || padding
//
// Padding: two bytes from crypto/rand (0xb3b686 -> 0x52ef20 crypto/rand.Read),
// read big endian (0xb3b690 rol dx,8):
//
//	n < 900 && pad requested:  pad = 900 + (rnd % 500) - n   (0xb3b6af..0xb3b6d9)
//	n >= 900 or no padding:    pad = rnd & 0xff              (0xb3b697)
//	then clamped to [0, 8171-n]                              (0xb3b6ea, 0x1feb)
//
// The padding area is cleared and then filled with crypto/rand
// (0xb3b8a2 memclrNoHeapPointers, 0xb3b900 crypto/rand.Read).
package vless

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"sync"

	"github.com/ANRCM0/TX-Node/internal/dataplane/tlsbuf"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

const (
	visionHeaderLen = 5
	// 0x384: payloads at or above this size skip the 900-based formula.
	visionPadBase = 900
	// 0x1f4: jitter window, pad = 900 + rnd%500 - n.
	visionPadJitter = 500
	// 0x1feb: hard upper bound of the padding, 8171-n.
	visionPadLimit = 8171

	// Vision command bytes. (*visionConn).Write selects 1 for data and 2 for
	// direct (0xb3bd3c/0xb3bd43); endFrame rejects everything outside 0..2.
	visionCmdEnd    byte = 0
	visionCmdData   byte = 1
	visionCmdDirect byte = 2
)

// errVisionDirect is returned when the peer asks for a direct (cmd==2) frame.
// The sample's direct path drains crypto/tls internals through tlsbuf
// (visionConn.bufs, 0xb3b336); without that package the honest answer is the
// probe-failure error and the connection is torn down — the sample has no
// fallback (notes/rev-round2b-proto.md §0).
var errVisionDirect = ErrTLSInternals

// visionConn wraps the VLESS stream in the Vision frame layer. It implements
// net.Conn on top of the *respConn, so the two-byte VLESS response header still
// precedes the first frame.
type visionConn struct {
	net.Conn

	uuid [16]byte

	// prefixUUID reproduces the first-frame 16-byte UUID prefix of appendFrame
	// (0xb3b71e tests vc[0x9a]; 0xb3b789 copies vc[0x20..0x2f]). UNVERIFIED:
	// the outbound side is reported not to expect it, so it defaults to off and
	// can be enabled with Options.VisionUUIDPrefix to match the sample exactly.
	prefixUUID bool
	firstWrite bool

	wmu sync.Mutex

	rmu     sync.Mutex
	rHeader [visionHeaderLen]byte
	rLeft   int // payload bytes still to hand out
	rPad    int // padding bytes still to discard
	rFirst  bool
	rBuf    []byte

	// direct is set when the peer switches to a cmd==2 frame: from then on the
	// bytes are handed over unframed, starting with whatever crypto/tls has
	// already decrypted (the sample drains it through internal/tlsbuf,
	// endFrame @0xb3b336 -> tlsBuffers @0xb3ab40).
	direct  bool
	pending []byte
}

// newVisionConn wraps wrapped in the frame layer. tlsConn is the connection the
// TLS 1.3 admission rule is evaluated on: it is the transport connection, not
// the respConn wrapper, because only the former exposes ConnectionState.
func newVisionConn(wrapped, tlsConn net.Conn, uuid [16]byte, prefix bool) (*visionConn, error) {
	if !isTLS13(tlsConn) {
		return nil, ErrVisionNeedsTLS13
	}
	return &visionConn{Conn: wrapped, uuid: uuid, prefixUUID: prefix, firstWrite: true, rFirst: true}, nil
}

// isTLS13 implements the admission rule of notes/rev-round2-proto.md §C.4: the
// underlying connection must be TLS and must have negotiated 0x0304
// (0xb3dd67 cmp word [rsp+0x358], 0x304). The sample asserts the concrete
// *tls.Conn; a reflective fallback also accepts uTLS-style states.
func isTLS13(c net.Conn) bool {
	if tc, ok := c.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return tc.ConnectionState().Version == tls.VersionTLS13
	}
	v := reflect.ValueOf(c)
	if !v.IsValid() {
		return false
	}
	m := v.MethodByName("ConnectionState")
	if !m.IsValid() || m.Type().NumIn() != 0 || m.Type().NumOut() != 1 {
		return false
	}
	st := m.Call(nil)[0]
	f := st.FieldByName("Version")
	if !f.IsValid() || f.Kind() != reflect.Uint16 {
		return false
	}
	return uint16(f.Uint()) == tls.VersionTLS13
}

// visionPad returns the padding length for a payload of n bytes. rnd is the
// 16-bit big-endian value from crypto/rand; doPad selects the 900-based
// formula (the sample passes doPad=1 for ordinary data frames).
func visionPad(n int, rnd uint16, doPad bool) int {
	var p int
	if doPad && n < visionPadBase {
		p = visionPadBase + int(rnd%visionPadJitter) - n
	} else {
		p = int(rnd & 0xff)
	}
	if max := visionPadLimit - n; p > max {
		p = max
	}
	if p < 0 {
		p = 0
	}
	return p
}

// appendFrame appends one Vision frame to dst.
func appendFrame(dst []byte, cmd byte, payload []byte, doPad bool) ([]byte, error) {
	var rndBuf [2]byte
	if _, err := rand.Read(rndBuf[:]); err != nil {
		return nil, err
	}
	pad := visionPad(len(payload), binary.BigEndian.Uint16(rndBuf[:]), doPad)

	hdr := [visionHeaderLen]byte{cmd}
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(payload)))
	binary.BigEndian.PutUint16(hdr[3:5], uint16(pad))

	dst = append(dst, hdr[:]...)
	dst = append(dst, payload...)
	if pad > 0 {
		off := len(dst)
		dst = append(dst, make([]byte, pad)...)
		// The sample clears the area and then randomises it.
		if _, err := rand.Read(dst[off:]); err != nil {
			return nil, err
		}
	}
	return dst, nil
}

// Write frames p as one data frame (cmd==1). Payloads above 65535 bytes cannot
// be represented in the 16-bit length field; they are split into frames.
func (c *visionConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > 0xffff {
			n = 0xffff
		}
		out := make([]byte, 0, visionHeaderLen+n+256)
		if c.prefixUUID && c.firstWrite {
			out = append(out, c.uuid[:]...)
		}
		out, err := appendFrame(out, visionCmdData, p[:n], true)
		if err != nil {
			return written, err
		}
		if _, err := c.Conn.Write(out); err != nil {
			return written, err
		}
		c.firstWrite = false
		written += n
		p = p[n:]
	}
	return written, nil
}

// Read returns payload bytes from the frame stream, discarding padding.
func (c *visionConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.direct {
		return c.readDirect(p)
	}
	for {
		if c.rLeft > 0 {
			n := c.rLeft
			if n > len(p) {
				n = len(p)
			}
			got, err := io.ReadFull(c.Conn, p[:n])
			c.rLeft -= got
			if err != nil {
				return got, err
			}
			if c.rLeft == 0 {
				if err := c.drainPadding(); err != nil {
					return got, err
				}
			}
			return got, nil
		}
		if err := c.nextFrame(); err != nil {
			return 0, err
		}
	}
}

// drainPadding discards the padding bytes of the current frame.
func (c *visionConn) drainPadding() error {
	if c.rPad <= 0 {
		c.rPad = 0
		return nil
	}
	if c.rBuf == nil {
		c.rBuf = make([]byte, 4096)
	}
	for c.rPad > 0 {
		n := c.rPad
		if n > len(c.rBuf) {
			n = len(c.rBuf)
		}
		if _, err := io.ReadFull(c.Conn, c.rBuf[:n]); err != nil {
			return err
		}
		c.rPad -= n
	}
	return nil
}

// nextFrame reads the next 5-byte header.
func (c *visionConn) nextFrame() error {
	if c.rFirst {
		c.rFirst = false
		if c.prefixUUID {
			var skip [16]byte
			if _, err := io.ReadFull(c.Conn, skip[:]); err != nil {
				return err
			}
		}
	}
	if _, err := io.ReadFull(c.Conn, c.rHeader[:]); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(c.rHeader[1:3]))
	pad := int(binary.BigEndian.Uint16(c.rHeader[3:5]))
	switch cmd := c.rHeader[0]; cmd {
	case visionCmdEnd, visionCmdData:
		c.rLeft, c.rPad = length, pad
		return nil
	case visionCmdDirect:
		// Direct mode: the rest of the stream is unframed. It only works when
		// the TLS internals can be read (the sample's tlsbuf probe); otherwise
		// the connection is torn down with the probe-failure wording.
		if !tlsbuf.Available() {
			return errVisionDirect
		}
		c.direct = true
		if tc := underlyingTLS(c.Conn); tc != nil {
			c.pending = tlsbuf.Pending(tc)
		}
		return nil
	default:
		return ErrUnknownVisionCommand
	}
}

// readDirect hands out the buffered plaintext and then the raw stream.
func (c *visionConn) readDirect(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// underlyingTLS unwraps to the *tls.Conn when the transport is TLS.
func underlyingTLS(c net.Conn) *tls.Conn {
	type unwrapper interface{ Unwrap() net.Conn }
	for i := 0; i < 8 && c != nil; i++ {
		if tc, ok := c.(*tls.Conn); ok {
			return tc
		}
		u, ok := c.(unwrapper)
		if !ok {
			return nil
		}
		c = u.Unwrap()
	}
	return nil
}

// CloseWrite ends the Vision stream with a zero-filled cmd==0 header, then
// half-closes the underlying connection (endFrame mode 1 writes
// byte[rax+0x41]=0).
func (c *visionConn) CloseWrite() error {
	c.wmu.Lock()
	var hdr [visionHeaderLen]byte
	_, err := c.Conn.Write(hdr[:])
	c.wmu.Unlock()
	if err != nil {
		return err
	}
	return core.CloseWrite(c.Conn)
}

// ReadsFrom / WritesTo keep the splice paths reachable through the wrapper
// ((*visionConn).ReadsFrom @0xb3c200, WritesTo @0xb3c220).
func (c *visionConn) ReadsFrom() net.Conn { return c.Conn }
func (c *visionConn) WritesTo() net.Conn  { return c.Conn }
