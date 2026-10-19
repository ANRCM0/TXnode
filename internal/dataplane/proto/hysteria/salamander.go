package hysteria

import (
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Salamander obfuscation, as recovered from the sample.
//
// The wire is the standard salamander shape: every UDP datagram is prefixed with
// 8 plaintext random bytes (the salt) and the rest is XOR-ed with a 32-byte
// keystream repeated as needed.
//
// The keystream schedule is NOT upstream's: kaze derives it from the salt
// instead of using a constant blake2b(psk):
//
//	// (*salamander).pad @0xaa6380
//	var block [128]byte
//	copy(block[:], psk)              // n = min(len(psk), 128)
//	copy(block[n:], salt)            // m = min(len(salt), 128-n)
//	key = blake2b.Sum256(block[:])   // @0xa9b700
//
//	// xorPad @0xaa66c0: XOR each byte with key[i%32]
//	// WriteTo @0xaa6be0: buf = salt(8) || xorPad(payload)
//	// ReadFrom @0xaa6820: symmetric
//
// See notes/rev-proto-udp.md §1.4. The OOB batch paths (salamanderOOB.ReadBatch
// @0xaa756f, WriteMsgUDP @0xaa7873) call the same pad, so there is one schedule.
//
// CONSEQUENCE: this variant does not interoperate with upstream hysteria2's
// salamander. The report flagged it as a private variant (§1.4 and REPORT §6.6).

const (
	// salamanderSaltSize is the plaintext salt prefix (8 bytes).
	salamanderSaltSize = 8
	// salamanderKeyBlock is the size of the block blake2b hashes.
	salamanderKeyBlock = 128
	// salamanderKeySize is the blake2b-256 output size.
	salamanderKeySize = 32
	// noiseTag is the label prefixed by NoiseTag. The report quotes the rodata
	// constant at 0xf642fc as "18 B" with bytes
	// 6b617a652d7564702d6e6f6973652d7631, but that hex string is 17 bytes
	// ("kaze-udp-noise-v1"), and 17+32 = 49, not the 50 the report states. The
	// hex is the primary evidence, so the label is 17 bytes here; the extra byte
	// in the report is most likely the rodata string's NUL terminator counted in
	// the length.
	noiseTag = "kaze-udp-noise-v1"
)

// salamanderKey derives the 32-byte keystream key for one datagram.
func salamanderKey(psk, salt []byte) [salamanderKeySize]byte {
	var block [salamanderKeyBlock]byte
	n := copy(block[:], psk)
	if n < len(block) {
		copy(block[n:], salt)
	}
	return blake2b.Sum256(block[:])
}

// xorPad XORs src into dst using the 32-byte key repeated across the buffer.
func xorPad(dst, src, key []byte) {
	for i := range src {
		dst[i] = src[i] ^ key[i%salamanderKeySize]
	}
}

// NoiseTag builds the OOB-path psk: the 17-byte label followed by
// blake2b-256(password), 49 bytes in total (the report says 50; see noiseTag).
//
// Evidence: newSalamanderOOB @0xaa6ee0 calls NoiseTag @0xaa6240, which feeds the
// 18-byte constant and the input to blake2b.Sum256 and concatenates label+digest.
// Confirmed length in the report: 50 B. So the OOB psk is not the password
// itself, another reason this does not match upstream.
func NoiseTag(password []byte) []byte {
	sum := blake2b.Sum256(password)
	out := make([]byte, 0, len(noiseTag)+len(sum))
	out = append(out, noiseTag...)
	out = append(out, sum[:]...)
	return out
}

// salamanderPacketConn wraps a net.PacketConn and applies the salamander
// schedule to every datagram.
type salamanderPacketConn struct {
	pc  net.PacketConn
	psk []byte

	bufPool sync.Pool
}

var errSalamanderShort = errors.New("hysteria: salamander packet shorter than the salt")

// newSalamanderPacketConn wraps pc with the OOB psk derived from the password.
// The wrapper only implements net.PacketConn: the pinned quic-go transports over
// net.PacketConn and turns off GSO for rewritten datagrams, so the batched
// ReadBatch/WriteMsgUDP path of the sample (which needed an OOBCapablePacketConn)
// is not reconstructed. This is a performance, not a wire, difference.
func newSalamanderPacketConn(pc net.PacketConn, password string) net.PacketConn {
	return &salamanderPacketConn{
		pc:  pc,
		psk: NoiseTag([]byte(password)),
		bufPool: sync.Pool{New: func() any {
			b := make([]byte, 0, 64<<10)
			return &b
		}},
	}
}

// ReadFrom decrypts one datagram. The first 8 bytes are the plaintext salt; the
// remainder is XOR-ed with blake2b(psk||salt).
func (c *salamanderPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufp := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bufp)
	buf := (*bufp)[:cap(*bufp)]
	n, addr, err := c.pc.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n < salamanderSaltSize {
		return 0, addr, errSalamanderShort
	}
	salt := buf[:salamanderSaltSize]
	key := salamanderKey(c.psk, salt)
	payload := buf[salamanderSaltSize:n]
	if len(payload) > len(p) {
		return 0, addr, errors.New("hysteria: salamander packet larger than the read buffer")
	}
	xorPad(p, payload, key[:])
	return len(payload), addr, nil
}

// WriteTo encrypts one datagram: 8 random salt bytes, then the XOR-ed payload.
func (c *salamanderPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := make([]byte, salamanderSaltSize+len(p))
	if _, err := rand.Read(out[:salamanderSaltSize]); err != nil {
		return 0, err
	}
	key := salamanderKey(c.psk, out[:salamanderSaltSize])
	xorPad(out[salamanderSaltSize:], p, key[:])
	if _, err := c.pc.WriteTo(out, addr); err != nil {
		return 0, err
	}
	// net.PacketConn reports the plaintext count, like every wrapper does.
	return len(p), nil
}

func (c *salamanderPacketConn) Close() error                       { return c.pc.Close() }
func (c *salamanderPacketConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *salamanderPacketConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *salamanderPacketConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *salamanderPacketConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
