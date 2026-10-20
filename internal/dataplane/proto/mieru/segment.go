package mieru

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Segment layout. The visible header is 14 bytes, and the offsets are the ones
// parsePacket @0x7dc800 decodes (notes/rev-proto-udp.md §3.3):
//
//	buf[0]     code (u8)
//	buf[1]     flags (u8, unused/skipped by the parser)
//	buf[2:6]   timestamp, big endian u32
//	buf[6:10]  payload length, big endian u32
//	buf[10:14] sequence number, big endian u32
//
// Field *names* are inferred (the report marks length vs sequence as I).
//
// The identification hint precedes the header (see crypto.go). One segment is
// therefore:
//
//	hint(16) || header(14) || XChaCha20-Poly1305(payload) || tag(16)
//
// The nonce is derived from the visible header fields, so no nonce is sent and
// the header cannot be swapped without breaking the tag (it is the AAD).
const (
	segmentHeaderLen = 14
	// maxSegmentPayload bounds one segment so a hostile length field cannot
	// allocate arbitrarily. UNVERIFIED: the sample's own cap was not extracted.
	maxSegmentPayload = 32 << 10
	// segmentTimeWindow is how far the timestamp may be from local time.
	// parsePacket compares against time.Now (@0x7dc92b); the window value was
	// not converted (notes §7 item 5).
	segmentTimeWindow = 60 * time.Second
)

// Segment codes.
const (
	// segOpen carries the destination address for a TCP stream.
	segOpen = 1
	// segData carries stream payload.
	segData = 2
	// segClose closes the stream.
	segClose = 3
	// segPacket carries one UDP datagram (address + payload).
	segPacket = 4
)

// segmentCipher seals and opens segments for one key.
type segmentCipher struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	key  [keySize]byte
	hint []byte
}

func newSegmentCipher(key [keySize]byte) (*segmentCipher, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	hint, err := hintFromKey(key[:])
	if err != nil {
		return nil, err
	}
	return &segmentCipher{aead: aead, key: key, hint: hint}, nil
}

// segmentNonce builds the 24-byte nonce from the visible header.
func segmentNonce(code byte, ts, seq, length uint32) [nonceSize]byte {
	var nonce [nonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], ts)
	binary.BigEndian.PutUint32(nonce[4:8], seq)
	binary.BigEndian.PutUint32(nonce[8:12], length)
	nonce[12] = code
	return nonce
}

// seal builds one segment.
func (c *segmentCipher) seal(code byte, ts, seq uint32, plaintext []byte) []byte {
	return c.sealWithFlags(code, 0, ts, seq, plaintext)
}

func (c *segmentCipher) sealWithFlags(code, flags byte, ts, seq uint32, plaintext []byte) []byte {
	total := hintLen + segmentHeaderLen + len(plaintext) + tagSize
	seg := make([]byte, hintLen+segmentHeaderLen, total)
	copy(seg, c.hint)
	h := seg[hintLen:]
	h[0] = code
	h[1] = flags
	binary.BigEndian.PutUint32(h[2:6], ts)
	binary.BigEndian.PutUint32(h[6:10], uint32(len(plaintext)))
	binary.BigEndian.PutUint32(h[10:14], seq)
	nonce := segmentNonce(code, ts, seq, uint32(len(plaintext)))
	return c.aead.Seal(seg, nonce[:], plaintext, h)
}

// parsedSegment is an opened segment.
type parsedSegment struct {
	code    byte
	flags   byte
	ts      uint32
	length  uint32
	seq     uint32
	payload []byte
}

// errSegmentMalformed means the container cannot be parsed at all (independent
// of the key).
var errSegmentMalformed = errors.New("mieru: malformed segment")

// open decrypts a segment that was already read in full.
func (c *segmentCipher) open(seg []byte) (*parsedSegment, error) {
	if len(seg) < hintLen+segmentHeaderLen+tagSize {
		return nil, errSegmentMalformed
	}
	h := seg[hintLen : hintLen+segmentHeaderLen]
	length := binary.BigEndian.Uint32(h[6:10])
	if int(length) != len(seg)-hintLen-segmentHeaderLen-tagSize {
		return nil, errSegmentMalformed
	}
	nonce := segmentNonce(h[0], binary.BigEndian.Uint32(h[2:6]), binary.BigEndian.Uint32(h[10:14]), length)
	plain, err := c.aead.Open(nil, nonce[:], seg[hintLen+segmentHeaderLen:], h)
	if err != nil {
		return nil, err
	}
	return &parsedSegment{
		code:    h[0],
		flags:   h[1],
		ts:      binary.BigEndian.Uint32(h[2:6]),
		length:  length,
		seq:     binary.BigEndian.Uint32(h[10:14]),
		payload: plain,
	}, nil
}

// readSegment reads hint+header, validates the announced length and returns the
// whole segment.
func readSegment(r io.Reader) ([]byte, error) {
	var prefix [hintLen + segmentHeaderLen]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(prefix[hintLen+6 : hintLen+10])
	if length > maxSegmentPayload {
		return nil, fmt.Errorf("mieru: segment length %d exceeds %d", length, maxSegmentPayload)
	}
	seg := make([]byte, len(prefix)+int(length)+tagSize)
	copy(seg, prefix[:])
	if _, err := io.ReadFull(r, seg[len(prefix):]); err != nil {
		return nil, err
	}
	return seg, nil
}

// withinWindow checks the segment timestamp against local time.
func withinWindow(ts uint32) bool {
	sent := time.Unix(int64(ts), 0)
	d := time.Since(sent)
	if d < 0 {
		d = -d
	}
	return d <= segmentTimeWindow
}

// Address encoding for the segOpen / segPacket payloads: SOCKS5 type numbers
// (1 IPv4, 3 domain, 4 IPv6) followed by the address and a big-endian port.
// UNVERIFIED: the sample's own address codec was not decoded (notes §7 items 5–6).
func encodeAddr(a socks.Addr) []byte {
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			v4 := ip.As4()
			out := append([]byte{1}, v4[:]...)
			return binary.BigEndian.AppendUint16(out, a.Port)
		}
		v6 := ip.As16()
		out := append([]byte{4}, v6[:]...)
		return binary.BigEndian.AppendUint16(out, a.Port)
	}
	out := append([]byte{3, byte(len(a.Host))}, a.Host...)
	return binary.BigEndian.AppendUint16(out, a.Port)
}

func decodeAddr(b []byte) (socks.Addr, int, error) {
	if len(b) < 1 {
		return socks.Addr{}, 0, errSegmentMalformed
	}
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return socks.Addr{}, 0, errSegmentMalformed
		}
		return socks.Addr{Host: net.IP(b[1:5]).String(), Port: binary.BigEndian.Uint16(b[5:7])}, 7, nil
	case 4:
		if len(b) < 19 {
			return socks.Addr{}, 0, errSegmentMalformed
		}
		return socks.Addr{Host: net.IP(b[1:17]).String(), Port: binary.BigEndian.Uint16(b[17:19])}, 19, nil
	case 3:
		if len(b) < 2 || len(b) < 2+int(b[1])+2 {
			return socks.Addr{}, 0, errSegmentMalformed
		}
		l := int(b[1])
		return socks.Addr{Host: string(b[2 : 2+l]), Port: binary.BigEndian.Uint16(b[2+l : 2+l+2])}, 2 + l + 2, nil
	}
	return socks.Addr{}, 0, fmt.Errorf("mieru: unknown address type %d", b[0])
}
