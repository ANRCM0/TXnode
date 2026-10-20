package hysteria

import (
	crand "crypto/rand"
	"encoding/binary"
)

// Padding bounds. Evidence: (*client).ServeHTTP calls padding(0x100, 0x700) for
// the Hysteria-Padding header (notes/rev-proto-udp.md §1.5), and padding
// @0xaa2ba0 computes:
//
//	uint16 r; crypto_rand.Read(&r, 2); r = bswap16(r)
//	n = min + (uint64(r) % max)
//
// so the length lands in [256, 256+1792) = 256..2047 bytes, matching the report's
// "256–2047".
const (
	paddingMin = 0x100 // 256
	paddingMax = 0x700 // 1792
)

// paddingCharset is base62 (a-zA-Z0-9). The binary's charset lives at 0xf9610a;
// the report only records the character classes, so the exact order is
// UNVERIFIED. It cannot matter for interop: the header is volume shaping, the
// peer never interprets its bytes.
const paddingCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// padding returns a random base62 string of length in [min, min+max).
//
// The modulo of a uniform uint16 by 1792 is very slightly biased (1792 does not
// divide 65536); the binary has the same bias, so it is reproduced rather than
// fixed.
func padding(min, max uint16) string {
	if max == 0 {
		return ""
	}
	var b [2]byte
	if _, err := crand.Read(b[:]); err != nil {
		// crypto/rand failing is fatal for every other part of the protocol too;
		// fall back to the minimum length rather than panicking in a handler.
		return paddingCharset[:min%uint16(len(paddingCharset))+1]
	}
	r := binary.BigEndian.Uint16(b[:])
	n := int(min) + int(r%max)
	out := make([]byte, n)
	// Reuse the same random word for the fill: the sample calls
	// crypto_rand.Read(buf, n) and then maps each byte into the charset, which
	// for a header value is equivalent to fresh random characters.
	var chunk [256]byte
	for i := 0; i < n; {
		if _, err := crand.Read(chunk[:]); err != nil {
			for ; i < n; i++ {
				out[i] = paddingCharset[i%len(paddingCharset)]
			}
			return string(out)
		}
		for _, c := range chunk[:] {
			if i >= n {
				break
			}
			out[i] = paddingCharset[c%byte(len(paddingCharset))]
			i++
		}
	}
	return string(out)
}
