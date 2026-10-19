package shadowsocks

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

var (
	errAsconKey  = errors.New("ascon: bad key length")
	errAsconAuth = errors.New("ascon: authentication failed")
)

// Ascon AEAD (v1.2), implemented in-package because the sample does the same
// (shadowsocks.ascon128 @0xb10fa0, ascon128a @0xb110a0, asconAEAD @0xb111a0)
// rather than pulling a dependency. Two variants exist in the method table:
//
//	ascon128   rate 64 bits,  b=6 rounds
//	ascon128a  rate 128 bits, b=8 rounds
//
// Both use a 128-bit key, a 128-bit nonce and a 128-bit tag. The test vectors in
// ascon_test.go are the official LWC KAT files (ascon-c v1.2).
type asconAEAD struct {
	key  [2]uint64
	rate int // bytes
	b    int // rounds for the intermediate permutation
}

const (
	asconIV128  = 0x80400c0600000000
	asconIV128a = 0x80800c0800000000
)

var asconRoundC = [12]uint64{
	0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
	0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
}

// newAscon128 returns the 64-bit-rate variant.
func newAscon128(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 {
		return nil, errAsconKey
	}
	return &asconAEAD{
		key:  [2]uint64{binary.BigEndian.Uint64(key[0:8]), binary.BigEndian.Uint64(key[8:16])},
		rate: 8,
		b:    6,
	}, nil
}

// newAscon128a returns the 128-bit-rate variant.
func newAscon128a(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 {
		return nil, errAsconKey
	}
	return &asconAEAD{
		key:  [2]uint64{binary.BigEndian.Uint64(key[0:8]), binary.BigEndian.Uint64(key[8:16])},
		rate: 16,
		b:    8,
	}, nil
}

func (a *asconAEAD) NonceSize() int { return 16 }
func (a *asconAEAD) Overhead() int  { return 16 }

func asconPermute(s *[5]uint64, rounds int) {
	for i := 12 - rounds; i < 12; i++ {
		s[2] ^= asconRoundC[i]
		// substitution layer
		x0, x1, x2, x3, x4 := s[0], s[1], s[2], s[3], s[4]
		x0 ^= x4
		x4 ^= x3
		x2 ^= x1
		t0 := ^x0 & x1
		t1 := ^x1 & x2
		t2 := ^x2 & x3
		t3 := ^x3 & x4
		t4 := ^x4 & x0
		x0 ^= t1
		x1 ^= t2
		x2 ^= t3
		x3 ^= t4
		x4 ^= t0
		x1 ^= x0
		x0 ^= x4
		x3 ^= x2
		x2 = ^x2
		// linear diffusion
		x0 ^= bits.RotateLeft64(x0, -19) ^ bits.RotateLeft64(x0, -28)
		x1 ^= bits.RotateLeft64(x1, -61) ^ bits.RotateLeft64(x1, -39)
		x2 ^= bits.RotateLeft64(x2, -1) ^ bits.RotateLeft64(x2, -6)
		x3 ^= bits.RotateLeft64(x3, -10) ^ bits.RotateLeft64(x3, -17)
		x4 ^= bits.RotateLeft64(x4, -7) ^ bits.RotateLeft64(x4, -41)
		s[0], s[1], s[2], s[3], s[4] = x0, x1, x2, x3, x4
	}
}

func (a *asconAEAD) init(nonce []byte) [5]uint64 {
	var s [5]uint64
	if a.rate == 8 {
		s[0] = asconIV128
	} else {
		s[0] = asconIV128a
	}
	s[1] = a.key[0]
	s[2] = a.key[1]
	s[3] = binary.BigEndian.Uint64(nonce[0:8])
	s[4] = binary.BigEndian.Uint64(nonce[8:16])
	asconPermute(&s, 12)
	s[3] ^= a.key[0]
	s[4] ^= a.key[1]
	return s
}

// xorBlock XORs a full rate block into the state.
func (a *asconAEAD) xorBlock(s *[5]uint64, b []byte) {
	s[0] ^= binary.BigEndian.Uint64(b[0:8])
	if a.rate == 16 {
		s[1] ^= binary.BigEndian.Uint64(b[8:16])
	}
}

// xorPartial XORs len(b) < rate bytes and applies the 10* padding.
func (a *asconAEAD) xorPartial(s *[5]uint64, b []byte) {
	for i := 0; i < len(b); i++ {
		s[i/8] ^= uint64(b[i]) << (56 - 8*(i%8))
	}
	s[len(b)/8] ^= 0x80 << (56 - 8*(len(b)%8))
}

// stateBytes renders the rate bytes of the state (big-endian words).
func (a *asconAEAD) stateBytes(s *[5]uint64) [16]byte {
	var out [16]byte
	binary.BigEndian.PutUint64(out[0:8], s[0])
	if a.rate == 16 {
		binary.BigEndian.PutUint64(out[8:16], s[1])
	}
	return out
}

func (a *asconAEAD) absorbAD(s *[5]uint64, ad []byte) {
	if len(ad) == 0 {
		return
	}
	for len(ad) >= a.rate {
		a.xorBlock(s, ad[:a.rate])
		asconPermute(s, a.b)
		ad = ad[a.rate:]
	}
	a.xorPartial(s, ad)
	asconPermute(s, a.b)
}

func (a *asconAEAD) finalize(s *[5]uint64) [16]byte {
	// Reference order (ascon-c aead.c): Ascon-128 mixes the key into x1/x2,
	// Ascon-128a into x2/x3; then P12 and x3/x4.
	if a.rate == 16 {
		s[2] ^= a.key[0]
		s[3] ^= a.key[1]
	} else {
		s[1] ^= a.key[0]
		s[2] ^= a.key[1]
	}
	asconPermute(s, 12)
	s[3] ^= a.key[0]
	s[4] ^= a.key[1]
	var tag [16]byte
	binary.BigEndian.PutUint64(tag[0:8], s[3])
	binary.BigEndian.PutUint64(tag[8:16], s[4])
	return tag
}

func (a *asconAEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	if len(nonce) != 16 {
		panic("ascon: bad nonce length")
	}
	s := a.init(nonce)
	a.absorbAD(&s, ad)
	s[4] ^= 0x01
	out := make([]byte, 0, len(plaintext)+16)
	pt := plaintext
	for len(pt) >= a.rate {
		a.xorBlock(&s, pt[:a.rate])
		block := a.stateBytes(&s)
		out = append(out, block[:a.rate]...)
		asconPermute(&s, a.b)
		pt = pt[a.rate:]
	}
	// Final partial block: ciphertext is state XOR plaintext, then pad.
	if len(pt) > 0 {
		a.xorPartialNoPad(&s, pt)
		block := a.stateBytes(&s)
		out = append(out, block[:len(pt)]...)
		a.xorPad(&s, len(pt))
	} else {
		a.xorPad(&s, 0)
	}
	tag := a.finalize(&s)
	out = append(out, tag[:]...)
	return append(dst, out...)
}

func (a *asconAEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(nonce) != 16 || len(ciphertext) < 16 {
		return nil, errAsconAuth
	}
	tag := ciphertext[len(ciphertext)-16:]
	ct := ciphertext[:len(ciphertext)-16]
	s := a.init(nonce)
	a.absorbAD(&s, ad)
	s[4] ^= 0x01
	out := make([]byte, 0, len(ct))
	for len(ct) >= a.rate {
		block := a.stateBytes(&s)
		var p [16]byte
		for i := 0; i < a.rate; i++ {
			p[i] = block[i] ^ ct[i]
		}
		out = append(out, p[:a.rate]...)
		a.xorBlock(&s, p[:a.rate])
		asconPermute(&s, a.b)
		ct = ct[a.rate:]
	}
	if len(ct) > 0 {
		block := a.stateBytes(&s)
		p := make([]byte, len(ct))
		for i := range ct {
			p[i] = block[i] ^ ct[i]
		}
		out = append(out, p...)
		a.xorPartialNoPad(&s, p)
		a.xorPad(&s, len(p))
	} else {
		a.xorPad(&s, 0)
	}
	want := a.finalize(&s)
	if subtle.ConstantTimeCompare(tag, want[:]) != 1 {
		return nil, errAsconAuth
	}
	return append(dst, out...), nil
}

// xorPartialNoPad XORs bytes without padding (used on the ciphertext path).
func (a *asconAEAD) xorPartialNoPad(s *[5]uint64, b []byte) {
	for i := 0; i < len(b); i++ {
		s[i/8] ^= uint64(b[i]) << (56 - 8*(i%8))
	}
}

// xorPad applies the 10* padding for a block of n bytes.
func (a *asconAEAD) xorPad(s *[5]uint64, n int) {
	s[n/8] ^= 0x80 << (56 - 8*(n%8))
}
