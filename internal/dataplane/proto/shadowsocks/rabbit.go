package shadowsocks

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/sina-ghaderi/rabbitio"
	"golang.org/x/crypto/poly1305"
)

// polyKeySize is the Poly1305 key length; x/crypto/poly1305 does not export it.
const polyKeySize = 32

// errRabbitKey ← "rabbit128-poly1305: bad key length" @0xf7a694
// (shadowsocks.rabbitAEAD @0xb16422).
var errRabbitKey = errors.New("rabbit128-poly1305: bad key length")

// rabbitPoly1305 is shadowsocks.rabbitPoly1305 (@0xb16480 family): Rabbit
// keystream plus Poly1305. The binary's methods are NonceSize, Overhead, tag,
// Seal and Open (@0xb16a80).
//
// Construction: the first 32 keystream bytes are the Poly1305 key, the rest is
// the ciphertext mask. The Rabbit IV is the first 8 bytes of the AEAD nonce
// (rabbitio requires an 8-byte IV).
//
// UNVERIFIED: the nonce size (12) and the IV slice are our reading; the binary
// exposes nonce handling only through the AEAD interface, and this method is a
// kaze/mihomo extension that no standard client negotiates.
type rabbitPoly1305 struct {
	key []byte
}

func (r *rabbitPoly1305) NonceSize() int { return 12 }
func (r *rabbitPoly1305) Overhead() int  { return poly1305.TagSize }

func (r *rabbitPoly1305) keystream(nonce []byte, n int) ([]byte, error) {
	iv := make([]byte, 8)
	copy(iv, nonce)
	stream, err := rabbitio.NewCipher(r.key, iv)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	stream.XORKeyStream(out, out)
	return out, nil
}

func (r *rabbitPoly1305) Seal(dst, nonce, plaintext, ad []byte) []byte {
	ks, err := r.keystream(nonce, polyKeySize+len(plaintext))
	if err != nil {
		return nil
	}
	var polyKey [polyKeySize]byte
	copy(polyKey[:], ks)
	ct := make([]byte, len(plaintext))
	subtle.XORBytes(ct, plaintext, ks[polyKeySize:])

	var tag [poly1305.TagSize]byte
	poly1305.Sum(&tag, ct, &polyKey)

	dst = append(dst, ct...)
	return append(dst, tag[:]...)
}

func (r *rabbitPoly1305) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(ciphertext) < poly1305.TagSize {
		return nil, errors.New("rabbit128-poly1305: short ciphertext")
	}
	ct := ciphertext[:len(ciphertext)-poly1305.TagSize]
	var got [poly1305.TagSize]byte
	copy(got[:], ciphertext[len(ciphertext)-poly1305.TagSize:])

	ks, err := r.keystream(nonce, polyKeySize+len(ct))
	if err != nil {
		return nil, err
	}
	var polyKey [polyKeySize]byte
	copy(polyKey[:], ks)
	if !poly1305.Verify(&got, ct, &polyKey) {
		return nil, errAuth
	}
	pt := make([]byte, len(ct))
	subtle.XORBytes(pt, ct, ks[polyKeySize:])
	return append(dst, pt...), nil
}

var _ cipher.AEAD = (*rabbitPoly1305)(nil)
