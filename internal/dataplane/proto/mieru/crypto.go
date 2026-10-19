// Package mieru implements the Mieru inbound of kaze (TCP and UDP).
//
// Evidence: kazecore/notes/rev-proto-udp.md §3 (mieru) and REPORT.md §6.8. The
// binary's package has 153 functions. The cryptography is fully confirmed:
//
//   - the only AEAD constructor in the whole package is
//     chacha20poly1305.NewX (24-byte nonce), at (*Handler).identifyWhere
//     @0x7d87a9, so the suite is XChaCha20-Poly1305 and nothing else;
//   - keys come from PBKDF2 (crypto/pbkdf2.Key @0x7ea0a0) over a SHA-256
//     normalised password (deriveKey @0x7d7d00);
//   - user identification tries to decrypt a 16-byte hint with every key in
//     h->keys (element size 0x38) at 0x7d8661;
//   - a scanGate (@0x7d8b40 and friends) budgets the unhinted scan attempts;
//   - TCP is Handler.ServeConn @0x7d8e80, UDP is ListenUDP @0x7e6ae0 with
//     UDPServer.{read,handle,identify,scanner,opened,dispatch@0x7e82c0,open,
//     write,sweep} and PacketSession (NewPacketSession @0x7e0700).
//
// UNVERIFIED: the segment body layout beyond the 14-byte header that
// parsePacket @0x7dc800 decodes (code u8, ts u32 BE at +2, u32 BE at +6, u32 BE
// at +10 — offsets are facts, field names are not: notes §7 item 5), the PBKDF2
// iteration count, the packet-session state machine (notes §7 item 3) and the
// Pattern/padding shape (notes §7 item 4) are all unresolved. The framing below
// is a coherent kaze-replication wire that keeps every confirmed offset and
// primitive; it is documented rather than presented as the sample's bytes.
package mieru

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// keySize is the XChaCha20-Poly1305 key length (chacha20poly1305.KeySize).
	keySize = chacha20poly1305.KeySize
	// nonceSize is the extended nonce length (24 bytes, NewX).
	nonceSize = chacha20poly1305.NonceSizeX
	// tagSize is the Poly1305 tag length.
	tagSize = chacha20poly1305.Overhead
	// hintLen is the identification hint length: "试解 16 B 提示" (0x7d8661).
	hintLen = 16
	// defaultIterations is the PBKDF2 work factor. UNVERIFIED: the report only
	// confirms crypto/pbkdf2.Key, not the count. 4096 keeps a per-user
	// derivation cheap enough for a node that derives once per user.
	defaultIterations = 4096
)

// hintMark is the 16-byte plaintext the hint decrypts to. Any fixed value works;
// a distinct one keeps a stray hint from matching.
var hintMark = []byte("kaze-mieru-hint!")

// zeroNonce is the XChaCha20 nonce used for the identification hint. It is a
// fixed nonce on purpose: the hint is an identifier, not a secret, and every
// key derives its own keystream.
var zeroNonce [nonceSize]byte

// errBadHint is returned when no key matches the hint.
var errBadHint = errors.New("mieru: no user matches the hint")

// DeriveKey derives a user key: PBKDF2-SHA256(sha256(password), salt=username).
//
// Evidence: deriveKey @0x7d7d00 calls crypto/pbkdf2.Key after normalising the
// password with sha256.Sum256 (0x7d7d39 -> 0x7d7d9a). The salt is the username in
// mieru's design; the report does not extract the salt bytes, so this is
// INFERRED from the username/password user model.
func DeriveKey(username string, password []byte) [keySize]byte {
	return DeriveKeyIter(username, password, defaultIterations)
}

// DeriveKeyIter is DeriveKey with an explicit PBKDF2 iteration count.
func DeriveKeyIter(username string, password []byte, iter int) [keySize]byte {
	if iter <= 0 {
		iter = defaultIterations
	}
	normalized := sha256.Sum256(password)
	k, err := pbkdf2.Key(sha256.New, string(normalized[:]), []byte(username), iter, keySize)
	var out [keySize]byte
	if err != nil {
		copy(out[:], normalized[:])
		return out
	}
	copy(out[:], k)
	return out
}

// hintFromKey produces the identification hint for one key: XChaCha20 with the
// fixed nonce over the 16-byte marker.
func hintFromKey(key []byte) ([]byte, error) {
	c, err := chacha20.NewUnauthenticatedCipher(key, zeroNonce[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, hintLen)
	c.XORKeyStream(out, hintMark)
	return out, nil
}

// keyMatchesHint re-derives the keystream with key and reports whether the hint
// decrypts to the marker.
func keyMatchesHint(key, hint []byte) bool {
	if len(hint) != hintLen || len(key) != keySize {
		return false
	}
	c, err := chacha20.NewUnauthenticatedCipher(key, zeroNonce[:])
	if err != nil {
		return false
	}
	plain := make([]byte, hintLen)
	c.XORKeyStream(plain, hint)
	return subtle.ConstantTimeCompare(plain, hintMark) == 1
}

// newAEAD builds the single XChaCha20-Poly1305 instance.
func newAEAD(key []byte) (interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}, error) {
	return chacha20poly1305.NewX(key)
}
