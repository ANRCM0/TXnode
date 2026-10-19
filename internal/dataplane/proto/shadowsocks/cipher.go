package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/RyuaNerin/go-krypto/lea"
	"github.com/Yawning/aez"
	"github.com/ericlagergren/aegis"
	"github.com/oasisprotocol/deoxysii"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// methodKind distinguishes the two wire formats.
type methodKind int

const (
	// kindClassic is SIP004 AEAD (salt + length/payload chunks).
	kindClassic methodKind = iota
	// kind2022 is SIP022 AEAD-2022 (salt + fixed header + chunks, BLAKE3 keys).
	kind2022
)

// method is one entry of shadowsocks.map.init.0 (@0xb109a0, 1536 B) — the table
// the binary builds at startup. Names and key sizes are the recovered literals
// (notes/rev-proto-tcp.md §4.1); REPORT.md §6.5 lists the algorithms.
type method struct {
	name     string
	keySize  int
	saltSize int
	kind     methodKind
	newAEAD  func(key []byte) (cipher.AEAD, error)
}

func aesGCM(size int) func([]byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
}

// leaGCM mirrors shadowsocks.leaGCM @0xb12980: LEA in GCM mode
// (github.com/RyuaNerin/go-krypto).
func leaGCM(size int) func([]byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		block, err := lea.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
}

func chacha20Poly1305AEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// xchacha is shadowsocks.xchacha @0xb16de0 / xAEAD @0xb16e60: XChaCha20-Poly1305
// with a 24-byte nonce.
func xchacha20Poly1305AEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// aezAEAD is shadowsocks.aezAEAD @0xb12840 (github.com/Yawning/aez), used for
// aez-384: a 48-byte key.
func aezAEAD(key []byte) (cipher.AEAD, error) { return aez.New(key) }

// aegisAEAD is shadowsocks.aegisAEAD @0xb12780; aegis.New picks AEGIS-128L for a
// 16-byte key and AEGIS-256 for a 32-byte key.
func aegisAEAD(key []byte) (cipher.AEAD, error) { return aegis.New(key) }

// deoxysAEAD is shadowsocks.deoxysAEAD @0xb12840-adjacent (deoxys-ii-256-128).
func deoxysAEAD(key []byte) (cipher.AEAD, error) { return deoxysii.New(key) }

// rabbitAEAD is shadowsocks.rabbitAEAD @0xb16422 (rabbit128-poly1305). The
// construction is Rabbit keystream + Poly1305 under the first 32 keystream bytes;
// the key must be 16 bytes ("rabbit128-poly1305: bad key length" @0xf7a694).
func rabbitAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 {
		return nil, errRabbitKey
	}
	return &rabbitPoly1305{key: append([]byte(nil), key...)}, nil
}

// methods is the cipher table. REPORT.md §24.1: the server table in this build
// has no 2022-blake3-chacha20-poly1305, so it is deliberately absent here and
// New reports `shadowsocks: unsupported cipher "2022-blake3-chacha20-poly1305"`.
var methods = func() map[string]*method {
	m := make(map[string]*method, 20)
	add := func(name string, keySize int, kind methodKind, fn func([]byte) (cipher.AEAD, error)) {
		m[name] = &method{name: name, keySize: keySize, saltSize: keySize, kind: kind, newAEAD: fn}
	}
	// Classic AEAD (SIP004).
	add("aes-128-gcm", 16, kindClassic, aesGCM(16))
	add("aes-192-gcm", 24, kindClassic, aesGCM(24))
	add("aes-256-gcm", 32, kindClassic, aesGCM(32))
	add("chacha20-ietf-poly1305", 32, kindClassic, chacha20Poly1305AEAD)
	// "chacha20-poly1305" is the same primitive under its other spelling
	// (@0xf62fa5 in the method table).
	add("chacha20-poly1305", 32, kindClassic, chacha20Poly1305AEAD)
	add("xchacha20-ietf-poly1305", 32, kindClassic, xchacha20Poly1305AEAD)
	add("lea-128-gcm", 16, kindClassic, leaGCM(16))
	add("lea-192-gcm", 24, kindClassic, leaGCM(24))
	add("lea-256-gcm", 32, kindClassic, leaGCM(32))
	add("aez-384", 48, kindClassic, aezAEAD)
	add("aegis-128l", 16, kindClassic, aegisAEAD)
	add("aegis-256", 32, kindClassic, aegisAEAD)
	add("deoxys-ii-256-128", 32, kindClassic, deoxysAEAD)
	add("rabbit128-poly1305", 16, kindClassic, rabbitAEAD)
	// Ascon is implemented in-package (ascon128 @0xb10fa0, ascon128a
	// @0xb110a0); both variants are in the method table.
	add("ascon128", 16, kindClassic, newAscon128)
	add("ascon128a", 16, kindClassic, newAscon128a)
	// SS2022 (SIP022). Only AES is defined (EIH is AES-based); the chacha entry
	// is absent from the server table (§24.1).
	add("2022-blake3-aes-128-gcm", 16, kind2022, aesGCM(16))
	add("2022-blake3-aes-256-gcm", 32, kind2022, aesGCM(32))
	return m
}()

// Ascon is implemented inside the binary (shadowsocks.ascon128 @0xb10fa0,
// ascon128a @0xb110a0, asconAEAD @0xb111a0) rather than by a dependency; this
// package does the same in ascon.go and validates both variants against the
// official ascon-c v1.2 KAT files.

// evpBytesToKey is shadowsocks.evpBytesToKey @0xb17ac0: OpenSSL's
// EVP_BytesToKey with MD5, no salt, one iteration — the classic Shadowsocks
// password -> master key derivation.
func evpBytesToKey(password []byte, keyLen int) []byte {
	var (
		out  []byte
		prev []byte
	)
	for len(out) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

// hkdfSHA1 is shadowsocks.hkdfSHA1 @0xb12980: HKDF-SHA1 with the "ss-subkey"
// info string, used for the per-salt subkey of classic AEAD.
func hkdfSHA1(master, salt []byte, keyLen int) []byte {
	const info = "ss-subkey"
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdf.New(sha1.New, master, salt, []byte(info)), out); err != nil {
		return nil
	}
	return out
}

// decodeKey parses a base64 key. The binary decodes URL-safe unpadded base64 (the
// "%s: a key is not unpadded URL" fragment sits next to the shadowsocks key
// parser, notes/rev-proto-tcp.md §4.6) but a padded standard string must also
// work — REPORT.md §24.1 shows `openssl rand -base64 16` keys being accepted and
// rejected only when the length is wrong ("must be 16 bytes in base64").
func decodeKey(s string, want int) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == want {
			return b, nil
		}
	}
	return nil, fmt.Errorf("must be %d bytes in base64", want)
}

// nonceCounter is the AEAD nonce: a little-endian counter of the AEAD's own nonce
// size, matching the go-shadowsocks2 / SIP004 layout (the first 8 bytes hold the
// counter, the rest stay zero; nonce sizes above 12 bytes are handled the same
// way because the counter simply occupies more bytes).
type nonceCounter struct{ buf []byte }

func newNonceCounter(n int) nonceCounter { return nonceCounter{buf: make([]byte, n)} }

func (n nonceCounter) get() []byte { return n.buf }

func (n nonceCounter) inc() {
	for i := range n.buf {
		n.buf[i]++
		if n.buf[i] != 0 {
			return
		}
	}
}

// chacha20XOR is only used by the XChaCha helper of the cipher table; keeping the
// import meaningful documents where the primitive comes from.
var _ = chacha20.NewUnauthenticatedCipher
