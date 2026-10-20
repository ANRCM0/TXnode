// Package shadowsocks is the Shadowsocks inbound of kaze v0.5.18: classic AEAD
// plus the 2022 protocol.
//
// Evidence:
//   - REPORT.md §6.5 (the algorithm surface is much wider than upstream),
//     §22.4 (classic AEAD self-interop works), §24.1 (**the server table has no
//     2022-blake3-chacha20-poly1305** and kaze↔kaze 2022 authentication fails in
//     the sample).
//   - notes/rev-proto-tcp.md §4: shadowsocks.map.init.0 @0xb109a0 (method table),
//     ss.New @0xb17180 (base64 key decode + length check), ss.NewClient
//     @0xb14260, handshakeClassic @0xb181c0, handshake2022 @0xb18aa0,
//     identityKey @0xb17f00, sessionKey @0xb17d20, evpBytesToKey @0xb17ac0,
//     hkdfSHA1 @0xb12980, saltCache.add @0xb1a1e0, ListenUDP @0xb1b580
//     (**120 s** = 0x1bf08eb000 session idle), reader @0xb1a8e0, writer @0xb1b280.
//   - notes/protocols.md §2.4 (documented cipher list and the classic multi-user
//     identification policy).
//
// The 2022 key schedule uses lukechampine.com/blake3 (the binary links both blake3
// implementations; ss.(*Handler).sessionKey @0xb17e80 calls blake3.DeriveKey with
// the context literal "shadowsocks 2022 session subkey" @0xf75ca1, and
// identityKey @0xb17f00 with "shadowsocks 2022 identity subkey" @0xf77455).
package shadowsocks

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zeebo/blake3"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Error strings are the binary's own literals.
var (
	// errAuth ← "shadowsocks: authentication failed" (§22.4 log line; the string is
	// also the socks5 one, the rodata blobs are adjacent).
	errAuth = errors.New("shadowsocks: authentication failed")
	// ErrReplayedSalt ← "shadowsocks: replayed salt" @0xf6eb53 (handshake2022
	// @0xb18edf; handshakeClassic @0xb18591 has the same check).
	ErrReplayedSalt = errors.New("shadowsocks: replayed salt")
	// errTimestamp ← "shadowsocks: timestamp outside the allowed window"
	// @0xf8d078 (handshake2022 @0xb18f12).
	errTimestamp = errors.New("shadowsocks: timestamp outside the allowed window")
	// errNotRequest ← "shadowsocks: not a request header" @0xf78dd1
	// (handshake2022 @0xb18f45).
	errNotRequest = errors.New("shadowsocks: not a request header")
	// errCorruptLength ← "shadowsocks: corrupt length chunk" @0xf78df2
	// (reader @0xb1acdd).
	errCorruptLength = errors.New("shadowsocks: corrupt length chunk")
	// errCorruptPayload ← "shadowsocks: corrupt payload chunk" @0xf7a6b6
	// (reader @0xb1af1c).
	errCorruptPayload = errors.New("shadowsocks: corrupt payload chunk")
	// ErrUDPSessionIdle ← "shadowsocks: UDP session idle" @0xf72f46.
	ErrUDPSessionIdle = errors.New("shadowsocks: UDP session idle")
)

// udpIdle is the UDP session idle limit: `movabs rdx,0x1bf08eb000` = 120e9 ns
// (ss.(*Handler).ListenUDP @0xb1b580).
const udpIdle = 120 * time.Second

// unsupportedCipher renders "shadowsocks: unsupported cipher %q" @0xf7a672
// (ss.New @0xb17381).
func unsupportedCipher(name string) error {
	return fmt.Errorf("shadowsocks: unsupported cipher %q", name)
}

// Options is the package contract (REPLICATION.md §3.2).
type Options struct {
	// Users are the admitted accounts. Classic AEAD derives each user's master key
	// from the UUID with EVP_BytesToKey(MD5); 2022 reads it as an unpadded base64
	// key of exactly keySize bytes.
	Users []core.User
	// Cipher is a method name from shadowsocks.map.init.0.
	Cipher string
	// ServerKey is required for 2022 (the pre-shared key, or the identity PSK when
	// users carry their own keys) and optional for classic AEAD.
	ServerKey string
	// UDP enables the UDP relay (ServePackets).
	UDP bool
}

// userKey pairs an account with its derived key material.
type userKey struct {
	user *core.User
	key  []byte
}

// Handler is the Shadowsocks inbound. It implements core.Handler and, when UDP is
// enabled, core.PacketHandler (ss.(*Handler).ListenUDP @0xb1b580).
type Handler struct {
	spec      *method
	serverKey []byte // 2022 PSK, or the identity PSK when users have their own keys
	users     []userKey
	salts     *saltCache
	search    *classicSearch
	window    time.Duration
	udp       bool

	pkt atomic.Pointer[udpServer]
}

var (
	_ core.Handler       = (*Handler)(nil)
	_ core.PacketHandler = (*Handler)(nil)
)

// New validates Options and builds the handler. The sample names this constructor
// ss.New (@0xb17180), not NewHandler.
func New(o Options) (*Handler, error) {
	spec, ok := methods[o.Cipher]
	if !ok {
		// ascon128/ascon128a exist in the method table but the binary implements
		// Ascon in-package (shadowsocks.ascon128 @0xb10fa0) and go.mod has no
		// Ascon dependency, so they are recognised but not wired.
		// UNVERIFIED: ascon128 / ascon128a
		return nil, unsupportedCipher(o.Cipher)
	}
	h := &Handler{
		spec:   spec,
		salts:  newSaltCache(saltCacheTTL),
		search: newClassicSearch(),
		window: TimestampWindow,
		udp:    o.UDP,
	}
	switch spec.kind {
	case kind2022:
		if strings.Count(o.ServerKey, ":") > 1 {
			// "shadowsocks: at most one server key and one user key are supported"
			return nil, errors.New("shadowsocks: at most one server key and one user key are supported")
		}
		if o.ServerKey == "" {
			return nil, fmt.Errorf("shadowsocks: server key %s", mustBase64(spec.keySize))
		}
		key, err := decodeKey(o.ServerKey, spec.keySize)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: server key %w", err)
		}
		h.serverKey = key
		for i := range o.Users {
			u := o.Users[i]
			if u.UUID == "" {
				continue
			}
			uk, err := decodeKey(u.UUID, spec.keySize)
			if err != nil {
				return nil, fmt.Errorf("shadowsocks: each key %w", err)
			}
			h.users = append(h.users, userKey{user: &o.Users[i], key: uk})
		}
	default:
		if o.ServerKey != "" {
			key, err := decodeKey(o.ServerKey, spec.keySize)
			if err != nil {
				return nil, fmt.Errorf("shadowsocks: server key %w", err)
			}
			h.serverKey = key
		}
		for i := range o.Users {
			u := o.Users[i]
			if u.UUID == "" {
				continue
			}
			h.users = append(h.users, userKey{
				user: &o.Users[i],
				key:  evpBytesToKey([]byte(u.UUID), spec.keySize),
			})
		}
	}
	return h, nil
}

// NewHandler is an alias for New, kept so node wiring can treat every inbound
// uniformly.
func NewHandler(o Options) (*Handler, error) { return New(o) }

func mustBase64(n int) string { return fmt.Sprintf("must be %d bytes in base64", n) }

// Handle parses the request header and returns the session to relay.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	br := bufio.NewReaderSize(conn, 4096)
	if h.spec.kind == kind2022 {
		return h.handshake2022(conn, br)
	}
	return h.handshakeClassic(conn, br)
}

// handshakeClassic is ss.(*Handler).handshakeClassic @0xb181c0:
// salt then length/payload chunks; the address is the first payload bytes.
func (h *Handler) handshakeClassic(conn net.Conn, br *bufio.Reader) (*core.Session, error) {
	salt, err := br.Peek(h.spec.saltSize)
	if err != nil {
		return nil, err
	}
	if !h.salts.add(salt) {
		return nil, ErrReplayedSalt
	}
	peer := peerHost(conn)

	// Try each candidate's subkey against the first length chunk
	// (classicSearch/scanClassic @0xb13d20): open the 2+tag bytes without
	// consuming them.
	head, err := br.Peek(h.spec.saltSize + 2 + 16)
	if err != nil {
		return nil, err
	}
	probe := head[h.spec.saltSize:]

	var (
		chosen   *userKey
		chosenAE cipher.AEAD
		chosenIx = -1
		master   []byte
	)
	order := h.search.order(peer, len(h.users))
	if !h.search.allowFullScan(peer) && len(order) > 0 {
		order = order[:1]
	}
	for _, idx := range order {
		uk := &h.users[idx]
		aead, err := h.classicAEAD(uk.key, salt)
		if err != nil {
			continue
		}
		nonce := newNonceCounter(aead.NonceSize())
		if _, err := aead.Open(nil, nonce.get(), probe, nil); err == nil {
			chosen, chosenAE, chosenIx, master = uk, aead, idx, uk.key
			break
		}
	}
	if chosen == nil && len(h.serverKey) > 0 {
		aead, err := h.classicAEAD(h.serverKey, salt)
		if err == nil {
			nonce := newNonceCounter(aead.NonceSize())
			if _, err := aead.Open(nil, nonce.get(), probe, nil); err == nil {
				chosenAE, master = aead, h.serverKey
			}
		}
	}
	if chosenAE == nil {
		h.search.failed(peer)
		return nil, errAuth
	}
	if chosen != nil {
		h.search.succeeded(peer, chosenIx)
	}

	// From here on the salt is consumed by the reader's owner: skip it.
	if _, err := br.Discard(h.spec.saltSize); err != nil {
		return nil, err
	}
	reader := newChunkReader(br, chosenAE, -1)
	dest, err := ReadAddr(reader)
	if err != nil {
		return nil, err
	}
	writer, err := h.responseWriterClassic(conn, master)
	if err != nil {
		return nil, err
	}
	userID := 0
	if chosen != nil && chosen.user != nil {
		userID = chosen.user.ID
	}
	return &core.Session{
		UserID: userID,
		Dest:   dest,
		Conn: &aeadConn{
			Reader:  reader,
			w:       writer,
			conn:    connRW{conn},
			netConn: conn,
		},
		Socket: tcpConn(conn),
	}, nil
}

// handshake2022 is ss.(*Handler).handshake2022 @0xb18aa0:
// salt (+ identity header) then the 11-byte fixed header then chunks.
func (h *Handler) handshake2022(conn net.Conn, br *bufio.Reader) (*core.Session, error) {
	salt := make([]byte, h.spec.saltSize)
	if _, err := io.ReadFull(br, salt); err != nil {
		return nil, err
	}
	if !h.salts.add(salt) {
		return nil, ErrReplayedSalt
	}

	key, user, err := h.identify2022(br, salt)
	if err != nil {
		return nil, err
	}
	subkey := sessionSubkey(key, salt, h.spec.keySize)
	aead, err := h.spec.newAEAD(subkey)
	if err != nil {
		return nil, err
	}

	// Fixed header: type(1) timestamp(8) length(2), sealed with the session subkey
	// and a zero nonce (27 bytes on the wire).
	nonce := newNonceCounter(aead.NonceSize())
	sealed := make([]byte, fixedHeaderLen+aead.Overhead())
	if _, err := io.ReadFull(br, sealed); err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce.get(), sealed, nil)
	if err != nil {
		return nil, errAuth
	}
	nonce.inc()
	if plain[0] != headerClientStream {
		return nil, errNotRequest
	}
	ts := int64(binary.BigEndian.Uint64(plain[1:9]))
	if !h.checkTimestamp(ts) {
		return nil, errTimestamp
	}
	firstLen := int(binary.BigEndian.Uint16(plain[9:11]))

	reader := newChunkReader(br, aead, firstLen)
	// The fixed header already spent nonce 0.
	reader.skip(1)
	dest, err := ReadAddr(reader)
	if err != nil {
		return nil, err
	}
	// The 2022 request payload is address || u16 paddingLen || padding || data.
	var padBuf [2]byte
	if _, err := io.ReadFull(reader, padBuf[:]); err != nil {
		return nil, err
	}
	if padLen := int(binary.BigEndian.Uint16(padBuf[:])); padLen > 0 {
		if _, err := io.CopyN(io.Discard, reader, int64(padLen)); err != nil {
			return nil, err
		}
	}
	writer, err := h.responseWriter2022(conn, key, salt)
	if err != nil {
		return nil, err
	}
	userID := 0
	if user != nil {
		userID = user.ID
	}
	return &core.Session{
		UserID: userID,
		Dest:   dest,
		Conn: &aeadConn{
			Reader:  reader,
			w:       writer,
			conn:    connRW{conn},
			netConn: conn,
		},
		Socket: tcpConn(conn),
	}, nil
}

// identify2022 resolves the request key for a 2022 salt.
//
// With one PSK (no per-user keys) the salt alone is enough. With users the client
// prepends an identity header: one AES-ECB block holding blake3(session subkey)
// encrypted under the identity key derived from the server key
// (ss.(*Handler).identityKey @0xb17f00 builds the AES cipher, then the decrypt is
// matched against the user table).
//
// UNVERIFIED: the exact byte order/derivation of the identity block. The sample's
// own client cannot authenticate against its own server (REPORT.md §24.1), so
// there is no local ground truth; this follows the BLAKE3 context strings the
// binary carries.
func (h *Handler) identify2022(br *bufio.Reader, salt []byte) ([]byte, *core.User, error) {
	if len(h.users) == 0 {
		if len(h.serverKey) == 0 {
			return nil, nil, errAuth
		}
		return h.serverKey, nil, nil
	}

	// Multi-user with an identity PSK: the client prepends one AES-ECB block
	// holding blake3(session subkey)[:16] under the identity key. A single-PSK
	// client sends no such block, so peek first and only consume it on a match.
	if len(h.serverKey) > 0 {
		if block, err := br.Peek(16); err == nil {
			idKey := identityKey(h.serverKey, h.spec.keySize)
			if dec, err := ecbDecryptBlock(idKey, block); err == nil {
				for i := range h.users {
					uk := &h.users[i]
					sub := sessionSubkey(uk.key, salt, h.spec.keySize)
					want := blake3Hash(sub)
					if equalBytes(want[:16], dec) {
						_, _ = br.Discard(16)
						return uk.key, uk.user, nil
					}
				}
			}
		}
		// No identity header: a single-PSK deployment where the user key is the
		// PSK (or the server key is the PSK and users are not involved).
		for i := range h.users {
			if equalBytes(h.users[i].key, h.serverKey) {
				return h.users[i].key, h.users[i].user, nil
			}
		}
		return h.serverKey, nil, nil
	}

	// Users but no identity key: the first user key doubles as the PSK.
	return h.users[0].key, h.users[0].user, nil
}

// responseWriterClassic builds the response direction of the classic format: a
// fresh salt and its own HKDF subkey off the same master key.
func (h *Handler) responseWriterClassic(conn net.Conn, master []byte) (*chunkWriter, error) {
	salt := make([]byte, h.spec.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := h.classicAEAD(master, salt)
	if err != nil {
		return nil, err
	}
	return newChunkWriter(conn, aead, salt, false, 0), nil
}

func (h *Handler) responseWriter2022(conn net.Conn, psk, requestSalt []byte) (*chunkWriter, error) {
	salt := make([]byte, h.spec.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	subkey := sessionSubkey(psk, salt, h.spec.keySize)
	aead, err := h.spec.newAEAD(subkey)
	if err != nil {
		return nil, err
	}
	w := newChunkWriter(conn, aead, salt, true, headerServerStream)
	w.requestSalt = append([]byte(nil), requestSalt...)
	return w, nil
}

// classicAEAD derives the per-salt subkey of the classic format
// (HKDF-SHA1 "ss-subkey").
func (h *Handler) classicAEAD(master, salt []byte) (cipher.AEAD, error) {
	sub := hkdfSHA1(master, salt, h.spec.keySize)
	if sub == nil {
		return nil, errAuth
	}
	return h.spec.newAEAD(sub)
}

// sessionSubkey is ss.(*Handler).sessionKey @0xb17d20:
// blake3.DeriveKey("shadowsocks 2022 session subkey", psk || salt), truncated to
// the AEAD key size.
func sessionSubkey(psk, salt []byte, keySize int) []byte {
	out := make([]byte, 32)
	src := make([]byte, 0, len(psk)+len(salt))
	src = append(src, psk...)
	src = append(src, salt...)
	blake3.DeriveKey("shadowsocks 2022 session subkey", src, out)
	return out[:keySize]
}

// identityKey is ss.(*Handler).identityKey @0xb17f00: an AES key derived from the
// identity PSK with the "shadowsocks 2022 identity subkey" context.
func identityKey(psk []byte, keySize int) []byte {
	out := make([]byte, 32)
	blake3.DeriveKey("shadowsocks 2022 identity subkey", psk, out)
	return out[:keySize]
}

func blake3Hash(b []byte) [32]byte {
	return blake3.Sum256(b)
}

func ecbDecryptBlock(key, block []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	c.Decrypt(out, block)
	return out, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func peerHost(c net.Conn) string {
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// connRW adapts net.Conn to the CloseWrite-capable interface aeadConn wants.
type connRW struct{ net.Conn }

func (c connRW) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func tcpConn(c net.Conn) *net.TCPConn {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc
	}
	return nil
}

var _ = socks.Addr{}
