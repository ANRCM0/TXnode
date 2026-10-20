// Package snell implements the Snell inbound of kaze (v1–v3, UDP on v3).
//
// Evidence: kazecore/notes/rev-proto-udp.md §4 (snell) and REPORT.md §6.8. The
// binary's package has 78 functions. What is confirmed:
//
//   - only versions 1, 2 and 3 are served: "snell: version %d is not 1, 2 or 3"
//     (all_strings 190488), and UDP needs version 3 ("clients: version 3 for
//     UDP", 190567);
//   - snell.AEAD @0xb2b840 has exactly two suites: chacha20-ietf-poly1305 for a
//     32-byte key and AES-128-GCM for a 16-byte key;
//   - the v3 key goes through argon2 (snell.Key @0xb2b780: mode byte=1 =
//     argon2i, time=3, threads=8, keyLen=32) and a shadowsocks salt cache
//     (shadowsocks.(*saltCache).add @0xb1a1e0) guards against salt replay;
//   - one chunk is at most 16383 bytes (cmp rcx,0x3fff in handshake @0xb28460);
//   - the error strings are "snell: chunk too large", "snell: a chunk does not
//     decrypt" and "authentication timeout".
//
// UNVERIFIED: the per-version header fields and the chunk container were not
// decoded instruction by instruction (notes §4.1/§7 items 6–7). The layout below
// is a coherent kaze-replication wire that keeps the confirmed primitives,
// limits and error strings:
//
//	handshake (plaintext)
//	  ver(1) cmd(1) idLen(1) id(idLen)
//	  ver == 3: salt(32)                       // argon2 salt, replay-checked
//	chunks (AEAD, per direction, increasing 12-byte nonce)
//	  sealedLen(u16 BE) sealed(plaintext + 16 tag)
//	CONNECT (cmd 1): the first chunk is the destination address
//	UDP (cmd 3, v3 only): every chunk is address || datagram
package snell

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// Wire constants.
const (
	// maxChunk is the single-chunk ceiling: cmp rcx,0x3fff (16383).
	maxChunk = 0x3fff
	// saltLen is the v3 salt length.
	saltLen = 32
	// cmdConnect is the TCP command.
	cmdConnect = 1
	// cmdUDP is the UDP command; only valid on version 3.
	cmdUDP = 3
	// cmdConnectV2 is the TCP command v4/v5 clients send (SNConnectorV4).
	cmdConnectV2 = 5
	// tagLen is the AEAD tag.
	tagLen = 16
)

// Error strings, verbatim where the report quotes them.
var (
	// ErrVersion is "snell: version %d is not 1, 2 or 3".
	errVersion = errors.New("snell: version %d is not 1, 2 or 3")
	// ErrChunkTooLarge is "snell: chunk too large".
	ErrChunkTooLarge = errors.New("snell: chunk too large")
	// ErrBadChunk is "snell: a chunk does not decrypt".
	ErrBadChunk = errors.New("snell: a chunk does not decrypt")
	// ErrReplayedSalt is "snell: replayed salt".
	ErrReplayedSalt = errors.New("snell: replayed salt")
	// ErrAuthTimeout is "authentication timeout".
	ErrAuthTimeout = errors.New("snell: authentication timeout")
	// ErrUDPVersion is the v1/v2 UDP rejection.
	ErrUDPVersion = errors.New("snell: UDP needs version 3")
)

// Argon2 parameters from snell.Key @0xb2b780: time=3, threads=8, keyLen=32,
// mode=argon2i. UNVERIFIED: the memory cost was not extracted; 64 MiB is the
// usual interactive cost for these parameters.
const (
	defaultArgon2Time    = 3
	defaultArgon2Memory  = 64 * 1024 // KiB
	defaultArgon2Threads = 8
)

// Options is the contract's option set for snell plus the tuning knobs.
type Options struct {
	Users   []core.User
	Version int
	Logger  *slog.Logger

	// Argon2Time/Argon2Memory/Argon2Threads override the v3 KDF cost.
	Argon2Time    uint32
	Argon2Memory  uint32
	Argon2Threads uint8
	// SaltTTL overrides the salt-cache entry lifetime.
	SaltTTL time.Duration
	// AuthTimeout bounds the handshake.
	AuthTimeout time.Duration
}

// user is one Snell account. The psk is the AEAD master secret; a 16-byte psk
// selects AES-128-GCM and a 32-byte psk selects chacha20-ietf-poly1305
// (snell.AEAD @0xb2b840).
type user struct {
	name string
	psk  []byte
	raw  []byte
	core core.User
}

// Handler is the Snell inbound.
type Handler struct {
	opts Options
	log  *slog.Logger

	usersMu sync.RWMutex
	users   []user
	byName  map[string]*user

	argon2Time    uint32
	argon2Memory  uint32
	argon2Threads uint8

	salts *saltCache
}

// NewHandler validates the options.
func NewHandler(o Options) (*Handler, error) {
	if len(o.Users) == 0 {
		return nil, errors.New("snell: no users configured")
	}
	if o.Version != 0 && (o.Version < 1 || o.Version > 4) {
		return nil, fmt.Errorf("snell: version %d is not 1, 2, 3 or 4", o.Version)
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &Handler{
		opts:          o,
		log:           log,
		byName:        make(map[string]*user),
		argon2Time:    o.Argon2Time,
		argon2Memory:  o.Argon2Memory,
		argon2Threads: o.Argon2Threads,
	}
	if h.argon2Time == 0 {
		h.argon2Time = defaultArgon2Time
	}
	if h.argon2Memory == 0 {
		h.argon2Memory = defaultArgon2Memory
	}
	if h.argon2Threads == 0 {
		h.argon2Threads = defaultArgon2Threads
	}
	h.salts = newSaltCache(o.SaltTTL)
	h.SetUsers(o.Users)
	if len(h.users) == 0 {
		return nil, errors.New("snell: no usable users")
	}
	return h, nil
}

// SetUsers rebuilds the user table. Evidence: (*Handler).SetUsers @0xb28020 uses
// the same make-map + atomic publish pattern as hysteria/tuic.
func (h *Handler) SetUsers(users []core.User) {
	next := make([]user, 0, len(users))
	byName := make(map[string]*user, len(users))
	for _, u := range users {
		name, psk := splitUser(u.UUID)
		if len(psk) == 0 {
			continue
		}
		entry := &user{name: name, psk: normalizePSK(psk), raw: psk, core: u}
		next = append(next, *entry)
		byName[name] = &next[len(next)-1]
	}
	h.usersMu.Lock()
	h.users = next
	h.byName = byName
	h.usersMu.Unlock()
}

// splitUser splits "name:psk". A bare value is a psk with an empty name, which
// is the single-user form.
func splitUser(v string) (string, []byte) {
	for i := 0; i < len(v); i++ {
		if v[i] == ':' {
			return v[:i], []byte(v[i+1:])
		}
	}
	return "", []byte(v)
}

// normalizePSK gives the AEAD suite the key length it expects: 16 bytes stays
// 16 (AES-128-GCM), 32 stays 32 (chacha20-ietf-poly1305), anything else is
// hashed to 32 so a panel-supplied passphrase still works.
// UNVERIFIED: the sample's own normalisation is not decoded; the report only
// states the two accepted lengths.
func normalizePSK(psk []byte) []byte {
	switch len(psk) {
	case 16, 32:
		return psk
	}
	sum := sha256.Sum256(psk)
	return sum[:]
}

// lookup finds the user the client claims in the handshake. A client id that
// matches no name falls back to the only configured user, which is how a
// single-psk Snell configuration behaves.
func (h *Handler) lookup(clientID string) (*user, bool) {
	h.usersMu.RLock()
	defer h.usersMu.RUnlock()
	if u, ok := h.byName[clientID]; ok {
		return u, true
	}
	if len(h.users) == 1 && clientID == "" {
		u := h.users[0]
		return &u, true
	}
	if len(h.users) == 1 {
		u := h.users[0]
		return &u, true
	}
	return nil, false
}

// newAEAD returns the suite for a key: 32 bytes is chacha20-ietf-poly1305,
// 16 bytes is AES-128-GCM (snell.AEAD @0xb2b840).
func newAEAD(key []byte) (cipher.AEAD, error) {
	switch len(key) {
	case 32:
		return chacha20poly1305.New(key)
	case 16:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	return nil, fmt.Errorf("snell: unsupported key length %d", len(key))
}

// deriveKey derives the AEAD key. v1/v2 use the psk directly; v3 runs
// argon2i(psk, salt) with the recovered cost parameters.
func (h *Handler) deriveKey(version int, psk, salt []byte) []byte {
	if version != 3 {
		return psk
	}
	return argon2.Key(psk, salt, h.argon2Time, h.argon2Memory, h.argon2Threads, uint32(len(psk)))
}

// Handle runs the handshake and returns the session.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	if h.opts.Version >= 4 {
		return h.handleV4(ctx, conn)
	}
	timeout := h.opts.AuthTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}

	var head [3]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, &core.Stranger{Conn: conn, Err: ErrAuthTimeout, Quiet: true}
	}
	version, cmd, idLen := int(head[0]), head[1], int(head[2])
	if version < 1 || version > 3 {
		return nil, &core.Stranger{Conn: conn, Err: fmt.Errorf(errVersion.Error(), version), Quiet: true}
	}
	if h.opts.Version != 0 && version != h.opts.Version {
		return nil, &core.Stranger{Conn: conn, Err: fmt.Errorf(errVersion.Error(), version), Quiet: true}
	}
	if cmd != cmdConnect && cmd != cmdUDP {
		return nil, &core.Stranger{Conn: conn, Err: errors.New("snell: unknown command"), Quiet: true}
	}
	if cmd == cmdUDP && version != 3 {
		return nil, &core.Stranger{Conn: conn, Err: ErrUDPVersion, Quiet: true}
	}

	idBuf := make([]byte, idLen)
	if _, err := io.ReadFull(conn, idBuf); err != nil {
		return nil, &core.Stranger{Conn: conn, Err: err, Quiet: true}
	}
	u, ok := h.lookup(string(idBuf))
	if !ok {
		return nil, &core.Stranger{Conn: conn, Err: errors.New("snell: unknown user"), Quiet: true}
	}

	var key []byte
	if version == 3 {
		salt := make([]byte, saltLen)
		if _, err := io.ReadFull(conn, salt); err != nil {
			return nil, &core.Stranger{Conn: conn, Err: err, Quiet: true}
		}
		if !h.salts.add(salt) {
			// Replayed salt: a replay of an earlier v3 connection.
			return nil, &core.Stranger{Conn: conn, Err: ErrReplayedSalt, Quiet: true}
		}
		key = h.deriveKey(version, u.psk, salt)
	} else {
		key = h.deriveKey(version, u.psk, nil)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})

	coder := newChunkCoder(aead, conn)
	if cmd == cmdUDP {
		p := &packets{coder: coder}
		// The first chunk carries the destination address; the session's Dest
		// stays zero because a UDP association is per packet.
		return &core.Session{UserID: u.core.ID, Conn: conn, Packets: p}, nil
	}
	// CONNECT: the first chunk is the destination address.
	addrChunk, err := coder.ReadChunk()
	if err != nil {
		return nil, &core.Stranger{Conn: conn, Err: err, Quiet: true}
	}
	dest, _, err := decodeAddr(addrChunk)
	if err != nil {
		return nil, &core.Stranger{Conn: conn, Err: err, Quiet: true}
	}
	sc := &streamConn{
		Conn:  conn,
		coder: coder,
	}
	return &core.Session{UserID: u.core.ID, Dest: dest, Conn: sc}, nil
}

// readHeader is exported for tests: it decodes the 3-byte plaintext prefix.
func readHeader(b []byte) (version int, cmd byte, idLen int, err error) {
	if len(b) < 3 {
		return 0, 0, 0, io.ErrUnexpectedEOF
	}
	version, cmd, idLen = int(b[0]), b[1], int(b[2])
	if version < 1 || version > 3 {
		return 0, 0, 0, fmt.Errorf(errVersion.Error(), version)
	}
	return version, cmd, idLen, nil
}
