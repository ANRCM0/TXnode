// Package vmess implements the VMess inbound of kaze v0.5.18. Only the AEAD
// header exists: the legacy MD5 header (alterId != 0) and the legacy
// aes-128-cfb body cipher are rejected, while the "none" and "zero" body
// ciphers are kept.
//
// Evidence (file virtual addresses of the reference sample, SHA-256 723d4e20…):
//
//   - REPORT.md §6.3 (AEAD-only, cipher set, error strings)
//   - notes/rev-proto-tcp.md §2 (KDF, request/response AEAD, chunking)
//   - vmess.(*Handler).handshake @0xb4a180 (request header decode + cmd split)
//   - vmess.(*Client).request  @0xb46860 (request header layout, KDF paths)
//   - vmess.(*ClientConn).response @0xb48640 (response header decode)
//   - vmess.(*vmessConn).header @0xb4b3e0 (response header encode)
//   - vmess.newCodecLen @0xb45320, (*codec).padding @0xb457e0,
//     (*bodyReader).readChunk @0xb45860, (*bodyWriter).appendChunk @0xb46060
//
// Request header (plaintext, 0xb46860):
//
//	[0]      version = 1
//	[1:17]   request body IV
//	[17:33]  request body key
//	[33]     response V (echoed in the response header)
//	[34]     option     1 = chunk stream, 4 = chunk masking,
//	                    8 = global padding, 0x10 = authenticated length
//	[35]     (padding length << 4) | security
//	[36]     reserved 0
//	[37]     command (1 = TCP, 2 = UDP, 3 = mux)
//	[38:40]  port, big endian
//	[40]     ATYP (1 = IPv4, 2 = domain, 3 = IPv6)
//	[41:]    address, then padding length random bytes
//	[-4:]    big-endian FNV-1a 32 of everything before it
//
// Wire: authID(16) | sealed length(2+16) | connection nonce(8) | sealed header.
// The server reads 42 bytes first (0xb4a1e4 "mov edi,0x2a"), which is exactly
// authID + length block + nonce.
package vmess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Body ciphers. vmess.newAEAD @0xb45280 handles 3 and 4; the handshake accepts
// 3..5 and 6 and rejects 1 with the "legacy aes-128-cfb" string (0xb4a900 and
// 0xb4a92f).
const (
	SecAES128GCM = 0x03
	SecChaCha20  = 0x04
	SecNone      = 0x05
	SecZero      = 0x06
)

// Request option bits (notes/rev-proto-tcp.md §2.6, 0xb4aab8 option&1 and
// vmess.newCodecLen @0xb45320: bit 4 builds the mask, bit 8 requires it, bit
// 0x10 derives the authenticated length key).
const (
	OptionChunkStream   = 0x01
	OptionChunkMasking  = 0x04
	OptionGlobalPadding = 0x08
	OptionAuthLength    = 0x10
)

// Commands: 1 TCP, 2 UDP (chunked only), 3 mux to v1.mux.cool:666.
// 0xb4ad75 (cmp 1), 0xb4ad80 (cmp 2), 0xb4aec0 (cmp 3), 0xb4a889 mux literal.
const (
	CmdTCP byte = 1
	CmdUDP byte = 2
	CmdMux byte = 3

	MuxAddress = "v1.mux.cool"
	MuxPort    = 666
)

// KDF path labels, exactly the rodata strings used by request/response:
// 0xf69550, 0xf7185d, 0xf74536, 0xf67f5a, 0xf6a9d9, 0xf6be22, 0xf6a9f0,
// 0xf67d3e(="AEAD Resp Header Key"), 0xf659fa.
// vmessAEADCmdKeySalt is the constant UUID Xray appends to the user UUID when
// deriving the VMess AEAD command key (common/protocol.NewID).
const vmessAEADCmdKeySalt = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

const (
	kdfAuthID         = "AES Auth ID Encryption"
	kdfHeaderKeyLen   = "VMess Header AEAD Key_Length"
	kdfHeaderNonceLen = "VMess Header AEAD Nonce_Length"
	kdfHeaderKey      = "VMess Header AEAD Key"
	kdfHeaderNonce    = "VMess Header AEAD Nonce"
	kdfRespLenKey     = "AEAD Resp Header Len Key"
	kdfRespLenIV      = "AEAD Resp Header Len IV"
	kdfRespKey        = "AEAD Resp Header Key"
	kdfRespIV         = "AEAD Resp Header IV"
	kdfAuthLen        = "auth_len"
)

// Errors. Literals read from rodata; addresses in comments.
var (
	// 0xf8386e, 35 bytes: identify() failed.
	ErrUnknownUser = errors.New("vmess: unknown user or clock out of sync")
	// 0xf6a9c2, 22 bytes: the authID was seen before (fresh @0xb49b00).
	ErrReplayed = errors.New("vmess: replayed request")
	// 0xf6aa07, 23 bytes: the length block did not decode.
	ErrMalformed = errors.New("vmess: malformed header")
	// 0xf75cdf, 31 bytes: FNV-1a mismatch.
	ErrChecksum = errors.New("vmess: header checksum mismatch")
	// 0xf75cfe, 31 bytes: cmd==2 without the chunk stream option.
	ErrUDPNotChunked = errors.New("vmess: UDP needs a chunked body")
	// 0xf884a8, 44 bytes: option bit 8 without bit 4.
	ErrPaddingNeedsMasking = errors.New("vmess: global padding requires chunk masking")
	// 0xf702c9, 27 bytes.
	ErrCorruptChunk = errors.New("vmess: corrupt chunk length")
	// 0xf7f2d3, 37 bytes.
	ErrShortChunk = errors.New("vmess: chunk shorter than its framing")
	// 0xf8f539, 51 bytes: the 16-bit body nonce counter wrapped.
	ErrChunkLimit = errors.New("vmess: connection reached its chunk limit; reconnect")
	// 0xf93b5b, 58 bytes.
	ErrLegacyCFB = errors.New("vmess: the legacy aes-128-cfb body cipher is not supported")
	// 0xf6eb87, 26 bytes.
	ErrUnknownBodyCipher = errors.New("vmess: unknown body cipher")
	// 0xf6eba1, 26 bytes.
	ErrUnsupportedCommand = errors.New("vmess: unsupported command")
	// 0xf6be3a, 23 bytes.
	ErrTruncatedAddress = errors.New("vmess: truncated address")
	// 0xf64332, 17 bytes.
	ErrBadAddress = errors.New("vmess: bad address")
	// 0xf77475, 31 bytes.
	ErrNameTooLong = errors.New("vmess: destination name too long")
	// response authentication failure, 0xfa2829 (the sample's string is
	// truncated by its own buffer in the report; the prefix is exact).
	errResponse = errors.New("vmess: the server's response does not match this request (wrong UUID, or not a VMess AEAD server)")
)

// vmessClockWindow is the tolerated clock skew of the authID timestamp; the
// error "vmess: unknown user or clock out of sync" implies a window, and the
// documentation states 120 s.
const vmessClockWindow = 120 * time.Second

// Options is the inbound configuration (REPLICATION.md §3.2).
type Options struct {
	Users  []core.User
	Cipher string // auto", aes-128-gcm, chacha20-poly1305, none, zero
	Logger *slog.Logger
	// MuxPackets wraps the connection into the mux packet stream (xudp.Stream
	// in the sample, itab 0xfc73c0 loaded at 0xb4af78). nil keeps TCP mux but
	// leaves UDP inside mux to core.
	MuxPackets func(conn net.Conn) core.PacketStream
}

// Handler is the VMess inbound.
type Handler struct {
	users map[[16]byte]*core.User
	key   map[[16]byte][]byte // cmdKey = MD5(uuid), vmess.cmdKey @0xb493e0
	sec   byte
	log   *slog.Logger
	mux   func(net.Conn) core.PacketStream

	replayMu *sync.Mutex
	replay   map[[16]byte]time.Time
}

// NewHandler validates the configuration. "auto" selects aes-128-gcm, the
// cipher every AEAD peer supports.
func NewHandler(o Options) (*Handler, error) {
	h := &Handler{
		users:    make(map[[16]byte]*core.User, len(o.Users)),
		key:      make(map[[16]byte][]byte, len(o.Users)),
		log:      o.Logger,
		mux:      o.MuxPackets,
		replay:   make(map[[16]byte]time.Time),
		replayMu: new(sync.Mutex),
	}
	if h.log == nil {
		h.log = slog.New(slog.DiscardHandler)
	}
	name := strings.ToLower(strings.TrimSpace(o.Cipher))
	switch name {
	case "", "auto", "aes-128-gcm", "aes128-gcm", "aes-128":
		h.sec = SecAES128GCM
	case "chacha20-poly1305", "chacha20-ietf-poly1305":
		h.sec = SecChaCha20
	case "none":
		h.sec = SecNone
	case "zero":
		h.sec = SecZero
	case "aes-128-cfb":
		return nil, ErrLegacyCFB
	default:
		return nil, fmt.Errorf("vmess: unknown cipher %q (auto, aes-128-gcm, chacha20-poly1305, none, zero)", o.Cipher)
	}
	h.SetUsers(o.Users)
	return h, nil
}

// SetUsers replaces the table (the sample exposes (*Handler).SetUsers at
// 0xb49560).
func (h *Handler) SetUsers(users []core.User) {
	u := make(map[[16]byte]*core.User, len(users))
	k := make(map[[16]byte][]byte, len(users))
	for i := range users {
		id, err := parseUUID(users[i].UUID)
		if err != nil {
			continue
		}
		user := users[i]
		u[id] = &user
		// Xray's protocol.NewID: cmdKey = MD5(uuid || vmessAEADCmdKeySalt).
		sum := md5.Sum(append(append([]byte(nil), id[:]...), []byte(vmessAEADCmdKeySalt)...))
		k[id] = sum[:]
	}
	h.users = u
	h.key = k
}

// Handle parses one VMess request and returns the session (0xb4a180).
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	_ = ctx
	var head [42]byte // authID(16) | length block(18) | connection nonce(8)
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	authID := head[:16]
	connNonce := head[34:42]

	userID, cmdKey, err := h.identify(authID, head[:])
	if err != nil {
		return nil, err
	}
	if err := h.fresh(authID); err != nil {
		return nil, err
	}

	// Length block: KDF path = [label, authID, connNonce] (path length 3 at
	// 0xb4a32f), AEAD additional data = authID (0xb4a448 stack slice).
	lenAEAD, err := newGCM(kdf16(cmdKey, []byte(kdfHeaderKeyLen), authID, connNonce))
	if err != nil {
		return nil, err
	}
	lenNonce := kdf(cmdKey, []byte(kdfHeaderNonceLen), authID, connNonce)[:12]
	bodyLenPlain, err := lenAEAD.Open(nil, lenNonce, head[16:34], authID)
	if err != nil || len(bodyLenPlain) != 2 {
		return nil, ErrMalformed
	}
	bodyLen := int(binary.BigEndian.Uint16(bodyLenPlain))

	hdrAEAD, err := newGCM(kdf16(cmdKey, []byte(kdfHeaderKey), authID, connNonce))
	if err != nil {
		return nil, err
	}
	hdrNonce := kdf(cmdKey, []byte(kdfHeaderNonce), authID, connNonce)[:12]
	sealed := make([]byte, bodyLen+16)
	if _, err := io.ReadFull(conn, sealed); err != nil {
		return nil, err
	}
	plain, err := hdrAEAD.Open(nil, hdrNonce, sealed, authID)
	if err != nil {
		return nil, ErrMalformed
	}
	req, err := parseRequestHeader(plain)
	if err != nil {
		return nil, err
	}
	req.UserID = userID

	if err := h.checkOption(req.Option); err != nil {
		return nil, err
	}

	vc := &vmessConn{
		conn:     conn,
		respV:    req.RespV,
		option:   req.Option,
		security: req.Security,
		// server -> client body keys: sha256(request body key/IV)[:16]
		// (0xb4a99a/0xb4a9e5, stored at session+0x20/+0x38).
		wKey: sha16(req.BodyKey),
		wIV:  sha16(req.BodyIV),
		// client -> server body keys: the raw request body key/IV
		// (newCodecLen at 0xb4aa* passes P+17 and P+1).
		rKey: req.BodyKey,
		rIV:  req.BodyIV,
	}
	if req.Option&OptionChunkStream != 0 {
		// Both directions authenticate the length with the request body key/IV
		// (Xray's lengthAuth NonceGenerator uses requestBodyKey/IV in both).
		if vc.wr, err = newCodec(req.Security, vc.wKey, vc.wIV, req.Option, vc.rKey, vc.rIV); err != nil {
			return nil, err
		}
		if vc.rd, err = newCodec(req.Security, vc.rKey, vc.rIV, req.Option, vc.rKey, vc.rIV); err != nil {
			return nil, err
		}
	}

	sess := &core.Session{UserID: req.UserID}
	switch req.Cmd {
	case CmdTCP:
		if reader := core.NewReadPauseConn(conn); reader != nil {
			vc.conn = reader
		}
		sess.Dest = req.Dest
		sess.Conn = vc
	case CmdUDP:
		if req.Option&OptionChunkStream == 0 || vc.rd == nil || vc.wr == nil {
			return nil, ErrUDPNotChunked
		}
		sess.Dest = req.Dest
		sess.Conn = vc
		sess.Packets = &packetStream{conn: vc, dest: req.Dest}
	case CmdMux:
		sess.Dest = socks.Addr{Host: MuxAddress, Port: MuxPort}
		sess.Conn = vc
		if h.mux != nil {
			sess.Packets = h.mux(vc)
		}
	default:
		return nil, ErrUnsupportedCommand
	}
	return sess, nil
}

// checkOption rejects the option combinations this build cannot carry.
//
// Bit 0x04 (chunk masking) is accepted but has no effect: the sample XORs the
// sealed length with a mask stream produced by a SHAKE-based object built in
// newCodecLen (0xb45580 stores an itab + a 32-byte shakeWrapper; the reader
// branch at 0xb45a5f consumes it). The seed order was not decoded, so the
// length here is simply the sealed length. UNVERIFIED: a peer that really
// masks the length will fail with "vmess: corrupt chunk length".
func (h *Handler) checkOption(option byte) error {
	if option&OptionGlobalPadding != 0 {
		if option&OptionChunkMasking == 0 {
			return ErrPaddingNeedsMasking
		}
	}
	return nil
}

// identify decrypts the authID with every user key and checks CRC + clock
// (vmess.(*Handler).identify @0xb49920: crypto/rand-free, it uses
// hash/crc32.ChecksumIEEE and time.Now).
func (h *Handler) identify(authID, head []byte) (int, []byte, error) {
	var plain [16]byte
	for id, user := range h.users {
		key := h.key[id]
		block, err := aes.NewCipher(kdf16(key, []byte(kdfAuthID)))
		if err != nil {
			continue
		}
		block.Decrypt(plain[:], authID)
		crcOK := crc32.ChecksumIEEE(plain[:12]) == binary.BigEndian.Uint32(plain[12:16])
		if !crcOK {
			continue
		}
		ts := int64(binary.BigEndian.Uint64(plain[:8]))
		skew := time.Since(time.Unix(ts, 0))
		if skew < -vmessClockWindow || skew > vmessClockWindow {
			return 0, nil, ErrUnknownUser
		}
		return user.ID, key, nil
	}
	return 0, nil, ErrUnknownUser
}

// fresh rejects a replayed authID inside the clock window
// (vmess.(*Handler).fresh @0xb49b00 keeps a map with a 120 s TTL).
func (h *Handler) fresh(authID []byte) error {
	var id [16]byte
	copy(id[:], authID)
	now := time.Now()
	h.replayMu.Lock()
	defer h.replayMu.Unlock()
	for k, t := range h.replay {
		if now.Sub(t) > 2*vmessClockWindow {
			delete(h.replay, k)
		}
	}
	if _, ok := h.replay[id]; ok {
		return ErrReplayed
	}
	h.replay[id] = now
	return nil
}

// request is the decoded request header.
type request struct {
	BodyIV   [16]byte
	BodyKey  [16]byte
	RespV    byte
	Option   byte
	Security byte
	Cmd      byte
	Dest     socks.Addr
	UserID   int
}

// parseRequestHeader decodes the AEAD-protected header buffer.
func parseRequestHeader(p []byte) (*request, error) {
	if len(p) < 42 {
		return nil, ErrMalformed
	}
	if p[0] != 1 {
		return nil, ErrMalformed
	}
	// FNV-1a 32 over everything but the trailing checksum (the loop at
	// 0xb4a836 uses 0x811c9dc5 and 0x1000193; the stored value is big endian,
	// 0xb4a84c bswap).
	want := binary.BigEndian.Uint32(p[len(p)-4:])
	if fnv1a32(p[:len(p)-4]) != want {
		return nil, ErrChecksum
	}
	r := &request{}
	copy(r.BodyIV[:], p[1:17])
	copy(r.BodyKey[:], p[17:33])
	r.RespV = p[33]
	r.Option = p[34]
	r.Security = p[35] & 0x0f
	padLen := int(p[35] >> 4)
	r.Cmd = p[37]

	dest, used, err := parseDest(p[38 : len(p)-4])
	if err != nil {
		return nil, err
	}
	r.Dest = dest
	// 38 fixed bytes up to the port, then [port][atyp][address], the header
	// padding (high nibble of p[35]) and the 4-byte checksum.
	if 38+used+padLen+4 != len(p) {
		return nil, ErrMalformed
	}
	switch r.Security {
	case SecAES128GCM, SecChaCha20, SecNone, SecZero:
	case 0x01:
		return nil, ErrLegacyCFB
	default:
		return nil, ErrUnknownBodyCipher
	}
	return r, nil
}

// parseDest decodes [port BE16][ATYP][address] (vmess.parseDest @0xb4b100).
func parseDest(b []byte) (socks.Addr, int, error) {
	if len(b) < 3 {
		return socks.Addr{}, 0, ErrTruncatedAddress
	}
	a := socks.Addr{Port: binary.BigEndian.Uint16(b[:2])}
	switch b[2] {
	case 1:
		if len(b) < 7 {
			return socks.Addr{}, 0, ErrTruncatedAddress
		}
		a.Host = net.IP(b[3:7]).String()
		return a, 7, nil
	case 2:
		n := int(b[3])
		if n == 0 || len(b) < 4+n {
			return socks.Addr{}, 0, ErrBadAddress
		}
		a.Host = string(b[4 : 4+n])
		return a, 4 + n, nil
	case 3:
		if len(b) < 19 {
			return socks.Addr{}, 0, ErrTruncatedAddress
		}
		a.Host = net.IP(b[3:19]).String()
		return a, 19, nil
	}
	return socks.Addr{}, 0, ErrBadAddress
}

// parseUUID decodes a textual UUID into its 16 bytes.
func parseUUID(s string) ([16]byte, error) {
	var id [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != 32 {
		return id, fmt.Errorf("vmess: bad UUID %q", s)
	}
	for i := 0; i < 16; i++ {
		hi := hexVal(clean[2*i])
		lo := hexVal(clean[2*i+1])
		if hi < 0 || lo < 0 {
			return id, fmt.Errorf("vmess: bad UUID %q", s)
		}
		id[i] = byte(hi<<4 | lo)
	}
	return id, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// fnv1a32 is the checksum of the request header (0x811c9dc5 / 0x1000193).
func fnv1a32(b []byte) uint32 {
	h := uint32(0x811c9dc5)
	for _, c := range b {
		h ^= uint32(c)
		h *= 0x1000193
	}
	return h
}

// ---------------------------------------------------------------------------
// KDF

// hmacCreator is the chain of vmess.kdf @0xb49120: each link is
// hmac.New(parent.create, value), with the root hmac.New(sha256.New,
// "VMess AEAD KDF") built by kdf.func1 @0xb4c120.
type hmacCreator struct {
	parent *hmacCreator
	value  []byte
}

func (c *hmacCreator) create() hash.Hash {
	if c.parent == nil {
		return hmac.New(sha256.New, c.value)
	}
	return hmac.New(c.parent.create, c.value)
}

// kdf computes the keyed HMAC chain: the path elements are the HMAC keys, the
// data key is written into the final hash (0xb4922b Write, 0xb4926d Sum).
func kdf(key []byte, path ...[]byte) []byte {
	c := &hmacCreator{value: []byte("VMess AEAD KDF")}
	for _, p := range path {
		c = &hmacCreator{parent: c, value: p}
	}
	mac := c.create()
	mac.Write(key)
	return mac.Sum(nil)
}

func kdf16(key []byte, path ...[]byte) []byte { return kdf(key, path...)[:16] }

func sha16(b [16]byte) [16]byte {
	sum := sha256.Sum256(b[:])
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// newGCM is vmess.gcm @0xb49de0.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// chachaKey is vmess.chachaKey @0xb49300: MD5(k) || MD5(MD5(k)) as a 32-byte
// chacha20-poly1305 key.
func chachaKey(k []byte) []byte {
	sum := md5.Sum(k)
	out := make([]byte, 32)
	copy(out, sum[:])
	inner := md5.Sum(sum[:])
	copy(out[16:], inner[:])
	return out
}

// newAEAD is vmess.newAEAD @0xb45280: 3 = AES-128-GCM, 4 = ChaCha20-Poly1305,
// 5/6 = no body cipher at all.
func newAEAD(sec byte, key []byte) (cipher.AEAD, error) {
	switch sec {
	case SecAES128GCM:
		return newGCM(key)
	case SecChaCha20:
		return chacha20poly1305.New(chachaKey(key))
	}
	return nil, nil
}
