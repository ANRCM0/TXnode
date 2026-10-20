package outbound

import (
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
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// VMess wire format, aligned with the sample's client and with the peer this
// client is tested against (internal/proto/vmess):
//
// Request header (plaintext, (*Client).request @0xb46860):
//
//	[0]      version = 1
//	[1:17]   requestBodyIV   (random)
//	[17:33]  requestBodyKey  (random)
//	[33]     responseHeader  (random; the server echoes it in its response)
//	[34]     option          (0x01 chunk stream, |0x10 authenticated length)
//	[35]     (paddingLen << 4) | security
//	[36]     reserved = 0
//	[37]     command (1 = TCP)
//	[38:40]  port (BE16)
//	[40:]    ATYP + address, then paddingLen random bytes,
//	         then FNV-1a32 of everything before it (BE): 0xb46fce on the client,
//	         parseRequestHeader @0xb4a836 (0x811c9dc5 / 0x1000193) on the server.
//
// KDF: vmess.kdf @0xb49120 is a nested HMAC chain whose root is keyed by the
// literal "VMess AEAD KDF" (vmess.kdf.func1 @0xb4c120 writes the 14 bytes as
// immediates) and whose path elements are the HMAC *keys*, with the input key
// written as data at the end:
//
//	kdf(key, p1..pn) = HMAC(HMAC(…HMAC("VMess AEAD KDF", p1)…, pn), key)
//
// The request header path is three elements: [label, authID(16), connNonce(8)]
// (client 0xb4719f/0xb47286/0xb47416, server 0xb4a32f `mov esi,3`); the authID
// encryption uses one element. Wire layout:
//
//	authID(16) | sealedLen(18) | connNonce(8) | sealedHdr
//
// connNonce is eight random bytes written after the length block (0xb47361);
// the server reads 42 bytes up front (0xb4a1e4 `mov $0x2a,%edi`).
//
// authID = AES-ECB(KDF16(cmdKey, "AES Auth ID Encryption"), ts BE64 || rand4 || crc32(ts||rand4))
// (the server's identify @0xb49920 checks CRC32 over the first 12 bytes).
//
// Response header (server (*vmessConn).header @0xb4b3e0, client
// (*ClientConn).response @0xb48640):
//
//	seeds: wKey = sha256(requestBodyKey)[:16], wIV = sha256(requestBodyIV)[:16]
//	sealedLen = AEAD(KDF16(wKey,"AEAD Resp Header Len Key"),
//	                 nonce=KDF(wIV,"AEAD Resp Header Len IV")[:12],
//	                 plaintext=BE16(4), AD=nil)       // AD cleared at 0xb48851
//	sealedHdr = AEAD(KDF16(wKey,"AEAD Resp Header Key"),
//	                 nonce=KDF(wIV,"AEAD Resp Header IV")[:12],
//	                 plaintext=[respV][0][0][0], AD=nil) // AD cleared at 0xb48a5d
//
// The decrypted header length is checked against 4 (0xb48a89 `cmp $0x4`), and
// the first byte must equal the responseHeader byte the client sent.
//
// Body chunks (both directions, vmess.newCodecLen @0xb45320):
//
//	length  : BE16(n), sealed with KDF16(bodyKey,"auth_len") when option&0x10
//	payload : sealed with bodyKey
//	nonce   : the 12-byte body IV with bytes [0:2] replaced by BE16(counter);
//	          the counter starts at 0 and increments on every Seal/Open
//	          (0xb45986), and 0xffff marks the codec broken.
//	client→server uses the raw request body key/IV; server→client uses
//	sha256(...)[:16] of them (0xb4a99a/0xb4a9e5).
const (
	vmessSecAES128GCM = 0x03
	vmessSecChaCha20  = 0x04
	vmessSecNone      = 0x05
	vmessSecZero      = 0x06
)

// Request option bits (proto/vmess.Options and 0xb45320).
const (
	vmessOptionChunkStream   = 0x01
	vmessOptionChunkMasking  = 0x04
	vmessOptionGlobalPadding = 0x08
	vmessOptionAuthLength    = 0x10
)

// vmessRespHeaderLen is the fixed size of the authenticated response header.
const vmessRespHeaderLen = 4

// KDF labels, exactly the rodata strings the client and server reference.
const (
	kdfAuthIDEncryption = "AES Auth ID Encryption"
	kdfHeaderKeyLen     = "VMess Header AEAD Key_Length"
	kdfHeaderNonceLen   = "VMess Header AEAD Nonce_Length"
	kdfHeaderKey        = "VMess Header AEAD Key"
	kdfHeaderNonce      = "VMess Header AEAD Nonce"
	kdfRespLenKey       = "AEAD Resp Header Len Key"
	kdfRespLenIV        = "AEAD Resp Header Len IV"
	kdfRespKey          = "AEAD Resp Header Key"
	kdfRespIV           = "AEAD Resp Header IV"
	kdfAuthLen          = "auth_len"
	kdfRoot             = "VMess AEAD KDF"
)

// newVMess builds the VMess client. Only AEAD headers exist: alterId must be 0.
func newVMess(s settings, o opt.Opt) (*Proxy, error) {
	addr, err := serverAddr(s, "vmess")
	if err != nil {
		return nil, err
	}
	uuidStr := strings.TrimSpace(s.str(keysUUID...))
	if uuidStr == "" {
		return nil, errors.New("vmess outbound needs a UUID")
	}
	uuid, err := parseUUID(uuidStr)
	if err != nil {
		return nil, fmt.Errorf("vmess outbound: %w", err)
	}
	if aid := strings.TrimSpace(s.str(keysAlterID...)); aid != "" && aid != "0" {
		return nil, fmt.Errorf("vmess outbound: alterId %s means the legacy MD5 header, which is not supported; set alterId to 0 (every current server takes the AEAD header)", aid)
	}
	// The body cipher comes from method/cipher; "security" is only a cipher in
	// the VMess dialect (where it cannot also mean TLS), so a transport value
	// such as "tls" falls back to auto.
	secName := strings.ToLower(strings.TrimSpace(s.str(keysMethod...)))
	if secName == "" {
		switch v := strings.ToLower(strings.TrimSpace(s.str(keysSecurity...))); v {
		case "", "tls", "reality":
			// A transport security, not a body cipher.
		default:
			secName = v
		}
	}
	var sec byte
	switch secName {
	case "", "auto":
		sec = vmessSecAES128GCM
		secName = "aes-128-gcm"
	case "aes-128-gcm", "aes128-gcm", "aes-128":
		sec = vmessSecAES128GCM
	case "chacha20-poly1305", "chacha20-ietf-poly1305":
		sec = vmessSecChaCha20
	case "none":
		sec = vmessSecNone
	case "zero":
		sec = vmessSecZero
	case "aes-128-cfb":
		return nil, errors.New("vmess: the legacy aes-128-cfb body cipher is not supported; use auto, aes-128-gcm, chacha20-poly1305, none or zero")
	default:
		return nil, fmt.Errorf("vmess: unknown cipher %q (auto, aes-128-gcm, chacha20-poly1305, none, zero)", secName)
	}
	// In the VMess dialect "security" names the body cipher (REPORT.md §22.4:
	// {security:"none"}), not the transport security; strip it before
	// readStream so it is not mistaken for TLS/REALITY.
	streamOpt := o
	if v, ok := o["security"].(string); ok && isVMessCipher(v) {
		streamOpt = opt.Merge(o, nil)
		delete(streamOpt, "security")
	}
	st, err := readStream(streamOpt)
	if err != nil {
		return nil, fmt.Errorf("vmess outbound: %w", err)
	}
	p := &Proxy{
		protocol: "vmess",
		opt:      o,
		stream:   st,
		addr:     addr,
		uuid:     uuid,
		method:   secName,
		security: sec,
	}
	via, err := readVia(o)
	if err != nil {
		return nil, err
	}
	p.via = via
	return p, nil
}

// isVMessCipher reports whether a "security" value is a VMess body cipher
// rather than a transport security.
func isVMessCipher(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "auto", "aes-128-gcm", "aes128-gcm", "aes-128", "chacha20-poly1305",
		"chacha20-ietf-poly1305", "none", "zero", "aes-128-cfb":
		return true
	}
	return false
}

// cmdKey is MD5(uuid) — only a KDF seed (vmess.cmdKey @0xb493e0).
func (p *Proxy) cmdKey() []byte {
	sum := md5.Sum(p.uuid[:])
	return sum[:]
}

// ---------------------------------------------------------------------------
// KDF (vmess.kdf @0xb49120, root label from vmess.kdf.func1 @0xb4c120)

type vmessKDFNode struct {
	parent *vmessKDFNode
	value  []byte
}

func (n *vmessKDFNode) create() hash.Hash {
	if n.parent == nil {
		return hmac.New(sha256.New, n.value)
	}
	return hmac.New(n.parent.create, n.value)
}

// vmessKDF is the nested HMAC chain: path elements are HMAC keys, the input key
// is the data of the final hash.
func vmessKDF(key []byte, parts ...[]byte) []byte {
	node := &vmessKDFNode{value: []byte(kdfRoot)}
	for _, p := range parts {
		node = &vmessKDFNode{parent: node, value: p}
	}
	mac := node.create()
	mac.Write(key)
	return mac.Sum(nil)
}

func vmessKDF16(key []byte, parts ...[]byte) []byte { return vmessKDF(key, parts...)[:16] }

// vmessGCM is vmess.gcm @0xb49de0 (AES-GCM; 16-byte keys here).
func vmessGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// vmessChaChaKey derives the 32-byte chacha key: MD5(k) || MD5(MD5(k)),
// vmess.chachaKey @0xb49300.
func vmessChaChaKey(key []byte) []byte {
	k1 := md5.Sum(key)
	k2 := md5.Sum(k1[:])
	out := make([]byte, 0, 32)
	out = append(out, k1[:]...)
	out = append(out, k2[:]...)
	return out
}

// vmessAEAD builds the body AEAD for a security byte (vmess.newAEAD @0xb45280).
func vmessAEAD(sec byte, key []byte) (cipher.AEAD, error) {
	switch sec {
	case vmessSecAES128GCM:
		return vmessGCM(key)
	case vmessSecChaCha20:
		return chacha20poly1305.New(vmessChaChaKey(key))
	}
	return nil, nil
}

// vmessAuthID builds and encrypts the 16-byte auth ID: unix seconds BE64, four
// random bytes, then CRC32-IEEE of the first twelve bytes (server identify
// @0xb49920).
func vmessAuthID(cmdKey []byte) ([16]byte, error) {
	var plain [16]byte
	binary.BigEndian.PutUint64(plain[:8], uint64(nowUnix()))
	if _, err := randRead(plain[8:12]); err != nil {
		return [16]byte{}, err
	}
	binary.BigEndian.PutUint32(plain[12:16], crc32.ChecksumIEEE(plain[:12]))
	block, err := aes.NewCipher(vmessKDF16(cmdKey, []byte(kdfAuthIDEncryption)))
	if err != nil {
		return [16]byte{}, err
	}
	var out [16]byte
	block.Encrypt(out[:], plain[:])
	return out, nil
}

// vmessKeys is what the request builder hands to the conn.
type vmessKeys struct {
	authID  [16]byte
	cmdKey  []byte
	bodyIV  [16]byte
	bodyKey [16]byte
	respV   byte
}

// fnv1a32 is the request-header checksum (0x811c9dc5 / 0x1000193, stored big
// endian; 0xb46fce on the client, 0xb4a836 on the server).
func fnv1a32(b []byte) uint32 {
	h := uint32(0x811c9dc5)
	for _, c := range b {
		h ^= uint32(c)
		h *= 0x1000193
	}
	return h
}

// vmessRequest writes the AEAD request header (with connNonce in the middle of
// the wire prefix) and returns the keys the conn needs.
func (p *Proxy) vmessRequest(w io.Writer, dest socks.Addr) (vmessKeys, error) {
	var keys vmessKeys
	keys.cmdKey = p.cmdKey()
	authID, err := vmessAuthID(keys.cmdKey)
	if err != nil {
		return keys, err
	}
	keys.authID = authID

	if _, err := randRead(keys.bodyIV[:]); err != nil {
		return keys, err
	}
	if _, err := randRead(keys.bodyKey[:]); err != nil {
		return keys, err
	}
	var respV [1]byte
	if _, err := randRead(respV[:]); err != nil {
		return keys, err
	}
	keys.respV = respV[0]
	var connNonce [8]byte
	if _, err := randRead(connNonce[:]); err != nil {
		return keys, err
	}
	var padRand [1]byte
	if _, err := randRead(padRand[:]); err != nil {
		return keys, err
	}
	padLen := int(padRand[0] & 0x0f)

	// Chunk stream is mandatory for a chunked body (the server only builds its
	// codecs when option&0x01 is set); AEAD adds authenticated lengths.
	option := byte(vmessOptionChunkStream)
	sec := p.security
	if sec == vmessSecAES128GCM || sec == vmessSecChaCha20 {
		option |= vmessOptionAuthLength
	}
	if opt.Opt(p.opt).Bool("chunkMasking", "chunk_masking") {
		option |= vmessOptionChunkMasking
	}
	if opt.Opt(p.opt).Bool("globalPadding", "global_padding") {
		option |= vmessOptionGlobalPadding
		// global padding without masking is rejected by the server.
		option |= vmessOptionChunkMasking
	}
	p.vmessOption = option

	header := make([]byte, 0, 42+len(dest.Host)+padLen+4)
	header = append(header, 0x01) // version
	header = append(header, keys.bodyIV[:]...)
	header = append(header, keys.bodyKey[:]...)
	header = append(header, keys.respV)
	header = append(header, option)
	header = append(header, byte(padLen<<4)|sec)
	header = append(header, 0x00) // reserved
	header = append(header, 0x01) // command: TCP
	header, err = appendVAddr(header, dest)
	if err != nil {
		return keys, err
	}
	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := randRead(padding); err != nil {
			return keys, err
		}
		header = append(header, padding...)
	}
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], fnv1a32(header))
	header = append(header, sum[:]...)

	// KDF path = [label, authID, connNonce]; AD = authID.
	lenAEAD, err := vmessGCM(vmessKDF16(keys.cmdKey, []byte(kdfHeaderKeyLen), authID[:], connNonce[:]))
	if err != nil {
		return keys, err
	}
	lenNonce := vmessKDF(keys.cmdKey, []byte(kdfHeaderNonceLen), authID[:], connNonce[:])[:12]
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(header)))
	sealedLen := lenAEAD.Seal(nil, lenNonce, lenPlain[:], authID[:])

	hdrAEAD, err := vmessGCM(vmessKDF16(keys.cmdKey, []byte(kdfHeaderKey), authID[:], connNonce[:]))
	if err != nil {
		return keys, err
	}
	hdrNonce := vmessKDF(keys.cmdKey, []byte(kdfHeaderNonce), authID[:], connNonce[:])[:12]
	sealedHdr := hdrAEAD.Seal(nil, hdrNonce, header, authID[:])

	if _, err := w.Write(authID[:]); err != nil {
		return keys, err
	}
	if _, err := w.Write(sealedLen); err != nil {
		return keys, err
	}
	if _, err := w.Write(connNonce[:]); err != nil {
		return keys, err
	}
	if _, err := w.Write(sealedHdr); err != nil {
		return keys, err
	}
	return keys, nil
}

// vmessStream writes the request header and returns the chunked conn.
func (p *Proxy) vmessStream(c net.Conn, dest socks.Addr) (net.Conn, error) {
	keys, err := p.vmessRequest(c, dest)
	if err != nil {
		return nil, fmt.Errorf("vmess outbound: %w", err)
	}
	return newVMessConn(c, keys, p.security, p.vmessOption)
}

// ---------------------------------------------------------------------------
// body codec (vmess.newCodecLen @0xb45320)

type vmessCodec struct {
	data    cipher.AEAD
	lenAEAD cipher.AEAD
	nonce   [12]byte
	count   uint16
	wraps   bool

	mask bool
	pad  bool
	xof  io.Reader
}

func newVMessCodec(sec byte, key, iv []byte, option byte) (*vmessCodec, error) {
	c := &vmessCodec{}
	copy(c.nonce[:], iv[:12])
	data, err := vmessAEAD(sec, key)
	if err != nil {
		return nil, err
	}
	c.data = data
	if option&(vmessOptionChunkMasking|vmessOptionGlobalPadding) != 0 {
		sh := sha3.NewShake128()
		_, _ = sh.Write(key)
		_, _ = sh.Write(iv)
		c.xof = sh
		c.mask = option&vmessOptionChunkMasking != 0
		c.pad = option&vmessOptionGlobalPadding != 0
	}
	if data != nil && option&vmessOptionAuthLength != 0 {
		la, err := vmessAEAD(sec, vmessKDF16(key, []byte(kdfAuthLen)))
		if err != nil {
			return nil, err
		}
		c.lenAEAD = la
	}
	return c, nil
}

func (c *vmessCodec) encodeLen(n int) (wire, pad int, err error) {
	if c.pad {
		var b [2]byte
		if _, err := io.ReadFull(c.xof, b[:]); err != nil {
			return 0, 0, err
		}
		pad = int(binary.BigEndian.Uint16(b[:]) & 0x3f)
	}
	wire = n + pad
	if c.mask {
		var b [2]byte
		if _, err := io.ReadFull(c.xof, b[:]); err != nil {
			return 0, 0, err
		}
		wire ^= int(binary.BigEndian.Uint16(b[:]))
	}
	return wire, pad, nil
}

func (c *vmessCodec) decodeLen(wire int) (n, pad int, err error) {
	if c.pad {
		var b [2]byte
		if _, err := io.ReadFull(c.xof, b[:]); err != nil {
			return 0, 0, err
		}
		pad = int(binary.BigEndian.Uint16(b[:]) & 0x3f)
	}
	n = wire
	if c.mask {
		var b [2]byte
		if _, err := io.ReadFull(c.xof, b[:]); err != nil {
			return 0, 0, err
		}
		n ^= int(binary.BigEndian.Uint16(b[:]))
	}
	if n < pad {
		return 0, 0, errors.New("vmess: corrupt chunk length")
	}
	return n - pad, pad, nil
}

// next returns the nonce for one AEAD operation and advances the counter.
func (c *vmessCodec) next() ([]byte, error) {
	if c.wraps {
		return nil, errors.New("vmess: connection reached its chunk limit; reconnect")
	}
	binary.BigEndian.PutUint16(c.nonce[:2], c.count)
	if c.count == 0xffff {
		c.wraps = true
	}
	c.count++
	return c.nonce[:], nil
}

func (c *vmessCodec) lenSize() int {
	if c.lenAEAD == nil {
		return 2
	}
	return 2 + c.lenAEAD.Overhead()
}

func (c *vmessCodec) overhead() int {
	if c.data == nil {
		return 0
	}
	return c.data.Overhead()
}

func (c *vmessCodec) sealLen(n int) ([]byte, error) {
	var lp [2]byte
	binary.BigEndian.PutUint16(lp[:], uint16(n))
	if c.lenAEAD == nil {
		return lp[:], nil
	}
	nonce, err := c.next()
	if err != nil {
		return nil, err
	}
	return c.lenAEAD.Seal(nil, nonce, lp[:], nil), nil
}

func (c *vmessCodec) sealChunk(p []byte) ([]byte, error) {
	if c.data == nil {
		return p, nil
	}
	nonce, err := c.next()
	if err != nil {
		return nil, err
	}
	return c.data.Seal(nil, nonce, p, nil), nil
}

func (c *vmessCodec) openLen(b []byte) (int, error) {
	if c.lenAEAD == nil {
		return int(binary.BigEndian.Uint16(b)), nil
	}
	nonce, err := c.next()
	if err != nil {
		return 0, err
	}
	plain, err := c.lenAEAD.Open(nil, nonce, b, nil)
	if err != nil || len(plain) != 2 {
		return 0, errors.New("vmess: corrupt chunk length")
	}
	return int(binary.BigEndian.Uint16(plain)), nil
}

func (c *vmessCodec) openChunk(b []byte) ([]byte, error) {
	if c.data == nil {
		return b, nil
	}
	nonce, err := c.next()
	if err != nil {
		return nil, err
	}
	plain, err := c.data.Open(nil, nonce, b, nil)
	if err != nil {
		return nil, errors.New("vmess: chunk shorter than its framing")
	}
	return plain, nil
}

// ---------------------------------------------------------------------------
// vmessConn (client side of proto/vmess.(*ClientConn))

type vmessConn struct {
	conn     net.Conn
	keys     vmessKeys
	security byte
	option   byte

	once   sync.Once
	hdrErr error
	rd     *vmessCodec
	rbuf   []byte

	wmu    sync.Mutex
	wr     *vmessCodec
	closed bool
}

func newVMessConn(c net.Conn, keys vmessKeys, security byte, option byte) (*vmessConn, error) {
	if option == 0 {
		option = vmessOptionChunkStream | vmessOptionAuthLength
	}
	v := &vmessConn{conn: c, keys: keys, security: security, option: option}
	// Client -> server body uses the raw request body key/IV.
	wr, err := newVMessCodec(security, keys.bodyKey[:], keys.bodyIV[:], option)
	if err != nil {
		return nil, err
	}
	v.wr = wr
	return v, nil
}

// response reads and authenticates the four-byte response header.
func (v *vmessConn) response() error {
	wKey := sha256.Sum256(v.keys.bodyKey[:])
	wIV := sha256.Sum256(v.keys.bodyIV[:])

	lenAEAD, err := vmessGCM(vmessKDF16(wKey[:16], []byte(kdfRespLenKey)))
	if err != nil {
		return err
	}
	lenNonce := vmessKDF(wIV[:16], []byte(kdfRespLenIV))[:12]
	sealedLen := make([]byte, 2+lenAEAD.Overhead())
	if _, err := io.ReadFull(v.conn, sealedLen); err != nil {
		return err
	}
	lenPlain, err := lenAEAD.Open(nil, lenNonce, sealedLen, nil)
	if err != nil || len(lenPlain) != 2 {
		return errRespMismatch
	}
	n := int(binary.BigEndian.Uint16(lenPlain))
	if n != vmessRespHeaderLen {
		return errRespMismatch
	}
	hdrAEAD, err := vmessGCM(vmessKDF16(wKey[:16], []byte(kdfRespKey)))
	if err != nil {
		return err
	}
	hdrNonce := vmessKDF(wIV[:16], []byte(kdfRespIV))[:12]
	sealedHdr := make([]byte, n+hdrAEAD.Overhead())
	if _, err := io.ReadFull(v.conn, sealedHdr); err != nil {
		return err
	}
	plain, err := hdrAEAD.Open(nil, hdrNonce, sealedHdr, nil)
	if err != nil || len(plain) != vmessRespHeaderLen || plain[0] != v.keys.respV {
		return errRespMismatch
	}
	// Server -> client body keys are sha256(request body key/IV)[:16].
	rd, err := newVMessCodec(v.security, wKey[:16], wIV[:16], v.option)
	if err != nil {
		return err
	}
	v.rd = rd
	return nil
}

var errRespMismatch = errors.New("vmess: the server's response does not match this request (wrong UUID, or not a VMess AEAD server)")

func (v *vmessConn) Read(p []byte) (int, error) {
	v.once.Do(func() { v.hdrErr = v.response() })
	if v.hdrErr != nil {
		return 0, v.hdrErr
	}
	for len(v.rbuf) == 0 {
		lenBuf := make([]byte, v.rd.lenSize())
		if _, err := io.ReadFull(v.conn, lenBuf); err != nil {
			return 0, err
		}
		wire, err := v.rd.openLen(lenBuf)
		if err != nil {
			return 0, err
		}
		if wire == 0 {
			continue
		}
		n, pad, err := v.rd.decodeLen(wire)
		if err != nil {
			return 0, err
		}
		body := make([]byte, n+pad+v.rd.overhead())
		if _, err := io.ReadFull(v.conn, body); err != nil {
			return 0, err
		}
		plain, err := v.rd.openChunk(body)
		if err != nil {
			return 0, err
		}
		if pad > 0 && len(plain) >= pad {
			plain = plain[:len(plain)-pad]
		}
		if len(plain) > 0 {
			v.rbuf = plain
		}
	}
	n := copy(p, v.rbuf)
	v.rbuf = v.rbuf[n:]
	return n, nil
}

// Write sends the request body immediately: the server's response header only
// arrives when it starts answering, so writing must not wait for it.
func (v *vmessConn) Write(p []byte) (int, error) {
	v.wmu.Lock()
	defer v.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > 0xffff {
			n = 0xffff
		}
		wire, pad, err := v.wr.encodeLen(n)
		if err != nil {
			return written, err
		}
		lp, err := v.wr.sealLen(wire)
		if err != nil {
			return written, err
		}
		payload := p[:n]
		if pad > 0 {
			payload = append(append([]byte(nil), payload...), make([]byte, pad)...)
		}
		body, err := v.wr.sealChunk(payload)
		if err != nil {
			return written, err
		}
		buf := make([]byte, 0, len(lp)+len(body))
		buf = append(buf, lp...)
		buf = append(buf, body...)
		if _, err := v.conn.Write(buf); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (v *vmessConn) Close() error                       { return v.conn.Close() }
func (v *vmessConn) LocalAddr() net.Addr                { return v.conn.LocalAddr() }
func (v *vmessConn) RemoteAddr() net.Addr               { return v.conn.RemoteAddr() }
func (v *vmessConn) SetDeadline(t time.Time) error      { return v.conn.SetDeadline(t) }
func (v *vmessConn) SetReadDeadline(t time.Time) error  { return v.conn.SetReadDeadline(t) }
func (v *vmessConn) SetWriteDeadline(t time.Time) error { return v.conn.SetWriteDeadline(t) }

func (v *vmessConn) CloseWrite() error {
	v.wmu.Lock()
	defer v.wmu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	return core.CloseWrite(v.conn)
}

var _ net.Conn = (*vmessConn)(nil)
