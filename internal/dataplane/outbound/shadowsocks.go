package outbound

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// ssCipher is one Shadowsocks method. The classic AEAD family plus the 2022
// family is what the binary's map (shadowsocks.map.init.0 @0xb109a0) contains;
// kaze also carries LEA/Rabbit/AEZ/Deoxys/AEGIS/ASCON but no panel emits them,
// and the server's own 2022 table only has the two AES entries
// (REPORT.md §24.1).
type ssCipher struct {
	name   string
	keyLen int
	aead   func(key []byte) (cipher.AEAD, error)
	is2022 bool
}

func aeadAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aeadChaCha(key []byte) (cipher.AEAD, error) { return chacha20poly1305.New(key) }

var ssCiphers = map[string]ssCipher{
	"aes-128-gcm":                   {"aes-128-gcm", 16, aeadAESGCM, false},
	"aes-192-gcm":                   {"aes-192-gcm", 24, aeadAESGCM, false},
	"aes-256-gcm":                   {"aes-256-gcm", 32, aeadAESGCM, false},
	"chacha20-ietf-poly1305":        {"chacha20-ietf-poly1305", 32, aeadChaCha, false},
	"chacha20-poly1305":             {"chacha20-poly1305", 32, aeadChaCha, false},
	"xchacha20-ietf-poly1305":       {"xchacha20-ietf-poly1305", 32, aeadChaCha, false},
	"2022-blake3-aes-128-gcm":       {"2022-blake3-aes-128-gcm", 16, aeadAESGCM, true},
	"2022-blake3-aes-256-gcm":       {"2022-blake3-aes-256-gcm", 32, aeadAESGCM, true},
	"2022-blake3-chacha20-poly1305": {"2022-blake3-chacha20-poly1305", 32, aeadChaCha, true},
}

// shadowsocksOutbound is the Shadowsocks client (proto/shadowsocks.(*Client),
// ss.NewClient @0xb14260). It is kept here so outbound.New is self-contained;
// the wire format is the standard AEAD/2022 one.
type shadowsocksOutbound struct {
	addr      socks.Addr
	cipher    ssCipher
	key       []byte // classic master key, or the 2022 user PSK
	serverKey []byte // 2022 identity PSK (nil for single-key)
	plugin    *pluginSettings
	stream    *stream
	opt       opt.Opt
}

func newShadowsocks(s settings, o opt.Opt) (core.Outbound, error) {
	addr, err := serverAddr(s, "shadowsocks")
	if err != nil {
		return nil, err
	}
	method := strings.ToLower(strings.TrimSpace(s.str(keysMethod...)))
	if method == "" {
		method = "aes-128-gcm"
	}
	c, ok := ssCiphers[method]
	if !ok {
		// The sample's server table has no 2022 chacha; report it exactly as
		// the server does so a panel misconfiguration is obvious.
		return nil, fmt.Errorf("shadowsocks: unsupported cipher %q", method)
	}
	password := s.str(keysPassword...)
	if password == "" {
		password = s.str("server_key", "serverKey")
	}
	if password == "" {
		return nil, errors.New("shadowsocks outbound needs a password")
	}
	st, err := readStream(o)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks outbound: %w", err)
	}
	plugin, err := readPlugin(s, o, st)
	if err != nil {
		return nil, err
	}
	if st.tls.ech != "" {
		return nil, errors.New("shadowsocks through ECH is not supported")
	}
	key, serverKey, err := parseSSKeys(c, password, s.str(keysServerKey...))
	if err != nil {
		return nil, err
	}
	return &shadowsocksOutbound{
		addr:      addr,
		cipher:    c,
		key:       key,
		serverKey: serverKey,
		plugin:    plugin,
		stream:    st,
		opt:       o,
	}, nil
}

func (o *shadowsocksOutbound) Name() string { return "shadowsocks" }

// parseSSKeys resolves the password field:
//
//   - classic ciphers: base64 key of exactly keyLen bytes, else the SIP002
//     passphrase is stretched with EVP_BytesToKey (shadowsocks.evpBytesToKey
//     @0xb17ac0);
//   - 2022 ciphers: the PSK must be base64 of keyLen bytes
//     ("shadowsocks: server key must be %d bytes in base64"). "serverPSK:userPSK"
//     selects the multi-user identity header.
func parseSSKeys(c ssCipher, password, serverKeySetting string) (key, identity []byte, err error) {
	decode := func(s string) ([]byte, bool) {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			return nil, false
		}
		return b, true
	}
	if c.is2022 {
		serverPart, userPart := password, ""
		if i := strings.IndexByte(password, ':'); i >= 0 {
			serverPart, userPart = password[:i], password[i+1:]
		}
		serverPSK, ok := decode(serverPart)
		if !ok || len(serverPSK) != c.keyLen {
			return nil, nil, fmt.Errorf("shadowsocks: server key must be %d bytes in base64", c.keyLen)
		}
		if serverKeySetting != "" {
			sb, ok := decode(serverKeySetting)
			if !ok || len(sb) != c.keyLen {
				return nil, nil, fmt.Errorf("shadowsocks: server key must be %d bytes in base64", c.keyLen)
			}
			serverPSK = sb
		}
		if userPart != "" {
			userPSK, ok := decode(userPart)
			if !ok || len(userPSK) != c.keyLen {
				return nil, nil, fmt.Errorf("shadowsocks: each key must be %d bytes in base64", c.keyLen)
			}
			return userPSK, serverPSK, nil
		}
		return serverPSK, nil, nil
	}
	if b, ok := decode(password); ok && len(b) == c.keyLen {
		return b, nil, nil
	}
	return evpBytesToKey([]byte(password), c.keyLen), nil, nil
}

// evpBytesToKey is OpenSSL's EVP_BytesToKey with MD5, shadowsocks.evpBytesToKey
// @0xb17ac0.
func evpBytesToKey(password []byte, keyLen int) []byte {
	var out, prev []byte
	for len(out) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

// hkdfSHA1 is shadowsocks.hkdfSHA1 @0xb12980 (the classic subkey derivation).
func hkdfSHA1(key, salt []byte, info string, outLen int) []byte {
	r := hmac.New(sha1.New, salt)
	r.Write(key)
	prk := r.Sum(nil)
	out := make([]byte, 0, outLen)
	var t []byte
	for i := byte(1); len(out) < outLen; i++ {
		h := hmac.New(sha1.New, prk)
		h.Write(t)
		h.Write([]byte(info))
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:outLen]
}

// ssWriter writes AEAD chunks. The nonce is a 96-bit little-endian counter
// starting at 0 (SIP004).
type ssWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	nonce  [12]byte
	cipher ssCipher
	mu     sync.Mutex
	first  bool
}

func newSSWriter(w io.Writer, key []byte, c ssCipher, is2022 bool) (*ssWriter, error) {
	aead, err := c.aead(key)
	if err != nil {
		return nil, err
	}
	return &ssWriter{w: w, aead: aead, cipher: c, first: is2022}, nil
}

// sealBlock seals with the current nonce, then increments it (SIP004: the
// 96-bit nonce is a little-endian counter starting at zero).
func (s *ssWriter) sealBlock(p []byte) []byte {
	out := s.aead.Seal(nil, s.nonce[:s.aead.NonceSize()], p, nil)
	incNonce(s.nonce[:s.aead.NonceSize()])
	return out
}

func (s *ssWriter) write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.first {
		// 2022: the first client chunk starts with a padding-length byte.
		// UNVERIFIED: SIP022's padding byte is implemented with zero padding
		// because the sample's own 2022 client cannot authenticate against its
		// own server anyway (REPORT.md §24.1) and no local peer exercises it.
		p = append([]byte{0}, p...)
		s.first = false
	}
	total := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > 0x3fff {
			n = 0x3fff
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		if _, err := s.w.Write(s.sealBlock(lenBuf[:])); err != nil {
			return 0, err
		}
		if _, err := s.w.Write(s.sealBlock(p[:n])); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return total, nil
}

// incNonce increments a little-endian nonce.
func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// ssReader reverses ssWriter.
type ssReader struct {
	r       io.Reader
	aead    cipher.AEAD
	nonce   [12]byte
	buf     []byte
	master  []byte
	cipher  ssCipher
	started bool
}

// init consumes the server's response salt and derives the response subkey
// (classic: HKDF-SHA1; 2022: BLAKE3). The request salt only covers the client
// direction.
func (s *ssReader) init() error {
	if s.started {
		return nil
	}
	salt := make([]byte, s.cipher.keyLen)
	if _, err := io.ReadFull(s.r, salt); err != nil {
		return err
	}
	var key []byte
	if s.cipher.is2022 {
		h := blake3.New(s.cipher.keyLen, s.master)
		h.Write(salt)
		key = h.Sum(nil)
	} else {
		key = hkdfSHA1(s.master, salt, "ss-subkey", s.cipher.keyLen)
	}
	aead, err := s.cipher.aead(key)
	if err != nil {
		return err
	}
	s.aead = aead
	s.started = true
	return nil
}

func (s *ssReader) openBlock(sealed []byte) ([]byte, error) {
	out, err := s.aead.Open(nil, s.nonce[:s.aead.NonceSize()], sealed, nil)
	incNonce(s.nonce[:s.aead.NonceSize()])
	return out, err
}

func (s *ssReader) read(p []byte) (int, error) {
	if err := s.init(); err != nil {
		return 0, err
	}
	for len(s.buf) == 0 {
		lenSealed := make([]byte, 2+s.aead.Overhead())
		if _, err := io.ReadFull(s.r, lenSealed); err != nil {
			return 0, err
		}
		lenPlain, err := s.openBlock(lenSealed)
		if err != nil || len(lenPlain) != 2 {
			return 0, errors.New("shadowsocks: corrupt length chunk")
		}
		n := int(binary.BigEndian.Uint16(lenPlain))
		if n == 0 {
			continue
		}
		body := make([]byte, n+s.aead.Overhead())
		if _, err := io.ReadFull(s.r, body); err != nil {
			return 0, err
		}
		plain, err := s.openBlock(body)
		if err != nil {
			return 0, errors.New("shadowsocks: corrupt payload chunk")
		}
		s.buf = plain
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// ssConn is the Shadowsocks TCP client conn: salt + EIH (2022) + chunks.
type ssConn struct {
	net.Conn //nolint:embedded
	w        *ssWriter
	r        *ssReader
}

func (c *ssConn) Write(p []byte) (int, error) { return c.w.write(p) }
func (c *ssConn) Read(p []byte) (int, error)  { return c.r.read(p) }

func (c *ssConn) CloseWrite() error { return core.CloseWrite(c.Conn) }

// openTarget is implemented by both protocols through the Proxy method; the
// Shadowsocks handshake is purely key + salt.
func (o *shadowsocksOutbound) connect(ctx context.Context) (net.Conn, error) {
	c, err := o.dialServer(ctx)
	if err != nil {
		return nil, err
	}
	hdr, key, err := o.sessionKeys()
	if err != nil {
		c.Close()
		return nil, err
	}
	if _, err := c.Write(hdr); err != nil {
		c.Close()
		return nil, err
	}
	w, err := newSSWriter(c, key, o.cipher, o.cipher.is2022)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &ssConn{Conn: c, w: w, r: &ssReader{r: c, master: o.key, cipher: o.cipher}}, nil
}

// sessionKeys builds the salt (and the 2022 identity header) and derives the
// session subkey.
func (o *shadowsocksOutbound) sessionKeys() (hdr, key []byte, err error) {
	salt := make([]byte, o.cipher.keyLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	hdr = append(hdr, salt...)
	if o.cipher.is2022 {
		if o.serverKey != nil {
			// Multi-user: AES-128-ECB(identity PSK, unix seconds BE64 || 0).
			var plain [16]byte
			binary.BigEndian.PutUint64(plain[:8], uint64(nowUnix()))
			block, err := aes.NewCipher(o.serverKey)
			if err != nil {
				return nil, nil, err
			}
			var eih [16]byte
			block.Encrypt(eih[:], plain[:])
			hdr = append(hdr, eih[:]...)
		}
		// SIP022: session subkey = BLAKE3(key=PSK, message=salt), truncated to
		// the cipher's key length.
		h := blake3.New(o.cipher.keyLen, o.key)
		h.Write(salt)
		return hdr, h.Sum(nil), nil
	}
	// Classic: subkey = HKDF-SHA1(master key, salt, "ss-subkey").
	return hdr, hkdfSHA1(o.key, salt, "ss-subkey", o.cipher.keyLen), nil
}

func (o *shadowsocksOutbound) DialTCP(ctx context.Context, dest socks.Addr) (net.Conn, error) {
	c, err := o.connect(ctx)
	if err != nil {
		return nil, err
	}
	// SOCKS5-style destination as the first payload byte stream.
	addr, err := appendSocksAddr(nil, dest)
	if err != nil {
		c.Close()
		return nil, err
	}
	if _, err := c.Write(addr); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// DialPacket sends each datagram as salt + sealed([addr][payload]). Classic and
// 2022 both use a fresh salt per datagram with counter 0.
func (o *shadowsocksOutbound) DialPacket(ctx context.Context, dest socks.Addr) (core.PacketStream, error) {
	var d net.Dialer
	pc, err := d.DialContext(ctx, "udp", o.addr.String())
	if err != nil {
		return nil, err
	}
	return &ssPacketConn{pc: pc, o: o, dest: dest}, nil
}

type ssPacketConn struct {
	pc   net.Conn
	o    *shadowsocksOutbound
	dest socks.Addr
}

func (s *ssPacketConn) WritePacket(p []byte, a socks.Addr) error {
	body, err := appendSocksAddr(nil, a)
	if err != nil {
		return err
	}
	body = append(body, p...)
	hdr, key, err := s.o.sessionKeys()
	if err != nil {
		return err
	}
	aead, err := s.o.cipher.aead(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, body, nil)
	buf := append(hdr, sealed...)
	_, err = s.pc.Write(buf)
	return err
}

func (s *ssPacketConn) ReadPacket(p []byte) (int, socks.Addr, error) {
	buf := make([]byte, 64*1024)
	n, err := s.pc.Read(buf)
	if err != nil {
		return 0, socks.Addr{}, err
	}
	saltLen := s.o.cipher.keyLen
	off := saltLen
	if s.o.cipher.is2022 {
		if s.o.serverKey != nil {
			off += 16 // identity header
		}
		if n < off {
			return 0, socks.Addr{}, errors.New("shadowsocks: short UDP datagram")
		}
		h := blake3.New(s.o.cipher.keyLen, s.o.key)
		h.Write(buf[:saltLen])
		aead, err := s.o.cipher.aead(h.Sum(nil))
		if err != nil {
			return 0, socks.Addr{}, err
		}
		plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), buf[off:n], nil)
		if err != nil {
			return 0, socks.Addr{}, errors.New("shadowsocks: corrupt UDP datagram")
		}
		addr, used, err := parseSocksAddr(plain)
		if err != nil {
			return 0, socks.Addr{}, err
		}
		return copy(p, plain[used:]), addr, nil
	}
	if n < saltLen {
		return 0, socks.Addr{}, errors.New("shadowsocks: short UDP datagram")
	}
	key := hkdfSHA1(s.o.key, buf[:saltLen], "ss-subkey", s.o.cipher.keyLen)
	aead, err := s.o.cipher.aead(key)
	if err != nil {
		return 0, socks.Addr{}, err
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), buf[saltLen:n], nil)
	if err != nil {
		return 0, socks.Addr{}, errors.New("shadowsocks: corrupt UDP datagram")
	}
	addr, used, err := parseSocksAddr(plain)
	if err != nil {
		return 0, socks.Addr{}, err
	}
	return copy(p, plain[used:]), addr, nil
}

func (s *ssPacketConn) Close() error { return s.pc.Close() }

// nowUnix is a test hook.
var nowUnix = func() int64 { return time.Now().Unix() }

// dialServer dials the Shadowsocks server through the configured transport and
// SIP003 plugin.
func (o *shadowsocksOutbound) dialServer(ctx context.Context) (net.Conn, error) {
	tp := &Proxy{protocol: "shadowsocks", opt: o.opt, addr: o.addr, stream: o.stream}
	if o.stream != nil && o.plugin != nil {
		st := *o.stream
		st.plugin = o.plugin
		tp.stream = &st
	}
	return tp.openStream(ctx)
}
