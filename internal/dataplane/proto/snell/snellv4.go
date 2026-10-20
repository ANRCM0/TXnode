package snell

// Snell v4: salt | AEAD header (7B plaintext + tag) | padding | AEAD payload,
// with a request ([1][cmd][idLen][id][socks-string host][port]) as the first
// record payload. Key derivation follows Surge 6.7 / sing-snell:
// argon2id(psk, salt, 3, 8, 1, 32)[:16], AES-128-GCM, 12-byte little-endian
// nonce counter.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

const (
	v4Version      = 4
	v4HeaderPlain  = 7
	v4TagLen       = 16
	v4HeaderCipher = v4HeaderPlain + v4TagLen
	v4SaltLen      = 16
	v4MaxPayload   = 0x3fff
)

func v4DeriveKey(psk, salt []byte) []byte {
	return argon2.IDKey(psk, salt, 3, 8, 1, 32)[:16]
}

func v4NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func v4IncreaseNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// v4Reader decrypts records from one direction.
type v4Reader struct {
	r      io.Reader
	aead   cipher.AEAD
	nonce  [12]byte
	cache  []byte
	buf    []byte
}

func (r *v4Reader) readRecord() ([]byte, error) {
	hdr := make([]byte, v4HeaderCipher)
	if _, err := io.ReadFull(r.r, hdr); err != nil {
		return nil, err
	}
	plainHdr, err := r.aead.Open(hdr[:0], r.nonce[:], hdr, nil)
	if err != nil {
		return nil, err
	}
	v4IncreaseNonce(r.nonce[:])
	if plainHdr[0] != v4Version {
		return nil, fmt.Errorf("snell: bad header version %d", plainHdr[0])
	}
	padLen := int(binary.BigEndian.Uint16(plainHdr[3:5]))
	payLen := int(binary.BigEndian.Uint16(plainHdr[5:7]))
	if payLen == 0 {
		return nil, io.EOF
	}
	if payLen > v4MaxPayload || padLen > v4MaxPayload {
		return nil, errors.New("snell: record too large")
	}
	padding := make([]byte, padLen)
	if _, err := io.ReadFull(r.r, padding); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, payLen+v4TagLen)
	if _, err := io.ReadFull(r.r, ciphertext); err != nil {
		return nil, err
	}
	for i := 0; i < len(padding) && i < len(ciphertext); i += 2 {
		padding[i], ciphertext[i] = ciphertext[i], padding[i]
	}
	plain, err := r.aead.Open(ciphertext[:0], r.nonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}
	v4IncreaseNonce(r.nonce[:])
	return plain, nil
}

func (r *v4Reader) Read(p []byte) (int, error) {
	for len(r.cache) == 0 {
		rec, err := r.readRecord()
		if err != nil {
			return 0, err
		}
		r.cache = rec
	}
	n := copy(p, r.cache)
	r.cache = r.cache[n:]
	return n, nil
}

// v4Writer encrypts records for one direction.
type v4Writer struct {
	w     io.Writer
	aead  cipher.AEAD
	nonce [12]byte
	salt  []byte
	sent  bool
	mu    sync.Mutex
}

func newV4Writer(w io.Writer, psk []byte) (*v4Writer, error) {
	salt := make([]byte, v4SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := v4NewAEAD(v4DeriveKey(psk, salt))
	if err != nil {
		return nil, err
	}
	return &v4Writer{w: w, aead: aead, salt: salt}, nil
}

func (w *v4Writer) writeRecord(payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.sent {
		if _, err := w.w.Write(w.salt); err != nil {
			return err
		}
		w.sent = true
	}
	hdr := make([]byte, v4HeaderCipher)
	hdr[0] = v4Version
	binary.BigEndian.PutUint16(hdr[3:5], 0)
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))
	w.aead.Seal(hdr[:0], w.nonce[:], hdr[:v4HeaderPlain], nil)
	v4IncreaseNonce(w.nonce[:])
	out := hdr
	if len(payload) > 0 {
		ct := w.aead.Seal(nil, w.nonce[:], payload, nil)
		v4IncreaseNonce(w.nonce[:])
		out = append(out, ct...)
	}
	_, err := w.w.Write(out)
	return err
}

func (w *v4Writer) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > v4MaxPayload {
			n = v4MaxPayload
		}
		if err := w.writeRecord(p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (w *v4Writer) writeEOF() error { return w.writeRecord(nil) }

// v4Conn adapts the record layer to net.Conn.
type v4Conn struct {
	net.Conn
	r *v4Reader
	w *v4Writer
}

func (c *v4Conn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *v4Conn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *v4Conn) CloseWrite() error {
	if err := c.w.writeEOF(); err != nil {
		return err
	}
	return core.CloseWrite(c.Conn)
}

// v4ReadRequest parses the request carried by the first record.
func v4ReadRequest(p []byte) (cmd byte, dest socks.Addr, clientID string, err error) {
	if len(p) < 3 || p[0] != 1 {
		return 0, socks.Addr{}, "", errors.New("snell: bad v4 request")
	}
	cmd = p[1]
	idLen := int(p[2])
	if len(p) < 3+idLen {
		return 0, socks.Addr{}, "", errors.New("snell: short v4 request")
	}
	clientID = string(p[3 : 3+idLen])
	rest := p[3+idLen:]
	if cmd != cmdConnect && cmd != cmdConnectV2 {
		return cmd, socks.Addr{}, clientID, errors.New("snell: unsupported v4 command")
	}
	if len(rest) < 1 {
		return 0, socks.Addr{}, "", errors.New("snell: short v4 address")
	}
	hostLen := int(rest[0])
	if len(rest) < 1+hostLen+2 {
		return 0, socks.Addr{}, "", errors.New("snell: short v4 address")
	}
	host := string(rest[1 : 1+hostLen])
	port := binary.BigEndian.Uint16(rest[1+hostLen:])
	return cmd, socks.Addr{Host: host, Port: port}, clientID, nil
}

// handleV4 runs the Snell v4 handshake (plain TCP, no obfs).
func (h *Handler) handleV4(ctx context.Context, conn net.Conn) (*core.Session, error) {
	_ = ctx
	timeout := h.opts.AuthTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	salt := make([]byte, v4SaltLen)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, err
	}
	hdr := make([]byte, v4HeaderCipher)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}

	// Try every configured psk: the record header authenticates the key.
	h.usersMu.RLock()
	users := append([]user(nil), h.users...)
	h.usersMu.RUnlock()
	var (
		chosen *user
		aead   cipher.AEAD
		plain  []byte
	)
	for i := range users {
		cand, err := v4NewAEAD(v4DeriveKey(users[i].raw, salt))
		if err != nil {
			continue
		}
		if p, err := cand.Open(nil, make([]byte, 12), hdr, nil); err == nil && p[0] == v4Version {
			chosen = &users[i]
			aead = cand
			plain = p
			break
		}
	}
	if chosen == nil {
		return nil, errors.New("snell: authentication failed")
	}
	var nonce [12]byte
	v4IncreaseNonce(nonce[:]) // header record consumed nonce 0

	padLen := int(binary.BigEndian.Uint16(plain[3:5]))
	payLen := int(binary.BigEndian.Uint16(plain[5:7]))
	if payLen == 0 || payLen > v4MaxPayload || padLen > v4MaxPayload {
		return nil, errors.New("snell: bad v4 request record")
	}
	padding := make([]byte, padLen)
	if _, err := io.ReadFull(conn, padding); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, payLen+v4TagLen)
	if _, err := io.ReadFull(conn, ciphertext); err != nil {
		return nil, err
	}
	for i := 0; i < len(padding) && i < len(ciphertext); i += 2 {
		padding[i], ciphertext[i] = ciphertext[i], padding[i]
	}
	rec, err := aead.Open(ciphertext[:0], nonce[:], ciphertext, nil)
	if err != nil {
		return nil, errors.New("snell: authentication failed")
	}
	v4IncreaseNonce(nonce[:])

	cmd, dest, clientID, err := v4ReadRequest(rec)
	if err != nil {
		return nil, err
	}
	if cmd != cmdConnect && cmd != cmdConnectV2 {
		return nil, errors.New("snell: unsupported v4 command")
	}
	if clientID != "" && clientID != chosen.name {
		if u, ok := h.lookup(clientID); ok {
			chosen = u
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	writer, err := newV4Writer(conn, chosen.raw)
	if err != nil {
		return nil, err
	}
	if err := writer.writeRecord([]byte{0x00}); err != nil { // ReplyTunnel
		return nil, err
	}
	vc := &v4Conn{Conn: conn, r: &v4Reader{r: conn, aead: aead, nonce: nonce}, w: writer}
	return &core.Session{UserID: chosen.core.ID, Dest: dest, Conn: vc}, nil
}
