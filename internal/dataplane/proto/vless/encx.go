package vless

// Xray-compatible VLESS Encryption (mlkem768x25519plus) server handshake and
// record layer. This mirrors proxy/vless/encryption of xray-core 26.x:
//
//	client hello: iv(16) | relays | [AEAD len][AEAD pfs public key] | [AEAD len][padding]
//	server hello: AEAD(nfs, MaxNonce, pfs public key) | AEAD(pfs, ticket) | [AEAD len][padding]
//
// The record layer is a TLS-looking 5-byte header plus an AEAD record keyed by
// blake3.DeriveKey(context, unitedKey); the nonce increments per record and the
// key is re-derived from the previous record when the nonce saturates.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

const (
	xMaxRecord  = 16640
	xMinRecord  = 17
	xMaxPayload = 8192
	xHeaderLen  = 5
	xTagLen     = 16
)

var xMaxNonce = bytes.Repeat([]byte{255}, 12)

type xAEAD struct {
	cipher.AEAD
	nonce [12]byte
}

func newXAEAD(ctx, key []byte, useAES bool) *xAEAD {
	k := make([]byte, 32)
	blake3.DeriveKey(k, string(ctx), key)
	var aead cipher.AEAD
	if useAES {
		block, _ := aes.NewCipher(k)
		aead, _ = cipher.NewGCM(block)
	} else {
		aead, _ = chacha20poly1305.New(k)
	}
	return &xAEAD{AEAD: aead}
}

func (a *xAEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	if nonce == nil {
		nonce = increaseNonce(a.nonce[:])
	}
	return a.AEAD.Seal(dst, nonce, plaintext, ad)
}

func (a *xAEAD) open(nonce, ciphertext, ad []byte) ([]byte, error) {
	if nonce == nil {
		nonce = increaseNonce(a.nonce[:])
	}
	return a.AEAD.Open(nil, nonce, ciphertext, ad)
}

func increaseNonce(n []byte) []byte {
	for i := 0; i < 12; i++ {
		n[11-i]++
		if n[11-i] != 0 {
			break
		}
	}
	return n
}

func xEncodeHeader(h []byte, l int) {
	h[0] = 23
	h[1] = 3
	h[2] = 3
	h[3] = byte(l >> 8)
	h[4] = byte(l)
}

func xDecodeHeader(h []byte) (int, error) {
	if h[0] != 23 || h[1] != 3 || h[2] != 3 {
		return 0, errors.New("vless encryption: not a TLS record")
	}
	l := int(h[3])<<8 | int(h[4])
	if l < xMinRecord || l > xMaxRecord {
		return 0, fmt.Errorf("vless encryption: bad record length %d", l)
	}
	return l, nil
}

func xEncodeLength(l int) []byte { return []byte{byte(l >> 8), byte(l)} }
func xDecodeLength(b []byte) int { return int(b[0])<<8 | int(b[1]) }

func newXCTR(key, iv []byte) cipher.Stream {
	k := make([]byte, 32)
	blake3.DeriveKey(k, "VLESS", key)
	block, _ := aes.NewCipher(k)
	return cipher.NewCTR(block, iv)
}

// xPublicBytes returns the public key bytes the XOR modes obscure.
func xPublicBytes(k Key) []byte {
	if k.X25519 != nil {
		return k.X25519.PublicKey().Bytes()
	}
	if k.MLKEM != nil {
		return k.MLKEM.EncapsulationKey().Bytes()
	}
	return nil
}

// xRecordConn is the encrypted record connection handed to the VLESS handler.
type xRecordConn struct {
	net.Conn
	useAES bool
	key    []byte
	w, r   *xAEAD
	rbuf   []byte
}

func (c *xRecordConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > xMaxPayload {
			n = xMaxPayload
		}
		rec := make([]byte, xHeaderLen+n+xTagLen)
		xEncodeHeader(rec, n+xTagLen)
		last := bytes.Equal(c.w.nonce[:], xMaxNonce)
		rec = c.w.Seal(rec[:xHeaderLen], nil, p[:n], rec[:xHeaderLen])
		if last {
			c.w = newXAEAD(rec[:xHeaderLen+n+xTagLen], c.key, c.useAES)
		}
		if _, err := c.Conn.Write(rec); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *xRecordConn) Read(p []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	var hdr [xHeaderLen]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}
	l, err := xDecodeHeader(hdr[:])
	if err != nil {
		return 0, err
	}
	payload := make([]byte, l)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}
	last := bytes.Equal(c.r.nonce[:], xMaxNonce)
	plain, err := c.r.open(nil, payload, hdr[:])
	if last {
		c.r = newXAEAD(append(hdr[:], payload...), c.key, c.useAES)
	}
	if err != nil {
		return 0, err
	}
	n := copy(p, plain)
	if n < len(plain) {
		c.rbuf = plain[n:]
	}
	return n, nil
}

// handshakeXray is the 1-RTT server handshake. 0-RTT resumption is not
// implemented (clients fall back to a fresh handshake).
func (s *EncServer) handshakeXray(conn net.Conn) (net.Conn, error) {
	keys := s.dec.Keys
	if len(keys) == 0 {
		return nil, errors.New("vless encryption: no keys")
	}
	xorMode := uint32(s.dec.Appearance)

	relaysLen := 0
	for _, k := range keys {
		if k.X25519 != nil {
			relaysLen += 32 + 32
		} else {
			relaysLen += 1088 + 32
		}
	}
	relaysLen -= 32
	buf := make([]byte, 16+relaysLen)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	iv := buf[:16]
	relays := buf[16:]

	var nfsKey []byte
	var lastCTR cipher.Stream
	for j := range keys {
		k := keys[j]
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:32])
		}
		index := 32
		if k.MLKEM != nil {
			index = 1088
		}
		if xorMode > 0 {
			newXCTR(xPublicBytes(k), iv).XORKeyStream(relays, relays[:index])
		}
		switch {
		case k.X25519 != nil:
			pub, err := ecdh.X25519().NewPublicKey(relays[:32])
			if err != nil {
				return nil, ErrEncHelloKey
			}
			if pub.Bytes()[31] > 127 {
				return nil, errors.New("vless encryption: the highest bit of the peer X25519 key is not 0")
			}
			nfsKey, err = k.X25519.ECDH(pub)
			if err != nil {
				return nil, ErrEncHelloKey
			}
		case k.MLKEM != nil:
			var err error
			nfsKey, err = k.MLKEM.Decapsulate(relays[:1088])
			if err != nil {
				return nil, ErrEncHelloKey
			}
		}
		if j == len(keys)-1 {
			break
		}
		relays = relays[index:]
		lastCTR = newXCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays, relays[:32])
		want := blake3.Sum256(xPublicBytes(keys[j+1]))
		if !bytes.Equal(relays[:32], want[:]) {
			return nil, ErrEncOtherKeys
		}
		relays = relays[32:]
	}

	useAES := true
	nfsAEAD := newXAEAD(iv, nfsKey, useAES)
	encLen := make([]byte, 18)
	if _, err := io.ReadFull(conn, encLen); err != nil {
		return nil, err
	}
	plainLen, err := nfsAEAD.open(nil, encLen, nil)
	if err != nil {
		useAES = false
		nfsAEAD = newXAEAD(iv, nfsKey, useAES)
		plainLen, err = nfsAEAD.open(nil, encLen, nil)
		if err != nil {
			return nil, ErrEncMalformed
		}
	}
	length := xDecodeLength(plainLen)
	if length == 32 {
		return nil, errors.New("vless encryption: 0-RTT is not supported")
	}
	if length < 1184+32+16 {
		return nil, errors.New("vless encryption: too short length")
	}
	encPfs := make([]byte, length)
	if _, err := io.ReadFull(conn, encPfs); err != nil {
		return nil, err
	}
	pfsPlain, err := nfsAEAD.open(nil, encPfs, nil)
	if err != nil {
		return nil, ErrEncHelloAuth
	}
	ek, err := mlkem.NewEncapsulationKey768(pfsPlain[:1184])
	if err != nil {
		return nil, ErrEncHelloKey
	}
	mlkemKey, mlkemCT := ek.Encapsulate()
	peerX, err := ecdh.X25519().NewPublicKey(pfsPlain[1184 : 1184+32])
	if err != nil {
		return nil, ErrEncHelloKey
	}
	serverEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	xKey, err := serverEph.ECDH(peerX)
	if err != nil {
		return nil, ErrEncHelloKey
	}
	pfsKey := append(append([]byte{}, mlkemKey...), xKey...)
	pfsPub := append(append([]byte{}, mlkemCT...), serverEph.PublicKey().Bytes()...)
	united := append(append([]byte{}, pfsKey...), nfsKey...)

	wAEAD := newXAEAD(pfsPub, united, useAES)
	rAEAD := newXAEAD(pfsPlain[:1184+32], united, useAES)

	ticket := make([]byte, 16)
	if _, err := rand.Read(ticket); err != nil {
		return nil, err
	}
	if sec := s.ticketSeconds(); sec > 0 {
		copy(ticket[:2], xEncodeLength(sec))
	} else {
		copy(ticket[:2], xEncodeLength(0))
	}

	// Server hello. Padding is fixed at 40 bytes (18 header + 6 plaintext + tag).
	const paddingLength = 40
	serverHello := make([]byte, 1136+32+paddingLength)
	copy(serverHello, nfsAEAD.Seal(nil, xMaxNonce, pfsPub, nil))
	copy(serverHello[1136:], wAEAD.Seal(nil, nil, ticket, nil))
	padding := serverHello[1136+32:]
	copy(padding, wAEAD.Seal(nil, nil, xEncodeLength(paddingLength-18), nil))
	copy(padding[18:], wAEAD.Seal(nil, nil, padding[18:paddingLength-xTagLen], nil))
	if _, err := conn.Write(serverHello); err != nil {
		return nil, err
	}

	// Client padding: length record then payload.
	if _, err := io.ReadFull(conn, encLen); err != nil {
		return nil, err
	}
	padLenPlain, err := nfsAEAD.open(nil, encLen, nil)
	if err != nil {
		return nil, ErrEncMalformed
	}
	padLen := xDecodeLength(padLenPlain)
	encPad := make([]byte, padLen)
	if _, err := io.ReadFull(conn, encPad); err != nil {
		return nil, err
	}
	if _, err := nfsAEAD.open(nil, encPad, nil); err != nil {
		return nil, ErrEncMalformed
	}
	return &xRecordConn{Conn: conn, useAES: useAES, key: united, w: wAEAD, r: rAEAD}, nil
}
