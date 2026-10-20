package ctransport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// REALITY client. Evidence: REPORT.md §7.5, §17.6 and
// notes/rev-transport.md §3: the client derives an X25519 shared secret with
// the server's reality public key, runs HKDF-SHA256 with salt "REALITY",
// seals its proof into the 32-byte session id and shows the borrowed site's
// name in SNI. The public key comes from realitySettings.publicKey
// ("reality-opts.public-key must be the server's X25519 public key, 32 bytes
// in base64url"), the short id from realitySettings.shortId.
const (
	realitySalt = "REALITY"
	realityInfo = "REALITY"
	// realityProofLen mirrors transport's session-id plaintext: 4-byte
	// big-endian Unix time, 8-byte short id, 4 bytes of random padding.
	//
	// UNVERIFIED: reconstructed; see internal/transport/reality.go.
	realityProofLen = 16
)

func (t *Transport) realityClient(ctx context.Context, c net.Conn) (net.Conn, error) {
	pubStr := firstNonEmpty(
		t.Reality.Str("publicKey", "public-key", "public_key"),
		t.Settings.Str("reality_public_key", "realityPublicKey", "publicKey", "public-key"),
	)
	pubRaw, err := decodeRealityKey(pubStr)
	if err != nil {
		return nil, err
	}
	serverPub, err := ecdh.X25519().NewPublicKey(pubRaw)
	if err != nil {
		return nil, errors.New("reality-opts.public-key must be the server's X25519 public key, 32 bytes in base64url")
	}
	shortID, err := decodeShortID(firstNonEmpty(
		t.Reality.Str("shortId", "short-id", "short_id"),
		t.Settings.Str("reality_short_id", "realityShortID", "shortId", "short_id"),
	))
	if err != nil {
		return nil, err
	}
	sni := firstNonEmpty(t.Reality.Str("serverName", "server_name", "sni"), t.Settings.Str("serverName", "reality_server_name"), t.sni)
	if sni == "" {
		return nil, errors.New("REALITY needs sni: one of the server names (serverNames) the far end's REALITY is set up for")
	}

	fp := firstNonEmpty(
		t.Settings.Str("client-fingerprint", "client_fingerprint", "fingerprint"),
		t.Reality.Str("fingerprint", "client-fingerprint"),
		"chrome",
	)
	id, shuffle, err := helloID(fp)
	if err != nil {
		return nil, err
	}
	cfg := utls.Config{
		ServerName: sni,
		// REALITY has no certificate to switch off: the server shows the
		// borrowed site's certificate and the client accepts it by design.
		InsecureSkipVerify: true,
		NextProtos:         t.clientALPN(),
		MinVersion:         utls.VersionTLS13,
	}
	var uconn *utls.UConn
	if shuffle {
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
		if err != nil {
			return nil, err
		}
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
		// The proof rides on the X25519 key share, so make sure the hello has
		// exactly that share (notes/rev-transport.md §3.2 step ①).
		if ks := findKeyShare(&spec); ks != nil {
			ks.KeyShares = []utls.KeyShare{{Group: utls.X25519}}
		} else {
			spec.Extensions = append(spec.Extensions, &utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}})
		}
		uconn = utls.UClient(c, &cfg, utls.HelloCustom)
		if err := uconn.ApplyPreset(&spec); err != nil {
			return nil, err
		}
	} else {
		uconn = utls.UClient(c, &cfg, id)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("reality: could not build a ClientHello to carry the proof: %w", err)
	}
	priv := uconn.HandshakeState.State13.KeyShareKeys
	if priv == nil || priv.Ecdhe == nil || priv.Ecdhe.Curve() != ecdh.X25519() {
		return nil, errors.New("reality: the client hello carries no X25519 key share")
	}
	ss, err := priv.Ecdhe.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("reality: hkdf: %s", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ss, []byte(realitySalt), []byte(realityInfo)), key); err != nil {
		return nil, fmt.Errorf("reality: hkdf: %s", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("reality: hkdf: %s", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("reality: hkdf: %s", err)
	}
	proof := make([]byte, realityProofLen)
	binary.BigEndian.PutUint32(proof[0:4], uint32(time.Now().Unix()))
	copy(proof[4:12], shortID)
	if _, err := rand.Read(proof[12:16]); err != nil {
		return nil, err
	}
	random := uconn.HandshakeState.Hello.Random
	if len(random) < aead.NonceSize() {
		return nil, errors.New("reality: could not build a ClientHello to carry the proof")
	}
	nonce := random[:aead.NonceSize()]
	uconn.HandshakeState.Hello.SessionId = aead.Seal(nil, nonce, proof, nil)
	if err := uconn.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("reality: could not build a ClientHello to carry the proof: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("reality: the server answered as its cover site, not as a REALITY server: check public-key, short-id and servername against the server, and this machine's clock (a server refuses a hello stamped more than about two minutes off its own time; \"ntp\" corrects the clock the kernel uses): %w", err)
	}
	return uconn, nil
}

func findKeyShare(spec *utls.ClientHelloSpec) *utls.KeyShareExtension {
	for _, ext := range spec.Extensions {
		if ks, ok := ext.(*utls.KeyShareExtension); ok {
			return ks
		}
	}
	return nil
}

func decodeRealityKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("REALITY needs public_key: the server's public key, as `xray x25519` or `kaze x25519` prints it")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("the REALITY public_key is not a public key: it must be 32 bytes in base64 (43 characters), the server's public key and not its private one")
	}
	return raw, nil
}

// decodeShortID turns the "up to 16 hex digits" short id into the 8-byte
// big-endian field of the proof (the server stores short ids as uint64).
func decodeShortID(s string) ([]byte, error) {
	out := make([]byte, 8)
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	if len(s) > 16 {
		return nil, fmt.Errorf("the REALITY short_id %q must be up to 16 hex digits, one of the far end's shortIds", s)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the REALITY short_id %q must be up to 16 hex digits, one of the far end's shortIds", s)
	}
	copy(out[8-len(raw):], raw)
	return out, nil
}
