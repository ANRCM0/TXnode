package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	xreality "github.com/xtls/reality"
	"golang.org/x/crypto/hkdf"
)

// REALITY server. Evidence: REPORT.md §7.5 and notes/rev-transport.md §3.
//
// The sample keeps one *Reality built by NewReality (0xab6ba0) holding the
// X25519 private key, the short-id set (map[uint64], mapassign_fast64), the
// allowed server names, the borrowed site address, the replay cache and a
// self-signed ed25519 certificate; Wrap (0xab9780) calls authenticateAt
// (0xab8720) on the ClientHello and every refusal forwards the connection to
// the borrowed site instead of answering with an error page.

// FallbackLimit bounds how much traffic an unauthenticated client may push to
// the borrowed site before it is throttled.
type FallbackLimit struct {
	BytesPerSec      int64 `yaml:"bytes_per_sec"`
	BurstBytesPerSec int64 `yaml:"burst_bytes_per_sec"`
	AfterBytes       int64 `yaml:"after_bytes"`
}

// DefaultRealityTimeDiff is the window used when reality_max_time_diff is 0:
// 0x37e11d6000 ns = 240 s (notes/rev-transport.md §3.4).
const DefaultRealityTimeDiff = 240 * time.Second

// realityReplayMax is the per-generation replay cache limit, 0x20000 entries
// (notes/rev-transport.md §3.4, immediate 0xab962f).
const realityReplayMax = 0x20000

// realityHKDFInfo is the HKDF info string. The salt is the first 20 bytes of the
// client random (xtls/reality: hkdf.New(sha256, shared, random[:20], "REALITY")).
// (0xf5970d); the info pointer (0xfa1108) was located but its text was not
// decoded in the static pass.
//
// UNVERIFIED: the info label, the session-id plaintext layout and the
// AES-GCM nonce choice below are reconstructed so this implementation's
// client and server agree; they were not byte-compared against the sample.
const (
	realityHKDFInfo = "REALITY"
)

// RealityConfig is what NewReality accepts. The field names follow the node's
// call site (internal/node/apply.go) and the reality_* keys of REPORT.md
// §4.2/§3.5.
type RealityConfig struct {
	PrivateKey    string         // reality_private_key, base64url X25519 (43 chars)
	ShortIDs      []string       // reality_short_id, up to 16 hex digits each
	Dest          string         // reality_dest, host:port of the borrowed site
	ServerNames   []string       // SNI whitelist
	MaxTimeDiff   int            // seconds; -1 disables the clock check, 0 = 240 s
	Mirror        string         // reality_mirror
	FallbackLimit *FallbackLimit // reality_fallback_limit
	Logger        *slog.Logger
	// ProbeDest asks NewReality to dial Dest once at startup. The sample
	// probes the borrowed site when the node starts (REPORT.md §20.5); the
	// flag keeps tests and offline builds from reaching out.
	ProbeDest bool
	// Dial is the dialer used to reach Dest (fallback and probe). Nil means
	// net.Dialer with a short timeout.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Reality is the server-side REALITY state.
type Reality struct {
	priv      *ecdh.PrivateKey
	pub       []byte
	shortIDs  map[uint64]struct{}
	shortID8  map[[8]byte]bool
	dest      string
	serverNs  []string
	maxDiff   time.Duration // 0 = disabled
	cache     *replayCache
	cert      tls.Certificate
	tlsConfig *tls.Config
	ref       *xreality.Config
	log       *slog.Logger
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	probe     bool
}

// NewReality validates the configuration and builds the server state.
func NewReality(cfg RealityConfig) (*Reality, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	key, err := parseRealityPrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	ids := make(map[uint64]struct{}, len(cfg.ShortIDs))
	shortID8 := make(map[[8]byte]bool, len(cfg.ShortIDs))
	for _, s := range cfg.ShortIDs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if len(s) > 16 {
			return nil, fmt.Errorf("reality: short ID %q must be up to 16 hex characters", s)
		}
		if len(s)%2 != 0 {
			return nil, fmt.Errorf("reality_short_id %q must be up to 16 hex characters, an even number of them", s)
		}
		raw, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("reality: short ID %q must be up to 16 hex characters", s)
		}
		// The sample stores short ids as uint64 map keys (mapassign_fast64 in
		// NewReality): left-pad the decimal value to 8 bytes.
		var v uint64
		for _, b := range raw {
			v = v<<8 | uint64(b)
		}
		ids[v] = struct{}{}
		var eight [8]byte
		copy(eight[:], raw)
		shortID8[eight] = true
	}
	if cfg.Dest == "" {
		return nil, errors.New("reality: destination %q must be host:port")
	}
	if _, _, err := net.SplitHostPort(cfg.Dest); err != nil {
		return nil, fmt.Errorf("reality: destination %q must be host:port", cfg.Dest)
	}

	diff := DefaultRealityTimeDiff
	switch {
	case cfg.MaxTimeDiff < 0:
		diff = 0
	case cfg.MaxTimeDiff > 0:
		diff = time.Duration(cfg.MaxTimeDiff) * time.Second
	}

	r := &Reality{
		priv:     key,
		pub:      key.PublicKey().Bytes(),
		shortIDs: ids,
		shortID8: shortID8,
		dest:     cfg.Dest,
		serverNs: append([]string(nil), cfg.ServerNames...),
		maxDiff:  diff,
		cache:    newReplayCache(diff),
		log:      log,
		dial:     cfg.Dial,
		probe:    cfg.ProbeDest,
	}
	// The borrowed site answers h2 and http/1.1. REALITY's key exchange is
	// X25519 only, so the TLS stack must not answer with a HelloRetryRequest
	// for a hybrid group. The certificate is built per handshake from the
	// connection's AuthKey (see realCertificate).
	r.tlsConfig = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		NextProtos:       []string{"h2", "http/1.1"},
		CurvePreferences: []tls.CurveID{tls.X25519},
	}
	if r.dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		r.dial = d.DialContext
	}
	// The REALITY reference implementation owns the TLS handshake: it must
	// force Ed25519 CertificateVerify even when the client's ClientHello omits
	// that signature scheme (Chrome fingerprints do), which crypto/tls cannot
	// express. Our wrapper below keeps the same []byte-in/[]byte-out contract.
	names := make(map[string]bool, len(cfg.ServerNames))
	for _, n := range cfg.ServerNames {
		if n = strings.TrimSpace(n); n != "" {
			names[n] = true
		}
	}
	r.ref = &xreality.Config{
		DialContext:            r.dial,
		Type:                   "tcp",
		Dest:                   cfg.Dest,
		ServerNames:            names,
		PrivateKey:             key.Bytes(),
		ShortIds:               shortID8,
		MaxTimeDiff:            0,   // reference: 0 disables the clock check
		NextProtos:             nil, // Xray keeps this nil for REALITY
		SessionTicketsDisabled: true,
	}
	// Xray starts this learner once per listener; it records the post-handshake
	// record lengths for the ALPN/SNI pair so the reference handshake can finish.
	go xreality.DetectPostHandshakeRecordsLens(r.ref)
	if r.probe {
		go r.probeDest()
	}
	return r, nil
}

// PublicKey returns the X25519 public key (base64url) the clients need.
func (r *Reality) PublicKey() string {
	return base64.RawURLEncoding.EncodeToString(r.pub)
}

// Dest is the borrowed site address.
func (r *Reality) Dest() string { return r.dest }

// MaxTimeDiff is the configured clock window (0 when disabled).
func (r *Reality) MaxTimeDiff() time.Duration { return r.maxDiff }

func parseRealityPrivateKey(s string) (*ecdh.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("security=reality needs reality_private_key (make a pair with: kaze -reality-keypair; the public key goes to the clients)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("reality_private_key is not a REALITY private key (43 characters of base64url, as kaze -reality-keypair prints it)")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, errors.New("reality_private_key is not a REALITY private key (43 characters of base64url, as kaze -reality-keypair prints it)")
	}
	return key, nil
}

// realityListener wraps accepted connections with Reality.Wrap.
type realityListener struct {
	net.Listener
	r   *Reality
	log *slog.Logger
}

func (l *realityListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.r.Wrap(c), nil
}

// Wrap authenticates the ClientHello of c. On success the returned connection
// is a TLS 1.3 server stream whose record layer is driven by crypto/tls with
// the self-signed certificate; on any refusal the connection is forwarded to
// reality_dest, byte for byte, so a prober only sees the borrowed site.
//
// Evidence: (*Reality).Wrap 0xab9780 -> authenticateAt 0xab8720 ->
// (*Reality).forward 0xaba3e0; the three refusal paths are listed in
// REPORT.md §7.5 and notes/rev-transport.md §3.3.
func (r *Reality) Wrap(c net.Conn) net.Conn {
	rc := &realityConn{Conn: c, r: r}
	return rc
}

type realityConn struct {
	net.Conn
	r *Reality

	once sync.Once
	err  error

	// under is the stream used after the ClientHello was classified: either a
	// tls.Server over the replayed bytes, or the connection to the site.
	under net.Conn
}

func (c *realityConn) start() error {
	c.once.Do(func() {
		c.err = c.handshake()
	})
	return c.err
}

func (c *realityConn) handshake() error {
	// xtls/reality performs the whole exchange: parse the ClientHello, derive
	// AuthKey, validate the session id, terminate TLS 1.3 with the HMAC-signed
	// certificate, or mirror the client to the borrowed site when the hello does
	// not authenticate. It owns the raw connection from here on.
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	rc, err := xreality.Server(ctx, c.Conn, c.r.ref)
	if err != nil {
		c.r.log.Debug("REALITY: handshake refused", "err", err)
		return err
	}
	c.under = rc
	return nil
}

// ConnectionState exposes the TLS state of the accepted stream.
func (c *realityConn) ConnectionState() tls.ConnectionState {
	_ = c.start()
	if st, ok := c.under.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return st.ConnectionState()
	}
	return tls.ConnectionState{}
}

// Handshake completes the handshake if it has not run yet.
func (c *realityConn) Handshake() error {
	startErr := c.start()
	if startErr != nil {
		return startErr
	}
	if h, ok := c.under.(interface{ Handshake() error }); ok {
		return h.Handshake()
	}
	return nil
}

func (c *realityConn) Read(p []byte) (int, error) {
	if err := c.start(); err != nil {
		return 0, err
	}
	return c.under.Read(p)
}

func (c *realityConn) Write(p []byte) (int, error) {
	if err := c.start(); err != nil {
		return 0, err
	}
	return c.under.Write(p)
}

func (c *realityConn) Close() error {
	if c.under != nil {
		_ = c.under.Close()
	}
	return c.Conn.Close()
}

func (c *realityConn) CloseWrite() error {
	if c.under != nil {
		if cw, ok := c.under.(interface{ CloseWrite() error }); ok {
			return cw.CloseWrite()
		}
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// realityProofLen is the decrypted session-id length: 4-byte big-endian Unix
// time + 8-byte short id + 4 bytes of random padding.
//
// UNVERIFIED: the sample checks the decrypted length against 0x14 (20) at
// 0xab8922 while a 32-byte session id leaves 16 bytes after the GCM tag; the
// layout above is the self-consistent reconstruction (both ends are kaze).
const realityProofLen = 16

func hkdfKey(shared, salt []byte) ([]byte, error) {
	out := make([]byte, 32)
	k := hkdf.New(sha256.New, shared, salt, []byte(realityHKDFInfo))
	if _, err := io.ReadFull(k, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Reality) serverNameAllowed(name string) bool {
	if len(r.serverNs) == 0 {
		return true
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, s := range r.serverNs {
		if strings.ToLower(strings.TrimSuffix(s, ".")) == name {
			return true
		}
	}
	return false
}

func (r *Reality) shortIDAllowed(b []byte) bool {
	if len(r.shortIDs) == 0 {
		return true
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	_, ok := r.shortIDs[v]
	return ok
}

func remoteIP(c net.Conn) string {
	if a := c.RemoteAddr(); a != nil {
		if h, _, err := net.SplitHostPort(a.String()); err == nil {
			return h
		}
		return a.String()
	}
	return ""
}

// probeDest dials the borrowed site once and reports the ServerHello it
// answers with. Evidence: the startup probe observed in REPORT.md §20.5
// ("REALITY: www.example.com:443 ... answers a browser with suite 0x1301 ...")
// and the "suite %#04x, group %#04x, extensions %s, flight %v, then %v, in %s"
// log format in the string table.
func (r *Reality) probeDest() {
	ctx, cancel := contextWithTimeout(10 * time.Second)
	defer cancel()
	c, err := r.dial(ctx, "tcp", r.dest)
	if err != nil {
		r.log.Warn("REALITY: the borrowed site could not be asked for a handshake", "dest", r.dest, "err", err)
		return
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		r.log.Warn("the handshake with the site failed (%w)", "dest", r.dest, "err", err)
		return
	}
	st := tc.ConnectionState()
	r.log.Info("REALITY: the borrowed site answers a browser",
		"dest", r.dest, "version", tls.VersionName(st.Version), "suite", fmt.Sprintf("%#04x", st.CipherSuite),
		"alpn", st.NegotiatedProtocol)
}

// replayCache is the generational replay map of notes/rev-transport.md §3.4:
// a current generation plus the previous one, 0x20000 entries each, rotated
// when the clock leaves the window.
type replayCache struct {
	mu   sync.Mutex
	cur  map[[32]byte]struct{}
	prev map[[32]byte]struct{}
	t0   time.Time
	win  time.Duration
}

func newReplayCache(win time.Duration) *replayCache {
	if win <= 0 {
		win = DefaultRealityTimeDiff
	}
	return &replayCache{cur: make(map[[32]byte]struct{}), t0: time.Now(), win: win}
}

// add returns 0 (new), 1 (seen before) or 2 (generation full).
func (rc *replayCache) add(now time.Time, ip string, key [32]byte) int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	delta := now.Sub(rc.t0)
	switch {
	case rc.cur == nil:
		rc.prev, rc.cur, rc.t0 = nil, make(map[[32]byte]struct{}), now
	case delta < rc.win && delta >= -rc.win:
		// still in the current generation
	case delta >= 2*rc.win:
		rc.prev, rc.cur, rc.t0 = nil, make(map[[32]byte]struct{}), now
	default:
		rc.prev, rc.cur, rc.t0 = rc.cur, make(map[[32]byte]struct{}), now
	}
	if _, ok := rc.cur[key]; ok {
		return 1
	}
	if _, ok := rc.prev[key]; ok {
		return 1
	}
	if len(rc.cur) >= realityReplayMax {
		return 2
	}
	rc.cur[key] = struct{}{}
	_ = ip
	return 0
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
