package mieru

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// Handler field order mirrors the recovered struct (notes/rev-proto-udp.md §3.2):
// +0x00 Idle, +0x08 Options{Pattern, HintRequired}, +0x18 users, +0x20 scans,
// +0x50 kmu, +0x58 keys, +0x60 keysFor, +0x68 rmu, +0x70 seen, +0x78 next.
type Handler struct {
	// Idle is the session idle timeout.
	Idle time.Duration
	// opts is Options (Pattern + HintRequired in the binary).
	opts Options
	log  *slog.Logger

	users map[string]core.User
	scans scanGate

	kmu     sync.RWMutex
	keys    []*keyEntry
	keysFor map[string]*keyEntry

	rmu  sync.Mutex
	seen map[uint64]time.Time

	udpMu sync.Mutex
	peers map[string]*udpPeer

	next uint32
}

// keyEntry is one element of h->keys (element size 0x38 in the binary): the
// per-user key plus its precomputed 16-byte hint.
type keyEntry struct {
	name     string
	user     core.User
	password []byte
	key      [keySize]byte
	hint     []byte
	added    time.Time
}

// Options is the contract's option set for mieru.
type Options struct {
	Users          []core.User
	Transport      string
	TrafficPattern string
	HintRequired   bool
	Logger         *slog.Logger

	// Iterations overrides the PBKDF2 work factor.
	Iterations int
	// IdleTimeout overrides the stream idle timeout.
	IdleTimeout time.Duration
	// ScanRate/ScanBurst override the scanGate budget.
	ScanRate, ScanBurst float64
	// Window overrides the accepted timestamp skew.
	Window time.Duration
}

// ErrNotMieru is returned for connections that carry no identifiable segment.
var ErrNotMieru = errors.New("mieru: not a mieru client")

// ErrScanThrottled is returned when the unhinted path is out of budget.
var ErrScanThrottled = errors.New("mieru: scan budget exhausted")

const (
	// defaultIdle is the stream idle timeout when Options.IdleTimeout is zero.
	defaultIdle = 5 * time.Minute
	// handshakeTimeout bounds the first segment read.
	handshakeTimeout = 10 * time.Second
	// replayWindow is how long (ts, seq) pairs are remembered.
	replayWindow = 2 * time.Minute
)

// NewHandler validates the users and derives their keys.
func NewHandler(o Options) (*Handler, error) {
	if len(o.Users) == 0 {
		return nil, errors.New("mieru: no users configured")
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &Handler{
		Idle:    o.IdleTimeout,
		opts:    o,
		log:     log,
		users:   make(map[string]core.User, len(o.Users)),
		keysFor: make(map[string]*keyEntry, len(o.Users)),
		seen:    make(map[uint64]time.Time),
		scans:   newScanGate(o.ScanRate, o.ScanBurst),
	}
	if h.Idle <= 0 {
		h.Idle = defaultIdle
	}
	for _, u := range o.Users {
		name, password := splitUser(u.UUID)
		if name == "" {
			continue
		}
		h.users[name] = u
		key := DeriveKeyIter(name, password, o.Iterations)
		hint, err := hintFromKey(key[:])
		if err != nil {
			return nil, err
		}
		entry := &keyEntry{
			name:     name,
			user:     u,
			password: password,
			key:      key,
			hint:     hint,
			added:    time.Now(),
		}
		h.keys = append(h.keys, entry)
		h.keysFor[name] = entry
	}
	if len(h.keys) == 0 {
		return nil, errors.New("mieru: no usable users")
	}
	return h, nil
}

// splitUser parses "user:password"; a value without ':' is a user with an empty
// password. UNVERIFIED: the panel's handed-down shape was not decoded for mieru.
func splitUser(v string) (string, []byte) {
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		return v[:i], []byte(v[i+1:])
	}
	return v, nil
}

// trimKeys drops keys older than their TTL. Evidence: trimKeys @0x7d7b00 is
// called at the top of identifyWhere.
func (h *Handler) trimKeys(now time.Time) {
	h.kmu.Lock()
	defer h.kmu.Unlock()
	if len(h.keys) == 0 {
		return
	}
	alive := h.keys[:0]
	for _, k := range h.keys {
		if now.Sub(k.added) <= 24*time.Hour {
			alive = append(alive, k)
		}
	}
	h.keys = alive
}

// identify resolves a segment to a user.
//
// The control flow is the binary's (*Handler).identify @0x7d8160 exactly:
// hinted identification first; if it failed and the handler does not require
// hints, give up; otherwise a scan is attempted only when the gate allows it.
func (h *Handler) identify(seg []byte) (*segmentCipher, *parsedSegment, *keyEntry, error) {
	h.trimKeys(time.Now())
	if c, p, e, err := h.identifyHinted(seg); err == nil {
		return c, p, e, nil
	}
	if !h.opts.HintRequired {
		return nil, nil, nil, errBadHint
	}
	if !h.scans.allow() {
		return nil, nil, nil, ErrScanThrottled
	}
	return h.identifyUnhinted(seg)
}

// identifyHinted tries only the key whose precomputed hint matches.
func (h *Handler) identifyHinted(seg []byte) (*segmentCipher, *parsedSegment, *keyEntry, error) {
	if len(seg) < hintLen+segmentHeaderLen {
		return nil, nil, nil, errSegmentMalformed
	}
	hint := seg[:hintLen]
	h.kmu.RLock()
	entries := append([]*keyEntry(nil), h.keys...)
	h.kmu.RUnlock()
	for _, e := range entries {
		if !keyMatchesHint(e.key[:], hint) {
			continue
		}
		c, err := newSegmentCipher(e.key)
		if err != nil {
			continue
		}
		p, err := c.open(seg)
		if err != nil {
			continue
		}
		return c, p, e, nil
	}
	return nil, nil, nil, errBadHint
}

// identifyUnhinted tries every key in order.
func (h *Handler) identifyUnhinted(seg []byte) (*segmentCipher, *parsedSegment, *keyEntry, error) {
	h.kmu.RLock()
	entries := append([]*keyEntry(nil), h.keys...)
	h.kmu.RUnlock()
	for _, e := range entries {
		c, err := newSegmentCipher(e.key)
		if err != nil {
			continue
		}
		p, err := c.open(seg)
		if err != nil {
			continue
		}
		return c, p, e, nil
	}
	return nil, nil, nil, errBadHint
}

// checkReplay records (ts, seq) and rejects duplicates inside the window.
// UNVERIFIED: the sample's replay guard is not decoded; anti-replay is part of
// the segment design (parsePacket compares timestamps).
func (h *Handler) checkReplay(ts, seq uint32) bool {
	key := uint64(ts)<<32 | uint64(seq)
	now := time.Now()
	h.rmu.Lock()
	defer h.rmu.Unlock()
	if _, ok := h.seen[key]; ok {
		return false
	}
	h.seen[key] = now
	for k, t := range h.seen {
		if now.Sub(t) > replayWindow {
			delete(h.seen, k)
		}
	}
	return true
}

// Handle parses the opening segment and returns the session.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	br := bufio.NewReaderSize(conn, 4096)
	if u, aead, plain, nonce, ok := h.v2Try(br); ok {
		return h.v2Handshake(conn, br, u, aead, plain, nonce)
	}
	conn = &bufConn{Conn: conn, r: br}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	}
	seg, err := readSegment(conn)
	if err != nil {
		return nil, h.stranger(conn, err)
	}
	cipher, parsed, entry, err := h.identify(seg)
	if err != nil {
		return nil, h.stranger(conn, err)
	}
	if !withinWindow(parsed.ts) {
		return nil, h.stranger(conn, errors.New("mieru: segment outside the time window"))
	}
	if !h.checkReplay(parsed.ts, parsed.seq) {
		return nil, h.stranger(conn, errors.New("mieru: replayed segment"))
	}
	if parsed.code != segOpen {
		return nil, h.stranger(conn, fmt.Errorf("mieru: first segment code %d", parsed.code))
	}
	dest, _, err := decodeAddr(parsed.payload)
	if err != nil {
		return nil, h.stranger(conn, err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	sc := &streamConn{
		h:      h,
		Conn:   conn,
		cipher: cipher,
		user:   entry.user,
		seq:    parsed.seq + 1,
	}
	return &core.Session{UserID: entry.user.ID, Dest: dest, Conn: sc}, nil
}

// stranger wraps an error as core.Stranger so the node answers like a web
// server instead of leaking a protocol error.
func (h *Handler) stranger(conn net.Conn, err error) error {
	h.log.Debug("mieru: rejecting connection", "error", err, "remote", conn.RemoteAddr().String())
	return &core.Stranger{Conn: conn, Err: err, Quiet: true}
}

// ServeConn serves a connection the caller already accepted. Evidence:
// (*Handler).ServeConn @0x7d8e80. It is a thin wrapper over Handle plus the
// default relay, kept so the binary's entry point has a counterpart.
func (h *Handler) ServeConn(conn net.Conn) error {
	sess, err := h.Handle(context.Background(), conn)
	if err != nil {
		return err
	}
	defer sess.Conn.Close()
	dest, err := net.DialTimeout("tcp", sess.Dest.String(), 10*time.Second)
	if err != nil {
		return err
	}
	defer dest.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = copyAll(dest, sess.Conn); done <- struct{}{} }()
	go func() { _, _ = copyAll(sess.Conn, dest); done <- struct{}{} }()
	<-done
	return nil
}

// copyAll is io.Copy, local so the relay helper does not pull io into the file's
// imports twice.
func copyAll(dst, src net.Conn) (int64, error) { return io.Copy(dst, src) }
