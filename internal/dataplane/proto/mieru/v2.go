package mieru

// mieru protocol v2 (official client) — TCP, single session, XChaCha20-Poly1305
// with implicit nonces. Derived from docs/protocol.md (mieru 3.38):
//
//	key: sha256(password || 0x00 || username) -> PBKDF2-64(sha256, salt =
//	     sha256(be64(2-minute-rounded unix time)), 32 bytes)
//	wire: [nonce 24][meta 32 + tag][padding1][payload + tag][padding2]
//	meta: sessionStruct (open/close) or dataAckStruct (data/ack)
//
// The SOCKS5 CONNECT request travels as the openSessionRequest payload and the
// SOCKS5 reply travels as the first dataServerToClient segment. The reply is
// emitted from core.HandshakeReply after the relay dialed the destination, so a
// failed dial reaches the client instead of a stalled session.

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// bufConn replays bytes peeked from a buffered reader.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

const (
	v2MetaLen      = 32
	v2NonceLen     = 24
	v2TagLen       = 16
	v2ProtoOpenReq = 2
	v2ProtoOpenRsp = 3
	v2ProtoCloseRq = 4
	v2ProtoCloseRs = 5
	v2ProtoDataC2S = 6
	v2ProtoDataS2C = 7
	v2ProtoAckC2S  = 8
	v2ProtoAckS2C  = 9

	// v2MaxPayload is the published per-fragment maximum (32768). A TCP session
	// fragments at the negotiated MTU instead so a client never has to reassemble
	// beyond what it advertised.
	v2MaxPayload = 32768
	// v2DefaultMTU is the client default (1400); the server uses it when the
	// panel does not hand an explicit MTU down.
	v2DefaultMTU = 1400
	// v2MaxSessionPayload is the session-metadata payload cap (1024).
	v2MaxSessionPayload = 1024
	// v2Heartbeat is the idle interval after which the server sends a data
	// segment with no payload; the official client does the same and uses it for
	// liveness. It also bounds how long a closed peer stays cached.
	v2Heartbeat = 20 * time.Second
)

func v2HashedPassword(username string, password []byte) [32]byte {
	p := make([]byte, 0, len(password)+1+len(username))
	p = append(p, password...)
	p = append(p, 0)
	p = append(p, username...)
	return sha256.Sum256(p)
}

func v2TimeSalt(sec int64) [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(sec))
	return sha256.Sum256(b[:])
}

func v2Derive(hashed []byte, salt []byte) []byte {
	return pbkdf2.Key(hashed, salt, 64, 32, sha256.New)
}

func v2NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

func v2HintNonce(nonce []byte, username string) {
	var input [256 + 16]byte
	n := copy(input[:], username)
	n += copy(input[n:], nonce[:16])
	sum := sha256.Sum256(input[:n])
	copy(nonce[len(nonce)-4:], sum[:4])
}

func v2IncreaseNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// v2Key is the cipher material recovered from the opening segment. salt is the
// time-salt window that actually decrypted it; the server cipher must reuse the
// same window even when the client clock is more than one window away.
type v2Key struct {
	user    *keyEntry
	aead    cipher.AEAD
	key     []byte
	salt    [32]byte
	saltSec int64
}

// v2Try authenticates the first segment from a peeked buffer. It returns
// (nil, false) when the bytes are not mieru v2 for any configured user.
func (h *Handler) v2Try(br *bufio.Reader) (*v2Key, []byte, []byte, bool) {
	head, err := br.Peek(v2NonceLen + v2MetaLen + v2TagLen)
	if err != nil {
		return nil, nil, nil, false
	}
	nonce := head[:v2NonceLen]
	meta := head[v2NonceLen:]

	rounded := time.Now().Round(2 * time.Minute).Unix()
	h.kmu.RLock()
	users := append([]*keyEntry(nil), h.keys...)
	h.kmu.RUnlock()
	for _, u := range users {
		hashed := v2HashedPassword(u.name, u.password)
		for _, delta := range []int64{-120, 0, 120} {
			salt := v2TimeSalt(rounded + delta)
			key := v2Derive(hashed[:], salt[:])
			cand, err := v2NewAEAD(key)
			if err != nil {
				continue
			}
			p, err := cand.Open(nil, append([]byte(nil), nonce...), meta, nil)
			if err != nil || len(p) != v2MetaLen || p[0] != v2ProtoOpenReq {
				continue
			}
			return &v2Key{user: u, aead: cand, key: key, salt: salt, saltSec: rounded + delta}, p, append([]byte(nil), nonce...), true
		}
	}
	return nil, nil, nil, false
}

// v2Handshake completes the session open on an authenticated first segment.
func (h *Handler) v2Handshake(conn net.Conn, br *bufio.Reader, kk *v2Key, plain, nonce []byte) (*core.Session, error) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	_, _ = br.Discard(v2NonceLen + v2MetaLen + v2TagLen)

	curNonce := append([]byte(nil), nonce...)
	sessionID := binary.BigEndian.Uint32(plain[6:10])
	seq := binary.BigEndian.Uint32(plain[10:14])
	status := plain[14]
	payloadLen := int(binary.BigEndian.Uint16(plain[15:17]))
	suffixLen := int(plain[17])
	if status != 0 || sessionID == 0 {
		return nil, errors.New("mieru: bad open request metadata")
	}
	if payloadLen > v2MaxSessionPayload || suffixLen > v2MaxSessionPayload {
		return nil, errors.New("mieru: bad open payload")
	}

	// payload follows the metadata; suffix padding after it.
	var req []byte
	if payloadLen > 0 {
		body := make([]byte, payloadLen+v2TagLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, err
		}
		v2IncreaseNonce(curNonce)
		p, err := kk.aead.Open(nil, curNonce, body, nil)
		if err != nil {
			return nil, errors.New("mieru: open payload authentication failed")
		}
		req = p
		v2IncreaseNonce(curNonce)
	}
	if suffixLen > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(suffixLen)); err != nil {
			return nil, err
		}
	}

	var dest socks.Addr
	if len(req) > 0 {
		d, err := parseSocks5Request(req)
		if err != nil {
			return nil, err
		}
		dest = d
	} else {
		// No piggybacked request: the client sends it as the first data segment.
		dest = socks.Addr{}
	}

	h.log.Debug("mieru v2 open", "user", kk.user.name, "session", sessionID, "dest", dest.String())

	// Server cipher: a fresh nonce and the same derived key as the client. The
	// nonce carries the username hint so the client can skip user discovery.
	srvNonce := make([]byte, v2NonceLen)
	if _, err := rand.Read(srvNonce); err != nil {
		return nil, err
	}
	v2HintNonce(srvNonce, kk.user.name)

	// openSessionResponse: no payload, server sequence starts at 0.
	rspMeta := v2SessionMeta(v2ProtoOpenRsp, sessionID, 0, 0, 0, 0)
	sealed := kk.aead.Seal(nil, srvNonce, rspMeta, nil)
	if _, err := conn.Write(append(append([]byte(nil), srvNonce...), sealed...)); err != nil {
		return nil, err
	}
	v2IncreaseNonce(srvNonce)

	vc := &v2Conn{
		Conn:       conn,
		conn:       conn,
		rr:         br,
		frames:     make(chan []byte, 64),
		log:        h.log,
		r:          kk.aead,
		w:          kk.aead,
		rn:         curNonce,
		wn:         srvNonce,
		sessionID:  sessionID,
		wseq:       1, // 0 was the openSessionResponse
		clientSeq:  seq + 1,
		clientNext: seq + 1,
		mtu:        h.v2MTU(),
		lastTX:     time.Now(),
		lastRX:     time.Now(),
	}
	go vc.readLoop()
	go vc.heartbeatLoop(h.v2HeartbeatInterval())
	return &core.Session{UserID: kk.user.user.ID, Dest: dest, Conn: vc}, nil
}

// v2HeartbeatInterval is the idle heartbeat (Options.Heartbeat, default 20s).
func (h *Handler) v2HeartbeatInterval() time.Duration {
	if h.v2Heartbeat > 0 {
		return h.v2Heartbeat
	}
	return v2Heartbeat
}

// v2MTU is the fragment payload size: the configured MTU minus the segment
// overhead, clamped to the published per-fragment maximum.
func (h *Handler) v2MTU() int {
	mtu := h.v2Mtu
	if mtu <= 0 {
		mtu = v2DefaultMTU
	}
	// Encrypted metadata (32+16) plus payload tag (16).
	if n := mtu - v2MetaLen - v2TagLen - v2TagLen; n >= 256 {
		if n > v2MaxPayload {
			return v2MaxPayload
		}
		return n
	}
	return v2DefaultMTU - v2MetaLen - 2*v2TagLen
}

// v2SessionMeta builds session metadata (baseStruct 1 + unused 1 + timestamp 4
// + session 4 + seq 4 + status 1 + payload 2 + suffix 1 + unused 14).
func v2SessionMeta(proto byte, sessionID, seq uint32, status byte, payloadLen, suffixLen int) []byte {
	b := make([]byte, v2MetaLen)
	b[0] = proto
	binary.BigEndian.PutUint32(b[2:], uint32(time.Now().Unix()/60))
	binary.BigEndian.PutUint32(b[6:], sessionID)
	binary.BigEndian.PutUint32(b[10:], seq)
	b[14] = status
	binary.BigEndian.PutUint16(b[15:], uint16(payloadLen))
	b[17] = byte(suffixLen)
	return b
}

// v2DataMeta builds data metadata (baseStruct 1 + unused 1 + timestamp 4 +
// session 4 + seq 4 + unack 4 + window 2 + fragment 1 + prefix 1 + payload 2 +
// suffix 1 + unused 7).
func v2DataMeta(proto byte, sessionID, seq, unack uint32, window uint16, fragment byte, payloadLen, prefixLen, suffixLen int) []byte {
	b := make([]byte, v2MetaLen)
	b[0] = proto
	binary.BigEndian.PutUint32(b[2:], uint32(time.Now().Unix()/60))
	binary.BigEndian.PutUint32(b[6:], sessionID)
	binary.BigEndian.PutUint32(b[10:], seq)
	binary.BigEndian.PutUint32(b[14:], unack)
	binary.BigEndian.PutUint16(b[18:], window)
	b[20] = fragment
	b[21] = byte(prefixLen)
	binary.BigEndian.PutUint16(b[22:], uint16(payloadLen))
	b[24] = byte(suffixLen)
	return b
}

// parseSocks5Request decodes the CONNECT payload: VER CMD RSV ATYP ADDR PORT.
func parseSocks5Request(b []byte) (socks.Addr, error) {
	if len(b) < 7 || b[0] != 5 || b[1] != 1 {
		return socks.Addr{}, errors.New("mieru: bad socks5 request")
	}
	switch b[3] {
	case 1:
		return socks.Addr{Host: net.IP(b[4:8]).String(), Port: binary.BigEndian.Uint16(b[8:10])}, nil
	case 4:
		if len(b) < 22 {
			return socks.Addr{}, errors.New("mieru: short socks5 ipv6")
		}
		return socks.Addr{Host: net.IP(b[4:20]).String(), Port: binary.BigEndian.Uint16(b[20:22])}, nil
	case 3:
		if len(b) < 5 {
			return socks.Addr{}, errors.New("mieru: short socks5 fqdn")
		}
		l := int(b[4])
		if len(b) < 5+l+2 {
			return socks.Addr{}, errors.New("mieru: short socks5 fqdn")
		}
		return socks.Addr{Host: string(b[5 : 5+l]), Port: binary.BigEndian.Uint16(b[5+l:])}, nil
	}
	return socks.Addr{}, errors.New("mieru: bad socks5 atyp")
}

// v2Socks5Reply renders the SOCKS5 CONNECT reply. BND.ADDR is the dialed local
// address when it is IPv4, else 0.0.0.0; the official client ignores it.
func v2Socks5Reply(code byte, local net.Addr) []byte {
	reply := []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
	if code != 0 {
		return reply
	}
	if ta, ok := local.(*net.TCPAddr); ok && ta != nil {
		if ip4 := ta.IP.To4(); ip4 != nil {
			copy(reply[4:8], ip4)
			binary.BigEndian.PutUint16(reply[8:10], uint16(ta.Port))
		}
	}
	return reply
}

// v2Socks5Code maps a dial error to a SOCKS5 reply code.
func v2Socks5Code(err error) byte {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return 4 // host unreachable
	}
	return 5 // connection refused
}

// v2Conn is the record connection handed to the relay. It is both the session
// net.Conn and the inner SOCKS5 responder.
type v2Conn struct {
	net.Conn
	conn      net.Conn
	rr        io.Reader
	r, w      cipher.AEAD
	rn, wn    []byte
	sessionID uint32
	log       *slog.Logger

	mtu int

	wmu      sync.Mutex
	wseq     uint32 // next server data sequence number
	fragment byte
	closed   bool

	clientSeq  uint32 // next client sequence number the server expects
	clientNext uint32 // highest client sequence + 1 (ACK value)

	lastTX, lastRX time.Time

	frames   chan []byte
	closeOne sync.Once
}

// HandshakeSucceeded answers the inner SOCKS5 CONNECT after the relay dialed the
// destination.
func (c *v2Conn) HandshakeSucceeded(local net.Addr) error {
	return c.writeData(v2Socks5Reply(0, local))
}

// HandshakeFailed reports the dial failure to the inner SOCKS5 client.
func (c *v2Conn) HandshakeFailed(err error) error {
	return c.writeData(v2Socks5Reply(v2Socks5Code(err), nil))
}

// writeData sends one application buffer as MTU-bounded data segments.
func (c *v2Conn) writeData(p []byte) error {
	c.log.Debug("mieru v2 write", "session", c.sessionID, "len", len(p))
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	for len(p) > 0 {
		n := len(p)
		if n > c.mtu {
			n = c.mtu
		}
		if err := c.writeSegmentLocked(p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// writeSegmentLocked seals one dataServerToClient segment. Caller holds wmu.
func (c *v2Conn) writeSegmentLocked(payload []byte) error {
	meta := v2DataMeta(v2ProtoDataS2C, c.sessionID, c.wseq, c.clientNext, 65535, c.fragment, len(payload), 0, 0)
	sealedMeta := c.w.Seal(nil, c.wn, meta, nil)
	v2IncreaseNonce(c.wn)
	sealedPayload := c.w.Seal(nil, c.wn, payload, nil)
	v2IncreaseNonce(c.wn)
	out := make([]byte, 0, len(sealedMeta)+len(sealedPayload))
	out = append(out, sealedMeta...)
	out = append(out, sealedPayload...)
	if _, err := c.conn.Write(out); err != nil {
		return err
	}
	c.wseq++
	c.fragment++
	c.lastTX = time.Now()
	return nil
}

// writeAckLocked replies to one client ACK with the current receive cursor.
// Caller holds wmu.
func (c *v2Conn) writeAckLocked() error {
	meta := v2DataMeta(v2ProtoAckS2C, c.sessionID, c.wseq-1, c.clientNext, 65535, 0, 0, 0, 0)
	sealed := c.w.Seal(nil, c.wn, meta, nil)
	v2IncreaseNonce(c.wn)
	if _, err := c.conn.Write(sealed); err != nil {
		return err
	}
	c.lastTX = time.Now()
	return nil
}

// heartbeatLoop sends an empty data segment after an idle interval. The
// official peer uses the same shape for liveness and closes idle sessions.
func (c *v2Conn) heartbeatLoop(interval time.Duration) {
	t := time.NewTicker(interval / 2)
	defer t.Stop()
	for range t.C {
		c.wmu.Lock()
		if c.closed {
			c.wmu.Unlock()
			return
		}
		if time.Since(c.lastTX) >= interval {
			if err := c.writeSegmentLocked(nil); err != nil {
				c.wmu.Unlock()
				return
			}
		}
		c.wmu.Unlock()
	}
}

func (c *v2Conn) Read(p []byte) (int, error) {
	for {
		select {
		case b, ok := <-c.frames:
			if !ok {
				return 0, io.EOF
			}
			c.log.Debug("mieru v2 read", "session", c.sessionID, "len", len(b))
			n := copy(p, b)
			if n < len(b) {
				// Keep the remainder.
				select {
				case c.frames <- b[n:]:
				default:
					return n, io.ErrShortBuffer
				}
			}
			return n, nil
		}
	}
}

func (c *v2Conn) Write(p []byte) (int, error) {
	if err := c.writeData(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// readLoop decrypts client segments and feeds application data.
func (c *v2Conn) readLoop() {
	defer close(c.frames)
	for {
		meta := make([]byte, v2MetaLen+v2TagLen)
		if _, err := io.ReadFull(c.rr, meta); err != nil {
			c.log.Debug("mieru v2 segment read", "err", err)
			return
		}
		c.lastRX = time.Now()
		plain, err := c.r.Open(nil, c.rn, meta, nil)
		if err != nil {
			c.log.Debug("mieru v2 meta decrypt failed", "err", err)
			return
		}
		v2IncreaseNonce(c.rn)
		proto := plain[0]
		seq := binary.BigEndian.Uint32(plain[10:14])
		if sid := binary.BigEndian.Uint32(plain[6:10]); sid != c.sessionID {
			c.log.Debug("mieru v2 session mismatch", "want", c.sessionID, "got", sid)
			return
		}
		var prefixLen, payloadLen, suffixLen int
		c.log.Debug("mieru v2 segment", "type", proto, "seq", seq)
		switch proto {
		case v2ProtoDataC2S:
			prefixLen = int(plain[21])
			payloadLen = int(binary.BigEndian.Uint16(plain[22:24]))
			suffixLen = int(plain[24])
		case v2ProtoAckC2S:
			// No payload or padding; answer with our cursor.
			c.log.Debug("mieru v2 client ack", "session", c.sessionID, "seq", seq,
				"unack", binary.BigEndian.Uint32(plain[14:18]),
				"window", binary.BigEndian.Uint16(plain[18:20]))
			c.wmu.Lock()
			err := c.writeAckLocked()
			c.wmu.Unlock()
			if err != nil {
				c.log.Debug("mieru v2 ack reply failed", "err", err)
				return
			}
			continue
		case v2ProtoCloseRq:
			c.log.Debug("mieru v2 close request", "session", c.sessionID)
			c.closeOne.Do(func() { _ = c.conn.Close() })
			return
		default:
			c.log.Debug("mieru v2 unexpected protocol", "type", proto)
			return
		}

		if prefixLen > 0 {
			if _, err := io.CopyN(io.Discard, c.rr, int64(prefixLen)); err != nil {
				return
			}
		}
		var data []byte
		if payloadLen > 0 {
			body := make([]byte, payloadLen+v2TagLen)
			if _, err := io.ReadFull(c.rr, body); err != nil {
				return
			}
			data, err = c.r.Open(nil, c.rn, body, nil)
			if err != nil {
				c.log.Debug("mieru v2 payload decrypt failed", "err", err)
				return
			}
			v2IncreaseNonce(c.rn)
		}
		if suffixLen > 0 {
			if _, err := io.CopyN(io.Discard, c.rr, int64(suffixLen)); err != nil {
				return
			}
		}

		// Track the client's sequence cursor for ACKs and fragment order. A data
		// segment may arrive before the relay consumed the open payload, so the
		// cursor is advanced monotonically rather than checked strictly.
		next := seq + 1
		if next > c.clientNext {
			c.clientNext = next
		}
		if seq >= c.clientSeq {
			c.clientSeq = next
		}

		if len(data) > 0 {
			c.log.Debug("mieru v2 deliver", "session", c.sessionID, "seq", seq, "len", len(data))
			c.frames <- data
			// A segment with the wrong sequence is still delivered: the client
			// reassembles by sequence, and the official peer does not reorder on
			// a single TCP connection.
		}
	}
}

// CloseWrite sends a closeSessionRequest.
func (c *v2Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil
	}
	meta := v2SessionMeta(v2ProtoCloseRq, c.sessionID, c.wseq, 0, 0, 0)
	sealed := c.w.Seal(nil, c.wn, meta, nil)
	v2IncreaseNonce(c.wn)
	_, err := c.conn.Write(sealed)
	return err
}

// Close closes the session. The reader is left to observe the transport EOF.
func (c *v2Conn) Close() error {
	c.wmu.Lock()
	c.closed = true
	c.wmu.Unlock()
	c.closeOne.Do(func() {})
	return c.conn.Close()
}
