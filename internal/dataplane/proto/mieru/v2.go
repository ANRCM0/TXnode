package mieru

// mieru protocol v2 (official client) — TCP, single session, XChaCha20-Poly1305
// with implicit nonces. Derived from docs/protocol.md:
//
//	key: sha256(password || 0x00 || username) -> PBKDF2-64(sha256, salt =
//	     sha256(be64(2-minute-rounded unix time)), 32 bytes)
//	wire: [nonce 24][meta 32 + tag][padding1][payload + tag][padding2]
//	meta: sessionStruct (open/close) or dataAckStruct (data/ack)

import (
	"crypto/rand"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"bufio"
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
	v2MaxPayload   = 32768
	v2ProtoOpenReq = 2
	v2ProtoOpenRsp = 3
	v2ProtoCloseRq = 4
	v2ProtoCloseRs = 5
	v2ProtoDataC2S = 6
	v2ProtoDataS2C = 7
	v2ProtoAckC2S  = 8
	v2ProtoAckS2C  = 9
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

// v2Try authenticates the first segment from a peeked buffer. It returns
// (nil, false, nil) when the bytes are not mieru v2 for any configured user.
func (h *Handler) v2Try(br *bufio.Reader) (*keyEntry, cipher.AEAD, []byte, []byte, bool) {
	head, err := br.Peek(v2NonceLen + v2MetaLen + v2TagLen)
	if err != nil {
		return nil, nil, nil, nil, false
	}
	nonce := head[:v2NonceLen]
	meta := head[v2NonceLen:]

	now := time.Now().Unix()
	rounded := (now + 120) / 120 * 120
	h.kmu.RLock()
	users := append([]*keyEntry(nil), h.keys...)
	h.kmu.RUnlock()
	for _, u := range users {
		hashed := v2HashedPassword(u.name, u.password)
		for _, delta := range []int64{-120, 0, 120} {
			salt := v2TimeSalt(rounded + delta)
			cand, err := v2NewAEAD(v2Derive(hashed[:], salt[:]))
			if err != nil {
				continue
			}
			if p, err := cand.Open(nil, append([]byte(nil), nonce...), meta, nil); err == nil && len(p) == v2MetaLen && p[0] == v2ProtoOpenReq {
				return u, cand, p, nonce, true
			}
		}
	}
	return nil, nil, nil, nil, false
}

// v2Handshake completes the session open on an authenticated first segment.
func (h *Handler) v2Handshake(conn net.Conn, br *bufio.Reader, chosen *keyEntry, aead cipher.AEAD, plain, nonce []byte) (*core.Session, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = br.Discard(v2NonceLen + v2MetaLen + v2TagLen)
	now := time.Now().Unix()
	rounded := (now + 120) / 120 * 120
	curNonc := append([]byte(nil), nonce...)
	sessionID := binary.BigEndian.Uint32(plain[6:10])
	payloadLen := int(binary.BigEndian.Uint16(plain[15:17]))
	suffixLen := int(plain[17])
	if payloadLen > 1024 {
		return nil, errors.New("mieru: bad open payload")
	}
	// payload follows the metadata; suffix padding after it.
	body := make([]byte, payloadLen+v2TagLen+suffixLen)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	v2IncreaseNonce(curNonc)
	var dest socks.Addr
	if payloadLen > 0 {
		p, err := aead.Open(nil, curNonc, body[:payloadLen+v2TagLen], nil)
		if err != nil {
			return nil, errors.New("mieru: open payload authentication failed")
		}
		dest, err = parseSocks5Request(p)
		if err != nil {
			return nil, err
		}
	}
	v2IncreaseNonce(curNonc)

	// Server cipher: fresh nonce, hinted with the username.
	srvNonce := make([]byte, v2NonceLen)
	if _, err := rand.Read(srvNonce); err != nil {
		return nil, err
	}
	hashed := v2HashedPassword(chosen.name, chosen.password)
	var srvAEAD cipher.AEAD
	for _, delta := range []int64{-120, 0, 120} {
		salt := v2TimeSalt(rounded + delta)
		cand, err := v2NewAEAD(v2Derive(hashed[:], salt[:]))
		if err != nil {
			continue
		}
		// Probe by sealing a throwaway block is unnecessary; use the first salt
		// matching the client's clock window by convention (rounded).
		srvAEAD = cand
		break
	}
	if srvAEAD == nil {
		return nil, errors.New("mieru: server cipher")
	}
	v2HintNonce(srvNonce, chosen.name)

	h.log.Debug("mieru v2 open", "user", chosen.name, "session", sessionID, "dest", dest.String())
	// openSessionResponse
	rspMeta := v2SessionMeta(v2ProtoOpenRsp, sessionID, 0, 0, 0)
	sealedMeta := srvAEAD.Seal(nil, srvNonce, rspMeta, nil)
	if _, err := conn.Write(append(append([]byte(nil), srvNonce...), sealedMeta...)); err != nil {
		return nil, err
	}
	v2IncreaseNonce(srvNonce)
	_ = conn.SetReadDeadline(time.Time{})

	vc := &v2Conn{
		Conn:      conn,
		conn:      conn,
		rr:        br,
		frames:    make(chan []byte, 16),
		log:       h.log,
		r:         aead,
		w:         srvAEAD,
		rn:        curNonc,
		wn:        srvNonce,
		sessionID: sessionID,
	}
	go vc.readLoop()
	return &core.Session{UserID: chosen.user.ID, Dest: dest, Conn: vc}, nil
}

func v2SessionMeta(proto byte, sessionID, seq uint32, status byte, payloadLen int) []byte {
	b := make([]byte, v2MetaLen)
	b[0] = proto
	binary.BigEndian.PutUint32(b[2:], uint32(time.Now().Unix()/60))
	binary.BigEndian.PutUint32(b[6:], sessionID)
	binary.BigEndian.PutUint32(b[10:], seq)
	b[14] = status
	binary.BigEndian.PutUint16(b[15:], uint16(payloadLen))
	return b
}

func v2DataMeta(proto byte, sessionID, seq, unack uint32, payloadLen int) []byte {
	b := make([]byte, v2MetaLen)
	b[0] = proto
	binary.BigEndian.PutUint32(b[2:], uint32(time.Now().Unix()/60))
	binary.BigEndian.PutUint32(b[6:], sessionID)
	binary.BigEndian.PutUint32(b[10:], seq)
	binary.BigEndian.PutUint32(b[14:], unack)
	binary.BigEndian.PutUint16(b[18:], 65535) // window size
	b[20] = 0                                 // fragment number
	b[21] = 0                                 // prefix (padding 1) length
	binary.BigEndian.PutUint16(b[22:], uint16(payloadLen))
	b[24] = 0 // suffix (padding 2) length
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

// v2Conn is the record connection handed to the relay.
type v2Conn struct {
	net.Conn
	conn      net.Conn
	rr        io.Reader
	r, w      cipher.AEAD
	rn, wn    []byte
	sessionID uint32
	log       *slog.Logger

	wmu      sync.Mutex
	wseq     uint32
	frames   chan []byte
	closeOne sync.Once
}

func (c *v2Conn) Read(p []byte) (int, error) {
	for {
		select {
		case b, ok := <-c.frames:
			if !ok {
				return 0, io.EOF
			}
			n := copy(p, b)
			if n < len(b) {
				// Keep the remainder.
				c.frames <- b[n:]
			}
			return n, nil
		}
	}
}

func (c *v2Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > v2MaxPayload {
			n = v2MaxPayload
		}
		meta := v2DataMeta(v2ProtoDataS2C, c.sessionID, c.wseq, 0, n)
		sealedMeta := c.w.Seal(nil, c.wn, meta, nil)
		v2IncreaseNonce(c.wn)
		sealedPayload := c.w.Seal(nil, c.wn, p[:n], nil)
		v2IncreaseNonce(c.wn)
		out := append(append([]byte(nil), sealedMeta...), sealedPayload...)
		if _, err := c.conn.Write(out); err != nil {
			return written, err
		}
		c.wseq++
		written += n
		p = p[n:]
	}
	return written, nil
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
		plain, err := c.r.Open(nil, c.rn, meta, nil)
		if err != nil {
			c.log.Debug("mieru v2 meta decrypt failed", "err", err)
			return
		}
		c.log.Debug("mieru v2 segment", "type", plain[0], "payload", binary.BigEndian.Uint16(plain[22:24]))
		v2IncreaseNonce(c.rn)
		prefixLen := 0
		payloadLen := 0
		suffixLen := 0
		switch plain[0] {
		case v2ProtoDataC2S:
			prefixLen = int(plain[21])
			payloadLen = int(binary.BigEndian.Uint16(plain[22:24]))
			suffixLen = int(plain[24])
		case v2ProtoAckC2S, v2ProtoAckS2C:
			// no payload
		case v2ProtoCloseRq:
			c.closeOne.Do(func() { _ = c.conn.Close() })
			return
		default:
			return
		}
		if prefixLen > 0 {
			if _, err := io.CopyN(io.Discard, c.rr, int64(prefixLen)); err != nil {
				return
			}
		}
		if payloadLen > 0 {
			body := make([]byte, payloadLen+v2TagLen)
			if _, err := io.ReadFull(c.rr, body); err != nil {
				return
			}
			data, err := c.r.Open(nil, c.rn, body, nil)
			if err != nil {
				return
			}
			v2IncreaseNonce(c.rn)
			c.frames <- data
		}
		if suffixLen > 0 {
			if _, err := io.CopyN(io.Discard, c.rr, int64(suffixLen)); err != nil {
				return
			}
		}
	}
}

// CloseWrite sends a closeSessionRequest.
func (c *v2Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	meta := v2SessionMeta(v2ProtoCloseRq, c.sessionID, 0, 0, 0)
	sealed := c.w.Seal(nil, c.wn, meta, nil)
	v2IncreaseNonce(c.wn)
	_, err := c.conn.Write(sealed)
	return err
}
