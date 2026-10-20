package mieru

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// The implicit cipher cursors belong to the TCP underlay, while sequence
// numbers and SOCKS requests belong to independently closed logical sessions.
type v2TCPTransport struct {
	h            *Handler
	key          *v2Key
	conn         net.Conn
	reader       *bufio.Reader
	rn, wn       []byte
	wmu          sync.Mutex
	deadlineMu   sync.Mutex
	activeWriter *v2Conn
	mu           sync.Mutex
	streams      map[uint32]*v2Conn
	lastRX       time.Time
	firstTX      bool
	done         chan struct{}
	once         sync.Once
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

func (h *Handler) v2ServeTCP(parent context.Context, conn net.Conn, br *bufio.Reader, key *v2Key, first, nonce []byte) (*core.Session, error) {
	_, _ = br.Discard(v2NonceLen + v2MetaLen + v2TagLen)
	ctx, cancel := context.WithCancel(parent)
	t := &v2TCPTransport{h: h, key: key, conn: conn, reader: br,
		rn: append([]byte(nil), nonce...), wn: make([]byte, v2NonceLen),
		streams: make(map[uint32]*v2Conn), lastRX: time.Now(), firstTX: true,
		done: make(chan struct{}), ctx: ctx, cancel: cancel}
	v2IncreaseNonce(t.rn)
	defer func() { t.close(); t.wg.Wait() }()
	stopCancel := context.AfterFunc(ctx, t.close)
	defer stopCancel()
	if _, err := rand.Read(t.wn); err != nil {
		return nil, err
	}
	if err := h.pattern.nonce(t.wn, true); err != nil {
		return nil, err
	}
	v2HintNonce(t.wn, key.user.name)
	payload, err := t.readPayload(first)
	if err != nil {
		return nil, err
	}
	if err := t.input(first, payload); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	go t.heartbeat()
	for {
		sealed := make([]byte, v2MetaLen+v2TagLen)
		if _, err := io.ReadFull(br, sealed); err != nil {
			break
		}
		meta, err := key.aead.Open(nil, t.rn, sealed, nil)
		if err != nil {
			break
		}
		v2IncreaseNonce(t.rn)
		payload, err := t.readPayload(meta)
		if err != nil {
			break
		}
		if err := t.input(meta, payload); err != nil {
			h.log.Debug("mieru v2 TCP underlay ended", "err", err)
			break
		}
	}
	// Like the HTTP/2 transport, this authenticated connection was consumed
	// through the configured relay and has no single session to return.
	return nil, &core.Stranger{Conn: conn, Quiet: true}
}

func (t *v2TCPTransport) valid() bool {
	select {
	case <-t.done:
		return false
	default:
		return t.h == t.h.currentPacketHandler()
	}
}

func (t *v2TCPTransport) close() {
	t.once.Do(func() {
		close(t.done)
		t.cancel()
		_ = t.conn.Close()
		t.mu.Lock()
		streams := make([]*v2Conn, 0, len(t.streams))
		for _, c := range t.streams {
			streams = append(streams, c)
		}
		t.mu.Unlock()
		// Do not take a session or writer lock here: a failed record invokes
		// close with those locks held. Cancel/transport EOF wakes each relay.
		for _, c := range streams {
			select {
			case c.wake <- struct{}{}:
			default:
			}
		}
	})
}

func (t *v2TCPTransport) readPayload(meta []byte) ([]byte, error) {
	if len(meta) != v2MetaLen || !v2MetaFresh(meta) {
		return nil, errSegmentMalformed
	}
	prefix, length, suffix := 0, 0, 0
	switch meta[0] {
	case v2ProtoOpenReq, v2ProtoCloseRq, v2ProtoCloseRs:
		length, suffix = int(binary.BigEndian.Uint16(meta[15:17])), int(meta[17])
		if (meta[0] == v2ProtoOpenReq && meta[14] != 0) || length > v2MaxSessionPayload || (meta[0] != v2ProtoOpenReq && length != 0) {
			return nil, errSegmentMalformed
		}
	case v2ProtoDataC2S, v2ProtoLowC2S, v2ProtoAckC2S:
		prefix, length, suffix = int(meta[21]), int(binary.BigEndian.Uint16(meta[22:24])), int(meta[24])
		if (meta[0] == v2ProtoDataC2S && length > v2MaxPayload) || (meta[0] == v2ProtoAckC2S && length != 0) || (meta[0] == v2ProtoLowC2S && length == 0) {
			return nil, errSegmentMalformed
		}
	default:
		return nil, errSegmentMalformed
	}
	if _, err := io.CopyN(io.Discard, t.reader, int64(prefix)); err != nil {
		return nil, err
	}
	var payload []byte
	if length > 0 {
		sealed := make([]byte, length+v2TagLen)
		if _, err := io.ReadFull(t.reader, sealed); err != nil {
			return nil, err
		}
		var err error
		if meta[0] == v2ProtoLowC2S {
			sealed, err = entropyOpenPayload(sealed, meta)
			if err != nil {
				return nil, err
			}
		}
		payload, err = t.key.aead.Open(nil, t.rn, sealed, nil)
		if err != nil {
			return nil, err
		}
		v2IncreaseNonce(t.rn)
	}
	if _, err := io.CopyN(io.Discard, t.reader, int64(suffix)); err != nil {
		return nil, err
	}
	return payload, nil
}

func (t *v2TCPTransport) input(meta, payload []byte) error {
	if !t.valid() {
		return net.ErrClosed
	}
	sid, seq := binary.BigEndian.Uint32(meta[6:10]), binary.BigEndian.Uint32(meta[10:14])
	if sid == 0 {
		return errSegmentMalformed
	}
	t.mu.Lock()
	t.lastRX = time.Now()
	c := t.streams[sid]
	full := len(t.streams) >= v2PacketWindow
	t.mu.Unlock()
	t.h.log.Debug("mieru v2 TCP segment", "type", meta[0], "session", sid, "seq", seq)
	if meta[0] == v2ProtoOpenReq {
		if c != nil || seq != 0 || full || !t.h.reserveV2Session(t.key, sid) {
			return errors.New("mieru: duplicate or excessive TCP session")
		}
		now := time.Now()
		c = &v2Conn{transport: t, Conn: t.conn, conn: t.conn, r: t.key.aead, w: t.key.aead,
			wn: t.wn, sessionID: sid, log: t.h.log, pattern: t.h.pattern, idle: t.h.Idle,
			mtu: t.h.v2MTU(), wseq: 1, clientSeq: 1, clientNext: 1,
			frames: make(chan []byte, 64), done: make(chan struct{}), wake: make(chan struct{}, 1),
			lastRX: now, lastTX: now}
		if len(payload) > 0 {
			c.frames <- payload
		}
		t.mu.Lock()
		t.streams[sid] = c
		t.mu.Unlock()
		t.wmu.Lock()
		err := t.writeControl(v2ProtoOpenRsp, sid, 0)
		t.wmu.Unlock()
		if err != nil {
			return err
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(handshakeTimeout))
			sess, err := v2SocksSession(c, t.key.user.user.ID)
			if err != nil {
				return
			}
			_ = c.SetReadDeadline(time.Time{})
			sess.AuthValid = t.valid
			_ = t.h.packetRelay(t.ctx, sess)
		}()
		return nil
	}
	// Late ACK/close records for a completed session still consume the shared
	// cipher cursor. They must not terminate or recreate the TCP underlay.
	if c == nil {
		return nil
	}
	if meta[0] == v2ProtoCloseRq || meta[0] == v2ProtoCloseRs {
		response := byte(0)
		if meta[0] == v2ProtoCloseRq {
			response = v2ProtoCloseRs
		}
		t.endSession(c, response)
		return nil
	}
	c.wmu.Lock()
	if c.closed {
		c.wmu.Unlock()
		return nil
	}
	if meta[0] == v2ProtoAckC2S {
		c.wmu.Unlock()
		// The official stream session ignores ACKs; only the packet underlay
		// uses them for reliability. Their metadata still consumed one nonce.
		return nil
	}
	if seq != c.clientSeq || seq == ^uint32(0) {
		c.wmu.Unlock()
		return errors.New("mieru: unexpected TCP session sequence")
	}
	c.clientSeq, c.clientNext = seq+1, seq+1
	c.lastRX = time.Now()
	if meta[0] == v2ProtoLowC2S {
		c.clientLow = true
	}
	c.wmu.Unlock()
	if len(payload) > 0 {
		select {
		case c.frames <- payload:
		case <-c.done:
		default:
			t.endSession(c, v2ProtoCloseRq)
		}
	}
	return nil
}

// Caller holds the shared writer lock. Only the first server metadata record
// carries the explicit nonce; all sessions then share the implicit cursor.
func (t *v2TCPTransport) writeControl(proto byte, sid, seq uint32) error {
	if !t.valid() {
		return net.ErrClosed
	}
	meta := v2SessionMeta(proto, sid, seq, 0, 0, 0)
	wire := make([]byte, 0, v2NonceLen+v2MetaLen+v2TagLen)
	if t.firstTX {
		wire = append(wire, t.wn...)
		t.firstTX = false
	}
	wire = t.key.aead.Seal(wire, t.wn, meta, nil)
	v2IncreaseNonce(t.wn)
	_ = t.conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	defer t.conn.SetWriteDeadline(time.Time{})
	if err := t.h.pattern.writeTCP(t.conn, wire); err != nil {
		t.close()
		return err
	}
	return nil
}

func (t *v2TCPTransport) endSession(c *v2Conn, response byte) {
	c.closeOne.Do(func() {
		c.wmu.Lock()
		c.closed = true
		close(c.done)
		if response != 0 {
			t.wmu.Lock()
			_ = t.writeControl(response, c.sessionID, c.wseq)
			t.wmu.Unlock()
		}
		c.wmu.Unlock()
		t.mu.Lock()
		delete(t.streams, c.sessionID)
		t.mu.Unlock()
	})
}

func (t *v2TCPTransport) heartbeat() {
	interval := t.h.v2HeartbeatInterval()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
		}
		t.mu.Lock()
		idle := time.Since(t.lastRX) > t.h.Idle
		streams := make([]*v2Conn, 0, len(t.streams))
		for _, c := range t.streams {
			streams = append(streams, c)
		}
		t.mu.Unlock()
		if idle || !t.valid() {
			t.close()
			return
		}
		if interval <= 0 {
			continue
		}
		for _, c := range streams {
			c.wmu.Lock()
			if !c.closed && time.Since(c.lastTX) >= interval {
				if err := c.writeSegmentLocked(nil); err != nil {
					c.failWriteLocked()
				}
			}
			c.wmu.Unlock()
		}
	}
}

func (c *v2Conn) readMultiplexed(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if !c.transport.valid() {
			return 0, net.ErrClosed
		}
		c.dlmu.Lock()
		deadline := c.readDL
		c.dlmu.Unlock()
		if len(c.remainder) == 0 {
			select {
			case c.remainder = <-c.frames:
			default:
			}
		}
		if len(c.remainder) > 0 {
			n := copy(p, c.remainder)
			c.remainder = c.remainder[n:]
			return n, nil
		}
		select {
		case <-c.done:
			return 0, io.EOF
		default:
		}
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case b := <-c.frames:
			c.remainder = b
		case <-c.done:
		case <-c.transport.done:
		case <-c.wake:
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *v2Conn) SetReadDeadline(deadline time.Time) error {
	if c.transport == nil {
		return c.conn.SetReadDeadline(deadline)
	}
	c.dlmu.Lock()
	c.readDL = deadline
	c.dlmu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

// Both the logical-session lock and the shared cipher writer lock are held.
func (c *v2Conn) writeWireLocked(wire []byte) error {
	if c.transport == nil {
		return c.pattern.writeTCP(c.conn, wire)
	}
	t := c.transport
	t.deadlineMu.Lock()
	t.activeWriter = c
	c.dlmu.Lock()
	deadline := c.writeDL
	c.dlmu.Unlock()
	_ = c.conn.SetWriteDeadline(v2WriteDeadline(deadline))
	t.deadlineMu.Unlock()
	defer func() {
		t.deadlineMu.Lock()
		t.activeWriter = nil
		_ = c.conn.SetWriteDeadline(time.Time{})
		t.deadlineMu.Unlock()
	}()
	return c.pattern.writeTCP(c.conn, wire)
}

func v2WriteDeadline(requested time.Time) time.Time {
	deadline := time.Now().Add(handshakeTimeout)
	if !requested.IsZero() && requested.Before(deadline) {
		return requested
	}
	return deadline
}

func (c *v2Conn) SetWriteDeadline(deadline time.Time) error {
	if c.transport == nil {
		return c.conn.SetWriteDeadline(deadline)
	}
	c.dlmu.Lock()
	c.writeDL = deadline
	c.dlmu.Unlock()
	t := c.transport
	t.deadlineMu.Lock()
	if t.activeWriter == c {
		_ = c.conn.SetWriteDeadline(v2WriteDeadline(deadline))
	}
	t.deadlineMu.Unlock()
	return nil
}

func (c *v2Conn) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}
