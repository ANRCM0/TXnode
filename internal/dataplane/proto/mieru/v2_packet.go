package mieru

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	v2MaxPeers          = 1024
	v2PacketWindow      = 64
	v2ReceiveBudget     = 256 << 10
	v2RetransmitInitial = 250 * time.Millisecond
	v2RetransmitMax     = 2 * time.Second
	v2TransmissionLimit = 12
	v2SessionLifetime   = 2 * time.Hour
	v2ReplayCapacity    = 16384
	v2ReplayLifetime    = 10 * time.Minute
)

type v2Datagram struct {
	meta    []byte
	payload []byte
}

type v2Pending struct {
	packet v2Datagram
	last   time.Time
	rto    time.Duration
	tries  int
}

// v2DatagramConn turns the authenticated v3.38.1 packet underlay into one
// ordered net.Conn. Only Read/Write expose business bytes to the shared relay;
// ACK, padding, duplicates and transport retransmissions stay below that edge.
type v2DatagramConn struct {
	srv       *udpServer
	handler   *Handler
	key       *v2Key
	peerKey   string
	client    net.Addr
	id        uint32
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	appDone   chan struct{}
	once      sync.Once
	closeOnce sync.Once
	notify    chan struct{}
	rmu       sync.Mutex
	wmu       sync.Mutex
	sendMu    sync.Mutex
	mu        sync.Mutex

	nextRecv  uint32
	nextSend  uint32
	window    uint16
	remoteAck uint32
	reorder   map[uint32]v2Datagram
	ready     [][]byte
	buffered  int
	pending   map[uint32]*v2Pending
	lastRX    time.Time
	lastTX    time.Time
	created   time.Time
	readDL    time.Time
	writeDL   time.Time
	closed    bool
	closing   bool
	clientLow bool
	closeErr  error
}

func v2PacketKey(addr net.Addr, userID int, sid uint32) string {
	return addr.String() + "/" + strconv.Itoa(userID) + "/" + strconv.FormatUint(uint64(sid), 10)
}

func (h *Handler) reserveV2Session(key *v2Key, sid uint32) bool {
	// A stable authenticated session identity, rather than ciphertext bytes,
	// also catches a retransmission re-encrypted under a different nonce.
	b := append([]byte("mieru-v2-session/"), key.user.key[:]...)
	b = binary.BigEndian.AppendUint32(b, sid)
	sum := sha256.Sum256(b)
	fingerprint := binary.BigEndian.Uint64(sum[:8])
	now := time.Now()
	h.rmu.Lock()
	defer h.rmu.Unlock()
	for id, at := range h.v2Replay {
		if now.Sub(at) > v2ReplayLifetime {
			delete(h.v2Replay, id)
		}
	}
	if _, seen := h.v2Replay[fingerprint]; seen || len(h.v2Replay) >= v2ReplayCapacity {
		return false
	}
	h.v2Replay[fingerprint] = now
	return true
}

func v2MetaFresh(meta []byte) bool {
	minute := int64(binary.BigEndian.Uint32(meta[2:6]))
	now := time.Now().Unix() / 60
	return minute >= now-2 && minute <= now+2
}

func v2OpenDatagram(key *v2Key, wire, meta []byte) (v2Datagram, error) {
	if len(wire) < v2NonceLen+v2MetaLen+v2TagLen || len(meta) != v2MetaLen || !v2MetaFresh(meta) {
		return v2Datagram{}, errSegmentMalformed
	}
	proto := meta[0]
	prefix, length, suffix := 0, 0, 0
	switch proto {
	case v2ProtoOpenReq, v2ProtoCloseRq, v2ProtoCloseRs:
		length, suffix = int(binary.BigEndian.Uint16(meta[15:17])), int(meta[17])
		if meta[14] != 0 || length > v2MaxSessionPayload || (proto != v2ProtoOpenReq && length != 0) {
			return v2Datagram{}, errSegmentMalformed
		}
	case v2ProtoDataC2S, v2ProtoLowC2S, v2ProtoAckC2S:
		prefix, length, suffix = int(meta[21]), int(binary.BigEndian.Uint16(meta[22:24])), int(meta[24])
		if (proto == v2ProtoDataC2S && length > v2MaxPayload) || (proto == v2ProtoAckC2S && length != 0) {
			return v2Datagram{}, errSegmentMalformed
		}
	default:
		return v2Datagram{}, errSegmentMalformed
	}
	body := wire[v2NonceLen+v2MetaLen+v2TagLen:]
	expected := prefix + length + suffix
	if length > 0 {
		expected += v2TagLen
	}
	if len(body) != expected {
		return v2Datagram{}, errSegmentMalformed
	}
	var payload []byte
	if length > 0 {
		sealed := body[prefix : prefix+length+v2TagLen]
		var err error
		if proto == v2ProtoLowC2S {
			sealed, err = entropyOpenPayload(sealed, meta)
			if err != nil {
				return v2Datagram{}, err
			}
		}
		payload, err = key.aead.Open(nil, wire[:v2NonceLen], sealed, nil)
		if err != nil {
			return v2Datagram{}, err
		}
	} else if proto == v2ProtoLowC2S {
		return v2Datagram{}, errEntropy
	}
	return v2Datagram{meta: append([]byte(nil), meta...), payload: payload}, nil
}

// handleV2 returns true only after authenticating the packet as the official
// underlay. An unauthenticated packet can still be the older compatibility mode.
func (s *udpServer) handleV2(h *Handler, addr net.Addr, wire []byte) bool {
	if len(wire) < v2NonceLen+v2MetaLen+v2TagLen {
		return false
	}
	var key *v2Key
	var meta []byte
	s.mu.Lock()
	candidates := make([]*v2DatagramConn, 0)
	for _, peer := range s.v2Peers {
		if peer.client.String() == addr.String() {
			candidates = append(candidates, peer)
		}
	}
	s.mu.Unlock()
	for _, peer := range candidates {
		plain, err := peer.key.aead.Open(nil, wire[:v2NonceLen], wire[v2NonceLen:v2NonceLen+v2MetaLen+v2TagLen], nil)
		if err == nil {
			key, meta = peer.key, plain
			break
		}
	}
	if key == nil {
		var ok bool
		key, meta, _, ok = h.v2Try(bufio.NewReader(bytes.NewReader(wire)))
		if !ok {
			return false
		}
	}
	packet, err := v2OpenDatagram(key, wire, meta)
	if err != nil || key.user.user.ID <= 0 {
		s.dropped.Add(1)
		return true
	}
	sid := binary.BigEndian.Uint32(meta[6:10])
	if sid == 0 {
		s.dropped.Add(1)
		return true
	}
	peerKey := v2PacketKey(addr, key.user.user.ID, sid)
	s.mu.Lock()
	peer := s.v2Peers[peerKey]
	full := len(s.v2Peers)+len(s.peers) >= v2MaxPeers
	s.mu.Unlock()
	if peer == nil {
		if meta[0] != v2ProtoOpenReq || full || binary.BigEndian.Uint32(meta[10:14]) != 0 || !h.reserveV2Session(key, sid) {
			s.dropped.Add(1)
			return true
		}
		ctx, cancel := context.WithCancel(s.ctx)
		now := time.Now()
		peer = &v2DatagramConn{
			srv: s, handler: h, key: key, peerKey: peerKey, client: addr, id: sid,
			ctx: ctx, cancel: cancel, done: make(chan struct{}), appDone: make(chan struct{}), notify: make(chan struct{}, 1),
			nextRecv: 1, nextSend: 1, window: v2PacketWindow,
			reorder: make(map[uint32]v2Datagram), pending: make(map[uint32]*v2Pending),
			lastRX: now, lastTX: now, created: now,
		}
		if len(packet.payload) > 0 {
			peer.ready = append(peer.ready, packet.payload)
			peer.buffered = len(packet.payload)
		}
		open := v2Datagram{meta: v2SessionMeta(v2ProtoOpenRsp, sid, 0, 0, 0, 0)}
		peer.pending[0] = &v2Pending{packet: open, last: now, rto: v2RetransmitInitial, tries: 1}
		s.mu.Lock()
		if s.v2Peers == nil {
			s.v2Peers = make(map[string]*v2DatagramConn)
		}
		s.v2Peers[peerKey] = peer
		s.mu.Unlock()
		go peer.run()
		if err := peer.send(open, true); err != nil {
			peer.abort(err)
			return true
		}
		go peer.serve()
		return true
	}
	if peer.handler != h || peer.key.user.user != key.user.user {
		s.dropped.Add(1)
		return true
	}
	peer.input(packet)
	return true
}

func (p *v2DatagramConn) signal() {
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

func (p *v2DatagramConn) input(packet v2Datagram) {
	meta := packet.meta
	proto, seq := meta[0], binary.BigEndian.Uint32(meta[10:14])
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.lastRX = time.Now()
	if proto == v2ProtoAckC2S || proto == v2ProtoDataC2S || proto == v2ProtoLowC2S {
		ack := binary.BigEndian.Uint32(meta[14:18])
		if ack > p.nextSend {
			p.mu.Unlock()
			p.srv.dropped.Add(1)
			return
		}
		if ack >= p.remoteAck {
			for sent := range p.pending {
				if sent < ack {
					delete(p.pending, sent)
				}
			}
			p.remoteAck = ack
			p.window = min(binary.BigEndian.Uint16(meta[18:20]), v2PacketWindow)
		}
	}
	if proto == v2ProtoCloseRq || proto == v2ProtoCloseRs {
		p.mu.Unlock()
		if proto == v2ProtoCloseRq {
			_ = p.send(v2Datagram{meta: v2SessionMeta(v2ProtoCloseRs, p.id, 0, 0, 0, 0)}, false)
		}
		p.abort(nil)
		return
	}
	if proto == v2ProtoAckC2S {
		p.mu.Unlock()
		p.signal()
		return
	}
	if p.closing {
		p.mu.Unlock()
		return
	}
	if proto == v2ProtoOpenReq || seq < p.nextRecv {
		p.srv.duplicates.Add(1)
		p.mu.Unlock()
		if proto == v2ProtoOpenReq {
			_ = p.send(v2Datagram{meta: v2SessionMeta(v2ProtoOpenRsp, p.id, 0, 0, 0, 0)}, false)
		}
		_ = p.ack()
		return
	}
	if seq-p.nextRecv >= v2PacketWindow || seq == ^uint32(0) || len(p.reorder)+len(p.ready) >= v2PacketWindow || p.buffered+len(packet.payload) > v2ReceiveBudget {
		p.mu.Unlock()
		p.srv.dropped.Add(1)
		_ = p.ack()
		return
	}
	if _, duplicate := p.reorder[seq]; duplicate {
		p.srv.duplicates.Add(1)
		p.mu.Unlock()
		_ = p.ack()
		return
	}
	if proto == v2ProtoLowC2S {
		p.clientLow = true
	}
	p.reorder[seq] = packet
	p.buffered += len(packet.payload)
	for {
		in, ok := p.reorder[p.nextRecv]
		if !ok {
			break
		}
		delete(p.reorder, p.nextRecv)
		p.nextRecv++
		if len(in.payload) > 0 {
			p.ready = append(p.ready, in.payload)
		}
	}
	p.mu.Unlock()
	p.signal()
	_ = p.ack()
}

func (p *v2DatagramConn) ack() error {
	p.mu.Lock()
	meta := v2DataMeta(v2ProtoAckS2C, p.id, p.nextSend-1, p.nextRecv, uint16(v2PacketWindow-len(p.reorder)-len(p.ready)), 0, 0, 0, 0)
	p.mu.Unlock()
	return p.send(v2Datagram{meta: meta}, false)
}

func (p *v2DatagramConn) send(packet v2Datagram, first bool) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	if p.handler != p.srv.owner.currentPacketHandler() {
		return net.ErrClosed
	}
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	meta := append([]byte(nil), packet.meta...)
	// Every transmission, including a retransmission, gets a fresh nonce and
	// current ACK cursor. Its business sequence and plaintext stay unchanged.
	p.mu.Lock()
	if meta[0] == v2ProtoDataS2C || meta[0] == v2ProtoLowS2C || meta[0] == v2ProtoAckS2C {
		binary.BigEndian.PutUint32(meta[14:18], p.nextRecv)
		binary.BigEndian.PutUint16(meta[18:20], uint16(v2PacketWindow-len(p.reorder)-len(p.ready)))
	}
	p.lastTX = time.Now()
	p.mu.Unlock()
	binary.BigEndian.PutUint32(meta[2:6], uint32(time.Now().Unix()/60))
	if meta[0] == v2ProtoLowS2C {
		if err := entropyMetadata(meta, entropyMode(meta[1]), entropyRotation(meta[31]), len(packet.payload)); err != nil {
			return err
		}
	}
	var nonce [v2NonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	if err := p.handler.pattern.nonce(nonce[:], first); err != nil {
		return err
	}
	v2HintNonce(nonce[:], p.key.user.name)
	var payload []byte
	if len(packet.payload) > 0 {
		payload = p.key.aead.Seal(nil, nonce[:], packet.payload, nil)
		if meta[0] == v2ProtoLowS2C {
			var err error
			payload, err = entropySealPayload(payload, meta)
			if err != nil {
				return err
			}
		}
	}
	budget := p.mtu() - v2NonceLen - v2MetaLen - v2TagLen - len(payload)
	var prefix, suffix []byte
	var err error
	if meta[0] == v2ProtoDataS2C || meta[0] == v2ProtoLowS2C {
		prefix, err = p.handler.pattern.padding(budget, true)
		if err != nil {
			return err
		}
		budget -= len(prefix)
		meta[21] = byte(len(prefix))
	}
	if meta[0] != v2ProtoAckS2C {
		suffix, err = p.handler.pattern.padding(budget, false)
		if err != nil {
			return err
		}
		if meta[0] == v2ProtoDataS2C || meta[0] == v2ProtoLowS2C {
			meta[24] = byte(len(suffix))
		} else {
			meta[17] = byte(len(suffix))
		}
	}
	wire := append([]byte(nil), nonce[:]...)
	wire = p.key.aead.Seal(wire, nonce[:], meta, nil)
	wire = append(wire, prefix...)
	wire = append(wire, payload...)
	wire = append(wire, suffix...)
	if len(wire) > p.mtu() {
		return errors.New("mieru: packet exceeds configured MTU")
	}
	n, err := p.srv.pc.WriteTo(wire, p.client)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	return err
}

func (p *v2DatagramConn) mtu() int {
	if p.handler.v2Mtu > 0 {
		return min(p.handler.v2Mtu, 1400)
	}
	return v2DefaultMTU
}

func (p *v2DatagramConn) serve() {
	defer p.Close()
	_ = p.SetReadDeadline(time.Now().Add(handshakeTimeout))
	sess, err := v2SocksSession(p, p.key.user.user.ID)
	if err != nil {
		return
	}
	_ = p.SetReadDeadline(time.Time{})
	sess.AuthValid = func() bool { return p.handler == p.srv.owner.currentPacketHandler() }
	_ = p.handler.packetRelay(p.ctx, sess)
}

func (p *v2DatagramConn) run() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-p.ctx.Done():
			p.abort(p.ctx.Err())
			return
		case now := <-ticker.C:
			if !p.step(now) {
				return
			}
		}
	}
}

func (p *v2DatagramConn) step(now time.Time) bool {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return false
	}
	if p.handler != p.srv.owner.currentPacketHandler() || now.Sub(p.lastRX) > p.handler.Idle || now.Sub(p.created) > v2SessionLifetime {
		p.mu.Unlock()
		p.abort(net.ErrClosed)
		return false
	}
	var resend []v2Datagram
	for _, pending := range p.pending {
		if now.Sub(pending.last) < pending.rto {
			continue
		}
		if pending.tries >= v2TransmissionLimit {
			p.mu.Unlock()
			p.srv.dropped.Add(1)
			p.abort(errors.New("mieru: reliable packet retransmission budget exhausted"))
			return false
		}
		pending.last, pending.tries = now, pending.tries+1
		pending.rto = min(pending.rto*2, v2RetransmitMax)
		resend = append(resend, pending.packet)
	}
	interval := p.handler.v2HeartbeatInterval()
	heartbeat := interval > 0 && now.Sub(p.lastTX) >= interval
	p.mu.Unlock()
	for _, packet := range resend {
		p.srv.retransmissions.Add(1)
		if err := p.send(packet, false); err != nil {
			p.abort(err)
			return false
		}
	}
	if heartbeat {
		if err := p.ack(); err != nil {
			p.abort(err)
			return false
		}
	}
	return true
}

func (p *v2DatagramConn) Read(dst []byte) (int, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	if len(dst) == 0 {
		return 0, nil
	}
	for {
		p.mu.Lock()
		if p.handler != p.srv.owner.currentPacketHandler() {
			p.mu.Unlock()
			p.abort(net.ErrClosed)
			return 0, net.ErrClosed
		}
		if len(p.ready) > 0 {
			n := copy(dst, p.ready[0])
			p.ready[0] = p.ready[0][n:]
			p.buffered -= n
			if len(p.ready[0]) == 0 {
				p.ready[0] = nil
				p.ready = p.ready[1:]
			}
			p.mu.Unlock()
			_ = p.ack()
			return n, nil
		}
		closed, deadline, closeErr := p.closed || p.closing, p.readDL, p.closeErr
		p.mu.Unlock()
		if closed {
			if closeErr != nil {
				return 0, closeErr
			}
			return 0, io.EOF
		}
		if err := p.wait(deadline); err != nil {
			return 0, err
		}
	}
}

func (p *v2DatagramConn) Write(src []byte) (int, error) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	written := 0
	for len(src) > 0 {
		p.mu.Lock()
		if p.closed || p.closing || p.handler != p.srv.owner.currentPacketHandler() {
			p.mu.Unlock()
			return written, net.ErrClosed
		}
		if len(p.pending) >= v2PacketWindow || len(p.pending) >= int(p.window) {
			deadline := p.writeDL
			p.mu.Unlock()
			if err := p.wait(deadline); err != nil {
				return written, err
			}
			continue
		}
		if p.nextSend == ^uint32(0) {
			p.mu.Unlock()
			p.abort(errors.New("mieru: sequence space exhausted"))
			return written, errors.New("mieru: sequence space exhausted")
		}
		limit := p.mtu() - v2NonceLen - v2MetaLen - 2*v2TagLen
		mode, rotation := entropyMode(0), entropyRotation(0)
		if p.clientLow && p.handler.pattern.LowEntropy != nil {
			mode, rotation = p.handler.pattern.LowEntropy.Mode, p.handler.pattern.LowEntropy.MaskRotation
			if mode != 0 {
				width, _ := entropySourceBytes(mode)
				limit = (limit / 8) * width
			}
		}
		n := min(len(src), limit)
		meta := v2DataMeta(v2ProtoDataS2C, p.id, p.nextSend, p.nextRecv, v2PacketWindow, 0, n, 0, 0)
		if mode != 0 {
			meta[0], meta[1], meta[31] = v2ProtoLowS2C, byte(mode), byte(rotation)
		}
		packet := v2Datagram{meta: meta, payload: append([]byte(nil), src[:n]...)}
		p.pending[p.nextSend] = &v2Pending{packet: packet, last: time.Now(), rto: v2RetransmitInitial, tries: 1}
		p.nextSend++
		p.mu.Unlock()
		if err := p.send(packet, false); err != nil {
			p.abort(err)
			return written, err
		}
		written += n
		src = src[n:]
	}
	return written, nil
}

func (p *v2DatagramConn) wait(deadline time.Time) error {
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return &net.OpError{Op: "mieru", Net: "udp", Err: os.ErrDeadlineExceeded}
	}
	// One notification channel is shared by reader and writer. A short bounded
	// poll also wakes the other direction if the first consumes its notification.
	delay := 50 * time.Millisecond
	if !deadline.IsZero() {
		delay = min(delay, time.Until(deadline))
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-p.done:
		return net.ErrClosed
	case <-p.appDone:
		return net.ErrClosed
	case <-p.notify:
	case <-timer.C:
	}
	return nil
}

func (p *v2DatagramConn) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closing = true
		p.mu.Unlock()
		close(p.appDone)
		p.signal()
		// Keep already accepted bytes retransmittable after the core finishes its
		// writes. This bounded drain owns no additional accounting tokens.
		go func() {
			timer := time.NewTimer(3 * time.Second)
			defer timer.Stop()
			tick := time.NewTicker(25 * time.Millisecond)
			defer tick.Stop()
			for {
				p.mu.Lock()
				empty := len(p.pending) == 0
				seq := p.nextSend
				p.mu.Unlock()
				if empty {
					_ = p.send(v2Datagram{meta: v2SessionMeta(v2ProtoCloseRq, p.id, seq, 0, 0, 0)}, false)
					p.abort(nil)
					return
				}
				select {
				case <-p.done:
					return
				case <-timer.C:
					p.abort(errors.New("mieru: close drain deadline exceeded"))
					return
				case <-tick.C:
				}
			}
		}()
	})
	return nil
}

func (p *v2DatagramConn) abort(err error) {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.closeErr = err
		p.pending = make(map[uint32]*v2Pending)
		p.reorder = make(map[uint32]v2Datagram)
		if p.handler != p.srv.owner.currentPacketHandler() || err != nil {
			p.ready = nil
			p.buffered = 0
		}
		p.mu.Unlock()
		p.cancel()
		close(p.done)
		p.srv.mu.Lock()
		if p.srv.v2Peers[p.peerKey] == p {
			delete(p.srv.v2Peers, p.peerKey)
		}
		p.srv.mu.Unlock()
	})
}

func (p *v2DatagramConn) LocalAddr() net.Addr  { return p.srv.pc.LocalAddr() }
func (p *v2DatagramConn) RemoteAddr() net.Addr { return p.client }
func (p *v2DatagramConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDL, p.writeDL = t, t
	p.mu.Unlock()
	p.signal()
	return nil
}
func (p *v2DatagramConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDL = t
	p.mu.Unlock()
	p.signal()
	return nil
}
func (p *v2DatagramConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeDL = t
	p.mu.Unlock()
	p.signal()
	return nil
}

func (p *v2DatagramConn) HandshakeSucceeded(local net.Addr) error {
	return writeFull(p, v2Socks5Reply(0, local))
}
func (p *v2DatagramConn) HandshakeFailed(err error) error {
	return writeFull(p, v2Socks5Reply(v2Socks5Code(err), nil))
}

var _ net.Conn = (*v2DatagramConn)(nil)
