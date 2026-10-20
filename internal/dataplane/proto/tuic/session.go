package tuic

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// udpSession is one UDP association, keyed by assocID in client+0x38
// (map[uint16]*udpSession, notes/rev-proto-udp.md §2.2).
type udpSession struct {
	id      uint16
	c       *client
	dest    socks.Addr
	socket  net.Conn
	pktID   atomic.Uint32
	once    sync.Once
	done    chan struct{}
	seen    atomic.Int64
	packets chan queuedPacket
	stream  bool

	fragMu      sync.Mutex
	frags       map[uint16]*fragSet
	recent      map[uint16]time.Time
	recentIDs   [256]uint16
	recentTimes [256]time.Time
	recentNext  uint8
}

type queuedPacket struct {
	addr    socks.Addr
	payload []byte
}

type fragSet struct {
	total   uint8
	parts   map[uint8][]byte
	addr    socks.Addr
	bytes   int
	created time.Time
}

func (s *udpSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.fragMu.Lock()
		clear(s.frags)
		clear(s.recent)
		s.fragMu.Unlock()
		if s.socket != nil {
			_ = s.socket.Close()
		}
	})
	return nil
}

// deliverPacket routes one inbound packet frame to its association.
func (c *client) deliverPacket(f *frame) {
	if !c.authValid() {
		return
	}
	c.mu.Lock()
	sess := c.sessions[f.assocID]
	c.mu.Unlock()

	if sess == nil {
		if (!f.hasAddr || f.addr.IsZero()) && !(c.srv.opts.Relay != nil && f.fragTotal > 1 && f.fragID < f.fragTotal) {
			// A unified packet relay can wait for fragment zero to supply the
			// address even when continuation fragments arrive first.
			return
		}
		var err error
		sess, err = c.openSession(f.assocID, f.addr, f.stream)
		if err != nil {
			c.srv.log.Debug("tuic: udp dial failed", "dest", f.addr.String(), "error", err)
			return
		}
	}
	sess.seen.Store(time.Now().UnixNano())

	payload, addr := sess.reassemble(f)
	if payload == nil {
		return
	}
	if c.srv.opts.Relay != nil {
		if addr.IsZero() {
			addr = sess.dest
		}
		if addr.IsZero() {
			return
		}
		packet := queuedPacket{addr: addr, payload: append([]byte(nil), payload...)}
		select {
		case <-sess.done:
		case sess.packets <- packet:
		default:
		}
		return
	}
	_, _ = sess.socket.Write(payload)
}

// openSession dials the destination and starts the return pump.
func (c *client) openSession(id uint16, dest socks.Addr, stream bool) (*udpSession, error) {
	var conn net.Conn
	if c.srv.opts.Relay == nil {
		raddr, err := net.ResolveUDPAddr("udp", dest.String())
		if err != nil {
			return nil, err
		}
		conn, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			return nil, err
		}
	}
	s := &udpSession{
		id:      id,
		c:       c,
		dest:    dest,
		socket:  conn,
		done:    make(chan struct{}),
		frags:   make(map[uint16]*fragSet),
		packets: make(chan queuedPacket, 64),
		stream:  stream,
	}
	s.seen.Store(time.Now().UnixNano())
	c.mu.Lock()
	if old := c.sessions[id]; old != nil {
		c.mu.Unlock()
		_ = s.Close()
		return old, nil
	}
	if len(c.sessions) >= 256 {
		c.mu.Unlock()
		_ = s.Close()
		return nil, errors.New("tuic: UDP association limit")
	}
	c.sessions[id] = s
	userID := int(c.userID)
	c.mu.Unlock()
	if relay := c.srv.opts.Relay; relay != nil {
		go func() {
			sess := &core.Session{UserID: userID, Dest: dest, Packets: s, SourceIP: c.sourceIP(), AuthValid: c.authValid}
			defer sess.Close()
			_ = relay(c.ctx, sess)
			c.mu.Lock()
			if c.sessions[id] == s {
				delete(c.sessions, id)
			}
			c.mu.Unlock()
		}()
	} else {
		go s.pump()
	}
	return s, nil
}

func (c *client) sourceIP() netip.Addr {
	if c.conn == nil {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddrPort(c.conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	return addr.Addr()
}

func (s *udpSession) ReadPacket(p []byte) (int, socks.Addr, error) {
	select {
	case <-s.done:
		return 0, socks.Addr{}, net.ErrClosed
	case pkt := <-s.packets:
		if len(pkt.payload) > len(p) {
			return 0, socks.Addr{}, io.ErrShortBuffer
		}
		return copy(p, pkt.payload), pkt.addr, nil
	}
}

func (s *udpSession) WritePacket(p []byte, addr socks.Addr) error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	if addr.IsZero() {
		addr = s.dest
	}
	return s.writePacket(p, addr)
}

// pump reads datagrams from the destination and writes them back to the client.
func (s *udpSession) pump() {
	buf := make([]byte, 64<<10)
	for {
		n, err := s.socket.Read(buf)
		if err != nil {
			return
		}
		_ = s.writePacket(buf[:n], s.dest)
	}
}

// writePacket implements (*udpSession).WritePacket @0xb44c60:
//
//	SendDatagram(frame); on DatagramTooLargeError split by (errLen - 0x1d) and
//	send the fragments as datagrams; on any other error fall back to a
//	unidirectional stream with a 10 s write deadline.
func (s *udpSession) writePacket(payload []byte, addr socks.Addr) error {
	if len(payload) > 65535 {
		return errors.New("tuic: UDP packet is too large")
	}
	base := &frame{
		assocID:   s.id,
		pktID:     uint16(s.pktID.Add(1)),
		fragTotal: 1,
		// The peer needs the origin address back: a SOCKS5 UDP relay writes it
		// into the reply header, and dropping it would leave the association
		// without a source for the echoed datagram.
		addr:    addr,
		hasAddr: true,
		payload: payload,
	}
	if s.stream {
		return s.writeStream(base)
	}
	first := base.marshal()
	err := s.c.conn.SendDatagram(first)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		chunk := fragChunkSize(int(tooLarge.MaxDatagramPayloadSize))
		fragments := fragment(base, payload, chunk)
		if len(fragments) == 0 {
			return errors.New("tuic: UDP fragment limit")
		}
		for _, f := range fragments {
			if e := s.c.conn.SendDatagram(f.marshal()); e != nil {
				s.c.srv.log.Debug("tuic: fragmented datagram failed", "error", e)
				return e
			}
		}
		return nil
	}
	// DATAGRAM is not usable on this connection: fall back to uni streams, one
	// frame per stream.
	for _, f := range fragment(base, payload, 0xffff-fragOverhead) {
		if err := s.writeStream(f); err != nil {
			return err
		}
	}
	return nil
}

// writeStream writes one frame on a fresh unidirectional stream.
func (s *udpSession) writeStream(f *frame) error {
	st, err := s.c.conn.OpenUniStream()
	if err != nil {
		return err
	}
	_ = st.SetWriteDeadline(time.Now().Add(writeTimeout))
	packet := f.marshal()
	n, err := st.WriteWithLimit(packet, nil)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	if err != nil {
		st.CancelWrite(quic.StreamErrorCode(0))
		return err
	}
	return st.Close()
}

// Packet IDs, not fragment counts, separate interleaved datagrams. A bounded
// set expires incomplete packets and preserves the first fragment's address.
func (s *udpSession) reassemble(f *frame) ([]byte, socks.Addr) {
	if f.fragTotal > 1 && f.fragID >= f.fragTotal || f.fragTotal <= 1 && f.fragID != 0 {
		return nil, socks.Addr{}
	}
	s.fragMu.Lock()
	defer s.fragMu.Unlock()
	select {
	case <-s.done:
		return nil, socks.Addr{}
	default:
	}
	now := time.Now()
	if seen, ok := s.recent[f.pktID]; ok && now.Sub(seen) < 30*time.Second {
		return nil, socks.Addr{}
	}
	if f.fragTotal <= 1 {
		if len(f.payload) > 65535 {
			return nil, socks.Addr{}
		}
		s.rememberPacket(f.pktID, now)
		return append([]byte{}, f.payload...), f.addr
	}
	for id, set := range s.frags {
		if now.Sub(set.created) > 10*time.Second {
			delete(s.frags, id)
		}
	}
	set := s.frags[f.pktID]
	if set == nil {
		if len(s.frags) >= 64 {
			return nil, socks.Addr{}
		}
		set = &fragSet{total: f.fragTotal, parts: make(map[uint8][]byte), created: now}
		if s.frags == nil {
			s.frags = make(map[uint16]*fragSet)
		}
		s.frags[f.pktID] = set
	}
	if set.total != f.fragTotal {
		delete(s.frags, f.pktID)
		return nil, socks.Addr{}
	}
	if _, ok := set.parts[f.fragID]; ok {
		return nil, socks.Addr{}
	}
	if set.bytes+len(f.payload) > 65535 {
		delete(s.frags, f.pktID)
		return nil, socks.Addr{}
	}
	if f.fragID == 0 {
		if !f.hasAddr || f.addr.IsZero() {
			delete(s.frags, f.pktID)
			return nil, socks.Addr{}
		}
		set.addr = f.addr
	}
	set.parts[f.fragID] = append([]byte(nil), f.payload...)
	set.bytes += len(f.payload)
	if len(set.parts) < int(set.total) {
		return nil, socks.Addr{}
	}
	out := make([]byte, 0, set.bytes)
	for i := uint8(0); i < set.total; i++ {
		out = append(out, set.parts[i]...)
	}
	delete(s.frags, f.pktID)
	s.rememberPacket(f.pktID, now)
	return out, set.addr
}

// Called under fragMu. The bounded completion window rejects replayed packet
// fragments without retaining an ever-growing history or blocking ID wrap.
func (s *udpSession) rememberPacket(id uint16, now time.Time) {
	if s.recent == nil {
		s.recent = make(map[uint16]time.Time)
	}
	index := s.recentNext
	oldID, oldTime := s.recentIDs[index], s.recentTimes[index]
	if oldTime == s.recent[oldID] {
		delete(s.recent, oldID)
	}
	s.recentIDs[index], s.recentTimes[index] = id, now
	s.recent[id] = now
	s.recentNext++
}

// sweep closes associations idle for longer than the configured timeout.
func (c *client) sweep(now time.Time) {
	timeout := c.srv.udpIdle()
	c.mu.Lock()
	var stale []*udpSession
	for id, s := range c.sessions {
		if now.Sub(time.Unix(0, s.seen.Load())) > timeout {
			delete(c.sessions, id)
			stale = append(stale, s)
		}
	}
	c.mu.Unlock()
	for _, s := range stale {
		_ = s.Close()
	}
}

// sweepLoop drives sweep.
func (c *client) sweepLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-t.C:
			c.sweep(now)
		}
	}
}

// closeAll closes every association of a finished connection.
func (c *client) closeAll() {
	c.mu.Lock()
	sessions := c.sessions
	c.sessions = make(map[uint16]*udpSession)
	c.mu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
}
