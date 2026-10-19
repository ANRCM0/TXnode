package tuic

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// udpSession is one UDP association, keyed by assocID in client+0x38
// (map[uint16]*udpSession, notes/rev-proto-udp.md §2.2).
type udpSession struct {
	id     uint16
	c      *client
	dest   socks.Addr
	socket net.Conn
	pktID  atomic.Uint32
	once   sync.Once
	done   chan struct{}
	seen   atomic.Int64

	fragMu sync.Mutex
	frags  map[uint8]*fragSet
}

type fragSet struct {
	total uint8
	parts map[uint8][]byte
}

func (s *udpSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		if s.socket != nil {
			_ = s.socket.Close()
		}
	})
	return nil
}

// deliverPacket routes one inbound packet frame to its association.
func (c *client) deliverPacket(f *frame) {
	c.mu.Lock()
	sess := c.sessions[f.assocID]
	c.mu.Unlock()

	if sess == nil {
		if !f.hasAddr || f.addr.IsZero() {
			// No association and no address to create one from.
			return
		}
		var err error
		sess, err = c.openSession(f.assocID, f.addr)
		if err != nil {
			c.srv.log.Debug("tuic: udp dial failed", "dest", f.addr.String(), "error", err)
			return
		}
	}
	sess.seen.Store(time.Now().UnixNano())

	payload := f.payload
	if f.fragTotal > 0 {
		payload = sess.reassemble(f.fragID, f.fragTotal, f.payload)
		if payload == nil {
			return
		}
	}
	_, _ = sess.socket.Write(payload)
}

// openSession dials the destination and starts the return pump.
func (c *client) openSession(id uint16, dest socks.Addr) (*udpSession, error) {
	raddr, err := net.ResolveUDPAddr("udp", dest.String())
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	s := &udpSession{
		id:     id,
		c:      c,
		dest:   dest,
		socket: conn,
		done:   make(chan struct{}),
		frags:  make(map[uint8]*fragSet),
	}
	s.seen.Store(time.Now().UnixNano())
	c.mu.Lock()
	if old := c.sessions[id]; old != nil {
		c.mu.Unlock()
		_ = old.Close()
		c.mu.Lock()
	}
	c.sessions[id] = s
	c.mu.Unlock()
	go s.pump()
	return s, nil
}

// pump reads datagrams from the destination and writes them back to the client.
func (s *udpSession) pump() {
	buf := make([]byte, 64<<10)
	for {
		n, err := s.socket.Read(buf)
		if err != nil {
			return
		}
		s.writePacket(buf[:n])
	}
}

// writePacket implements (*udpSession).WritePacket @0xb44c60:
//
//	SendDatagram(frame); on DatagramTooLargeError split by (errLen - 0x1d) and
//	send the fragments as datagrams; on any other error fall back to a
//	unidirectional stream with a 10 s write deadline.
func (s *udpSession) writePacket(payload []byte) {
	base := &frame{
		assocID: s.id,
		pktID:   uint16(s.pktID.Add(1)),
		// The server -> client frames of a session established by the client
		// need no address; the report's frame() writes 0xff in that case
		// (0xb44b8f).
		hasAddr: false,
		payload: payload,
	}
	first := base.marshal()
	err := s.c.conn.SendDatagram(first)
	if err == nil {
		return
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		chunk := fragChunkSize(int(tooLarge.MaxDatagramPayloadSize))
		for _, f := range fragment(base, payload, chunk) {
			if e := s.c.conn.SendDatagram(f.marshal()); e != nil {
				s.c.srv.log.Debug("tuic: fragmented datagram failed", "error", e)
			}
		}
		return
	}
	// DATAGRAM is not usable on this connection: fall back to uni streams, one
	// frame per stream.
	for _, f := range fragment(base, payload, 0xffff-fragOverhead) {
		s.writeStream(f)
	}
}

// writeStream writes one frame on a fresh unidirectional stream.
func (s *udpSession) writeStream(f *frame) {
	st, err := s.c.conn.OpenUniStream()
	if err != nil {
		return
	}
	_ = st.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := st.WriteWithLimit(f.marshal(), nil); err != nil {
		st.CancelWrite(quic.StreamErrorCode(0))
		return
	}
	_ = st.Close()
}

// reassemble stores a fragment and returns the payload once all arrived.
func (s *udpSession) reassemble(id, total uint8, part []byte) []byte {
	if total == 0 || id >= total {
		return nil
	}
	s.fragMu.Lock()
	defer s.fragMu.Unlock()
	set := s.frags[total]
	if set == nil {
		set = &fragSet{total: total, parts: make(map[uint8][]byte)}
		s.frags[total] = set
	}
	cp := make([]byte, len(part))
	copy(cp, part)
	set.parts[id] = cp
	if len(set.parts) < int(total) {
		return nil
	}
	var out []byte
	for i := uint8(0); i < total; i++ {
		out = append(out, set.parts[i]...)
	}
	delete(s.frags, total)
	return out
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
