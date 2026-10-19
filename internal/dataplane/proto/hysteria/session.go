package hysteria

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// UDP over QUIC datagrams.
//
// The sample carries UDP in QUIC datagrams (EnableDatagrams = 1 and the
// Hysteria-UDP: true header) and keeps a per-destination session table
// (udpSession @0xed9920: +0x00 UserID, +0x08 Dest, +0x20 Conn, +0x30 Packets,
// +0x40 Local, +0x58 Socket) with dispatcher functions dispatch @0xaa34e0,
// parseUDP @0xaa3f40, appendUDP @0xaa4220, readDatagrams @0xaa4400,
// makeRoom @0xaa4a20 and udpSession.{receive,enqueue,ReadPacket,WritePacket}
// (notes/rev-proto-udp.md §1.6).
//
// The report explicitly marks the datagram payload layout as unresolved
// (§7 item 12). The framing below is therefore kaze-replication defined and
// shared by both ends:
//
//	client -> server
//	  varint sessionID
//	  u8     flags: bit0 = fragmented, bit1 = carries a destination address
//	  [varint addrLen][addr]              when bit1 is set (first datagram)
//	  [u8 fragID][u8 fragTotal]           when bit0 is set
//	  payload
//
//	server -> client
//	  varint sessionID
//	  u8     flags: bit0 = fragmented
//	  [u8 fragID][u8 fragTotal]           when bit0 is set
//	  payload
//
// A session is created by the first datagram that carries an address and is
// dropped after udpIdleTimeout of silence.
const (
	// maxDatagramPayload is the payload budget per QUIC datagram. QUIC's floor
	// MTU is 1200 bytes; the framing overhead below is subtracted from it so a
	// datagram never exceeds the path MTU even before DPLPMTUD raises it.
	maxDatagramPayload = 1200
	// datagramOverhead reserves room for the varint id, flags, address and
	// fragmentation fields.
	datagramOverhead = 48
	// udpIdleTimeout is how long an idle session is kept. UNVERIFIED: the report
	// does not extract the sample's value; 60 s is upstream hysteria2's default.
	udpIdleTimeout = 60 * time.Second
	// maxUDPSessions bounds the per-connection session table (makeRoom evicts).
	maxUDPSessions = 1024
	// maxFragments bounds reassembly state per session.
	maxFragments = 0xff
)

const (
	flagFrag = 1 << 0
	flagNew  = 1 << 1
)

// udpSession is one destination association. Field names and order follow the
// recovered struct so the comments can cite offsets.
type udpSession struct {
	UserID  int64       // +0x00
	Dest    socks.Addr  // +0x08
	Conn    net.Conn    // +0x20
	Packets chan []byte // +0x30
	Local   netip.Addr  // +0x40
	Socket  *net.UDPConn

	id    uint64
	st    *connState
	seen  atomic.Int64 // unix nanoseconds of the last datagram
	once  sync.Once
	done  chan struct{}
	fragM sync.Mutex
	frags map[uint8]*fragSet
}

type fragSet struct {
	total uint8
	parts map[uint8][]byte
}

// enqueue hands a decoded payload to the relay (relay mode) without blocking the
// datagram loop.
func (s *udpSession) enqueue(p []byte) {
	select {
	case s.Packets <- p:
	default:
		// The relay is slower than the network; dropping is correct for UDP.
	}
}

// receive is the dest -> QUIC pump used when no relay is wired.
func (s *udpSession) receive() {
	buf := make([]byte, 64<<10)
	for {
		n, err := s.Conn.Read(buf)
		if err != nil {
			return
		}
		s.st.writeDatagram(s, buf[:n], false)
	}
}

// ReadPacket implements core.PacketStream for relay mode.
func (s *udpSession) ReadPacket(p []byte) (int, socks.Addr, error) {
	select {
	case <-s.done:
		return 0, socks.Addr{}, net.ErrClosed
	case b, ok := <-s.Packets:
		if !ok {
			return 0, socks.Addr{}, net.ErrClosed
		}
		n := copy(p, b)
		return n, s.Dest, nil
	}
}

// WritePacket implements core.PacketStream for relay mode.
func (s *udpSession) WritePacket(p []byte, addr socks.Addr) error {
	if addr != s.Dest {
		return errors.New("hysteria: packet for a different destination")
	}
	s.st.writeDatagram(s, p, false)
	return nil
}

// Close tears the session down.
func (s *udpSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		if s.Conn != nil {
			_ = s.Conn.Close()
		}
	})
	return nil
}

// startDatagramLoop starts the connection's datagram reader once auth succeeded
// (the sample's "go forward_loop()").
func (st *connState) startDatagramLoop() {
	st.datagrams.Do(func() {
		if st.conn == nil {
			// Unit tests drive the handler without a QUIC connection.
			return
		}
		ctx := st.conn.Context()
		go func() {
			for {
				p, err := st.conn.ReceiveDatagram(ctx)
				if err != nil {
					return
				}
				st.dispatch(p)
			}
		}()
	})
}

// dispatch routes one inbound datagram to its session.
func (st *connState) dispatch(p []byte) {
	if now := time.Now(); now.After(st.sweepAt) {
		st.sweepAt = now.Add(time.Second)
		st.sweep(now)
	}
	sid, n := binary.Uvarint(p)
	if n <= 0 || len(p) < n+1 {
		return
	}
	p = p[n:]
	flags := p[0]
	p = p[1:]

	var dest socks.Addr
	if flags&flagNew != 0 {
		addrLen, m := binary.Uvarint(p)
		if m <= 0 || int(addrLen) > len(p)-m || addrLen == 0 {
			return
		}
		var err error
		dest, err = decodeAddr(p[m : m+int(addrLen)])
		if err != nil {
			return
		}
		p = p[m+int(addrLen):]
	}
	var fragID, fragTotal uint8
	if flags&flagFrag != 0 {
		if len(p) < 2 {
			return
		}
		fragID, fragTotal = p[0], p[1]
		p = p[2:]
	}

	sess, err := st.session(sid, dest, flags&flagNew != 0)
	if err != nil || sess == nil {
		return
	}
	sess.seen.Store(time.Now().UnixNano())

	payload := p
	if flags&flagFrag != 0 {
		payload = sess.reassemble(fragID, fragTotal, p)
		if payload == nil {
			return
		}
	}
	if st.srv.opts.Relay != nil {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		sess.enqueue(cp)
		return
	}
	_, _ = sess.Conn.Write(payload)
}

// session returns (or creates) the session for sid. Creation needs an address;
// a datagram for an unknown session without one is dropped.
func (st *connState) session(sid uint64, dest socks.Addr, isNew bool) (*udpSession, error) {
	st.sessMu.Lock()
	defer st.sessMu.Unlock()
	if st.sessions == nil {
		st.sessions = make(map[uint64]*udpSession)
	}
	if s, ok := st.sessions[sid]; ok {
		return s, nil
	}
	if !isNew || dest.IsZero() {
		return nil, nil
	}
	if len(st.sessions) >= maxUDPSessions {
		st.makeRoom()
	}
	conn, err := dialUDP(dest)
	if err != nil {
		st.srv.log.Debug("hysteria: udp dial failed", "dest", dest.String(), "error", err)
		return nil, err
	}
	s := &udpSession{
		UserID:  int64(st.userIDValue()),
		Dest:    dest,
		Conn:    conn,
		Packets: make(chan []byte, 64),
		done:    make(chan struct{}),
		frags:   make(map[uint8]*fragSet),
		id:      sid,
		st:      st,
	}
	if ap := dest.AddrPort(); ap.IsValid() {
		s.Local = ap.Addr()
	}
	if udp, ok := conn.(*net.UDPConn); ok {
		s.Socket = udp
	}
	s.seen.Store(time.Now().UnixNano())
	st.sessions[sid] = s
	if st.srv.opts.Relay == nil {
		go s.receive()
	} else {
		go func() {
			sess := &core.Session{UserID: st.userIDValue(), Dest: dest, Conn: conn, Packets: s}
			if err := st.srv.opts.Relay(st.conn.Context(), sess); err != nil {
				st.srv.log.Debug("hysteria: udp relay finished", "error", err)
			}
			_ = s.Close()
			st.dropSession(sid)
		}()
	}
	return s, nil
}

// dropSession removes a session from the table.
func (st *connState) dropSession(sid uint64) {
	st.sessMu.Lock()
	if s, ok := st.sessions[sid]; ok {
		delete(st.sessions, sid)
		_ = s.Conn.Close()
	}
	st.sessMu.Unlock()
}

// makeRoom evicts the least recently used session. Evidence: makeRoom @0xaa4a20.
func (st *connState) makeRoom() {
	var oldest *udpSession
	for _, s := range st.sessions {
		if oldest == nil || s.seen.Load() < oldest.seen.Load() {
			oldest = s
		}
	}
	if oldest != nil {
		delete(st.sessions, oldest.id)
		_ = oldest.Close()
	}
}

// sweep closes sessions idle for longer than udpIdleTimeout.
func (st *connState) sweep(now time.Time) {
	cutoff := now.Add(-udpIdleTimeout).UnixNano()
	st.sessMu.Lock()
	for id, s := range st.sessions {
		if s.seen.Load() < cutoff {
			delete(st.sessions, id)
			_ = s.Close()
		}
	}
	st.sessMu.Unlock()
}

// closeSessions tears down every session of a finished connection.
func (st *connState) closeSessions() {
	st.sessMu.Lock()
	sessions := st.sessions
	st.sessions = nil
	st.sessMu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
}

// reassemble stores a fragment and returns the payload once all of them arrived.
func (s *udpSession) reassemble(id, total uint8, part []byte) []byte {
	if total == 0 || total > maxFragments || id >= total {
		return nil
	}
	s.fragM.Lock()
	defer s.fragM.Unlock()
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

// writeDatagram sends payload, fragmenting it when the framing exceeds the
// datagram budget.
func (st *connState) writeDatagram(sess *udpSession, payload []byte, withAddr bool) {
	var addr []byte
	if withAddr {
		addr = encodeAddr(sess.Dest)
	}
	max := maxDatagramPayload - datagramOverhead - len(addr)
	if max <= 0 {
		max = 64
	}
	if len(payload) <= max {
		st.sendDatagram(buildDatagram(sess.id, withAddr, addr, 0, 0, false, payload))
		return
	}
	total := (len(payload) + max - 1) / max
	if total > maxFragments {
		// Cannot fragment further: send what the protocol allows and let the
		// destination see a truncated datagram rather than silently dropping it.
		total = maxFragments
	}
	for i := 0; i < total; i++ {
		chunk := payload[i*max:]
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		st.sendDatagram(buildDatagram(sess.id, withAddr && i == 0, addr, uint8(i), uint8(total), true, chunk))
	}
}

// buildDatagram serialises the framing described in the file comment.
func buildDatagram(sid uint64, withAddr bool, addr []byte, fragID, fragTotal uint8, frag bool, payload []byte) []byte {
	buf := make([]byte, 0, binary.MaxVarintLen64+1+binary.MaxVarintLen64+len(addr)+2+len(payload))
	buf = binary.AppendUvarint(buf, sid)
	var flags byte
	if frag {
		flags |= flagFrag
	}
	if withAddr {
		flags |= flagNew
	}
	buf = append(buf, flags)
	if withAddr {
		buf = binary.AppendUvarint(buf, uint64(len(addr)))
		buf = append(buf, addr...)
	}
	if frag {
		buf = append(buf, fragID, fragTotal)
	}
	buf = append(buf, payload...)
	return buf
}

func (st *connState) sendDatagram(p []byte) {
	if err := st.conn.SendDatagram(p); err != nil {
		st.srv.log.Debug("hysteria: datagram send failed", "error", err)
	}
}

// dialUDP opens the per-destination UDP socket.
func dialUDP(dest socks.Addr) (net.Conn, error) {
	raddr, err := net.ResolveUDPAddr("udp", dest.String())
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, raddr)
}
