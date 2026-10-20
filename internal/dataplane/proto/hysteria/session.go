package hysteria

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go/quicvarint"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// UDP over QUIC datagrams.
//
// The wire format is upstream hysteria2's UDPMessage
// (core/internal/protocol/proxy.go):
//
//	u32 SessionID | u16 PacketID | u8 FragID | u8 FragCount |
//	varint addrLen | "host:port" | data
//
// The server answers with the same shape; the address is the UDP source of the
// reply and FragCount is 1 unless the payload was split.
const (
	// maxDatagramPayload is the QUIC datagram budget (floor MTU 1200).
	maxDatagramPayload = 1200
	// datagramOverhead reserves the fixed fields plus address and varint.
	datagramOverhead = 64
	// udpIdleTimeout is how long an idle session is kept (upstream default).
	udpIdleTimeout = 60 * time.Second
	// maxUDPSessions bounds the per-connection session table (makeRoom evicts).
	maxUDPSessions = 1024
	// maxFragments bounds one fragmented message.
	maxFragments = 0xff
)

// udpMessage is protocol.UDPMessage.
type udpMessage struct {
	SessionID uint32
	PacketID  uint16
	FragID    uint8
	FragCount uint8
	Addr      string
	Data      []byte
}

func parseUDPMessage(p []byte) (*udpMessage, error) {
	if len(p) < 8 {
		return nil, errors.New("hysteria: short udp message")
	}
	m := &udpMessage{
		SessionID: binary.BigEndian.Uint32(p[0:4]),
		PacketID:  binary.BigEndian.Uint16(p[4:6]),
		FragID:    p[6],
		FragCount: p[7],
	}
	rest := p[8:]
	l, n, err := quicvarint.Parse(rest)
	if err != nil || n <= 0 || l == 0 || l > 2048 || int(l) > len(rest)-n {
		return nil, errors.New("hysteria: invalid udp address")
	}
	m.Addr = string(rest[n : n+int(l)])
	m.Data = rest[n+int(l):]
	return m, nil
}

func (m *udpMessage) marshal() []byte {
	buf := make([]byte, 8, 8+quicvarint.Len(uint64(len(m.Addr)))+len(m.Addr)+len(m.Data))
	binary.BigEndian.PutUint32(buf[0:4], m.SessionID)
	binary.BigEndian.PutUint16(buf[4:6], m.PacketID)
	buf[6] = m.FragID
	buf[7] = m.FragCount
	buf = quicvarint.Append(buf, uint64(len(m.Addr)))
	buf = append(buf, m.Addr...)
	buf = append(buf, m.Data...)
	return buf
}

func parseUDPAddr(s string) (socks.Addr, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return socks.Addr{}, fmt.Errorf("hysteria: udp address %q: %w", s, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return socks.Addr{}, fmt.Errorf("hysteria: udp port %q", portStr)
	}
	return socks.Addr{Host: host, Port: uint16(port)}, nil
}

type udpPacket struct {
	addr socks.Addr
	data []byte
}

// udpSession is one hysteria UDP session (SessionID key).
type udpSession struct {
	UserID  int64
	Dest    socks.Addr
	Conn    net.Conn // destination socket; nil in relay mode (core dials)
	Packets chan udpPacket
	Local   netip.Addr
	Socket  *net.UDPConn

	id    uint32
	st    *connState
	seen  atomic.Int64
	once  sync.Once
	done  chan struct{}
	fragM sync.Mutex
	frags map[uint16]*fragSet
}

type fragSet struct {
	total uint8
	parts map[uint8][]byte
}

func (s *udpSession) enqueue(addr socks.Addr, p []byte) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case s.Packets <- udpPacket{addr: addr, data: cp}:
	default:
		// The relay is slower than the network; dropping is correct for UDP.
	}
}

// receive is the destination -> QUIC pump used when no relay is wired.
func (s *udpSession) receive() {
	buf := make([]byte, 64<<10)
	for {
		n, err := s.Conn.Read(buf)
		if err != nil {
			return
		}
		s.st.sendUDPMessage(s.id, s.Dest.String(), buf[:n])
	}
}

// ReadPacket implements core.PacketStream for relay mode.
func (s *udpSession) ReadPacket(p []byte) (int, socks.Addr, error) {
	select {
	case <-s.done:
		return 0, socks.Addr{}, net.ErrClosed
	case pkt, ok := <-s.Packets:
		if !ok {
			return 0, socks.Addr{}, net.ErrClosed
		}
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	}
}

// WritePacket sends one response datagram back to the client.
func (s *udpSession) WritePacket(p []byte, addr socks.Addr) error {
	if addr.IsZero() {
		addr = s.Dest
	}
	s.st.sendUDPMessage(s.id, addr.String(), p)
	return nil
}

func (s *udpSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		if s.Conn != nil {
			_ = s.Conn.Close()
		}
	})
	return nil
}

// startDatagramLoop starts the QUIC datagram reader once per connection.
func (st *connState) startDatagramLoop() {
	st.datagrams.Do(func() {
		if st.conn == nil {
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
	m, err := parseUDPMessage(p)
	if err != nil {
		return
	}
	dest, err := parseUDPAddr(m.Addr)
	if err != nil {
		return
	}
	sess, err := st.session(m.SessionID, dest)
	if err != nil || sess == nil {
		return
	}
	sess.seen.Store(time.Now().UnixNano())
	payload := m.Data
	if m.FragCount > 1 {
		payload = sess.reassemble(m.PacketID, m.FragID, m.FragCount, m.Data)
		if payload == nil {
			return
		}
	}
	if st.srv.opts.Relay != nil {
		sess.enqueue(dest, payload)
		return
	}
	if sess.Conn != nil {
		_, _ = sess.Conn.Write(payload)
	}
}

func (st *connState) session(sid uint32, dest socks.Addr) (*udpSession, error) {
	st.sessMu.Lock()
	defer st.sessMu.Unlock()
	if st.sessions == nil {
		st.sessions = make(map[uint32]*udpSession)
	}
	if s, ok := st.sessions[sid]; ok {
		return s, nil
	}
	if dest.IsZero() {
		return nil, nil
	}
	if len(st.sessions) >= maxUDPSessions {
		st.makeRoom()
	}
	var conn net.Conn
	var err error
	if st.srv.opts.Relay == nil {
		conn, err = dialUDP(dest)
		if err != nil {
			st.srv.log.Debug("hysteria: udp dial failed", "dest", dest.String(), "error", err)
			return nil, err
		}
	}
	s := &udpSession{
		UserID:  int64(st.userIDValue()),
		Dest:    dest,
		Conn:    conn,
		Packets: make(chan udpPacket, 64),
		done:    make(chan struct{}),
		frags:   make(map[uint16]*fragSet),
		id:      sid,
		st:      st,
	}
	if conn != nil {
		if ap := dest.AddrPort(); ap.IsValid() {
			s.Local = ap.Addr()
		}
		if udp, ok := conn.(*net.UDPConn); ok {
			s.Socket = udp
		}
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

func (st *connState) dropSession(sid uint32) {
	st.sessMu.Lock()
	if s, ok := st.sessions[sid]; ok {
		delete(st.sessions, sid)
		_ = s.Close()
	}
	st.sessMu.Unlock()
}

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

func (st *connState) closeSessions() {
	st.sessMu.Lock()
	sessions := st.sessions
	st.sessions = nil
	st.sessMu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
}

// reassemble stores a fragment and returns the payload once all arrived. The
// PacketID keys the fragment set (upstream frag.Defragger).
func (s *udpSession) reassemble(packetID uint16, id, total uint8, part []byte) []byte {
	if total == 0 || total > maxFragments || id >= total {
		return nil
	}
	s.fragM.Lock()
	defer s.fragM.Unlock()
	set := s.frags[packetID]
	if set == nil {
		set = &fragSet{total: total, parts: make(map[uint8][]byte)}
		s.frags[packetID] = set
	}
	if set.total != total {
		delete(s.frags, packetID)
		return nil
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
	delete(s.frags, packetID)
	return out
}

// sendUDPMessage serialises one response, fragmenting when it exceeds the
// datagram budget.
func (st *connState) sendUDPMessage(sid uint32, addr string, payload []byte) {
	max := maxDatagramPayload - datagramOverhead - len(addr) - quicvarint.Len(uint64(len(addr)))
	if max < 64 {
		max = 64
	}
	if len(payload) <= max {
		st.sendDatagram((&udpMessage{SessionID: sid, FragCount: 1, Addr: addr, Data: payload}).marshal())
		return
	}
	total := (len(payload) + max - 1) / max
	if total > maxFragments {
		total = maxFragments
	}
	for i := 0; i < total; i++ {
		chunk := payload[i*max:]
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		st.sendDatagram((&udpMessage{
			SessionID: sid, FragID: uint8(i), FragCount: uint8(total), Addr: addr, Data: chunk,
		}).marshal())
	}
}

func (st *connState) sendDatagram(p []byte) {
	if err := st.conn.SendDatagram(p); err != nil {
		st.srv.log.Debug("hysteria: datagram send failed", "error", err)
	}
}

func dialUDP(dest socks.Addr) (net.Conn, error) {
	raddr, err := net.ResolveUDPAddr("udp", dest.String())
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, raddr)
}
