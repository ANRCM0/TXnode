package mieru

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// The native packet framing remains address || payload inside a segment.
// The common core relay owns all destination sockets, routing and accounting.
const udpPeerTTL = 2 * time.Minute

func (h *Handler) SetRelay(relay func(context.Context, *core.Session) error) { h.packetRelay = relay }
func (h *Handler) SetCurrent(current func() *Handler)                        { h.packetCurrent.Store(&current) }
func (h *Handler) currentPacketHandler() *Handler {
	if fn := h.packetCurrent.Load(); fn != nil && *fn != nil {
		return (*fn)()
	}
	return h
}
func (h *Handler) ClosePackets() {
	if srv := h.packetServer.Load(); srv != nil {
		srv.closePeers()
	}
}

func (h *Handler) ListenUDP(pc net.PacketConn) error { return h.ServePackets(context.Background(), pc) }

func (h *Handler) ServePackets(ctx context.Context, pc net.PacketConn) error {
	if h.packetRelay == nil {
		return errors.New("mieru: UDP relay is not configured")
	}
	srv := &udpServer{owner: h, pc: pc, ctx: ctx, peers: make(map[string]*udpPeer), v2Peers: make(map[string]*v2DatagramConn)}
	h.packetServer.Store(srv)
	defer h.packetServer.CompareAndSwap(srv, nil)
	defer srv.closePeers()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = pc.Close()
		case <-done:
		}
	}()
	go srv.sweep(done)
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		srv.handle(addr, buf[:n])
	}
}

type udpServer struct {
	owner           *Handler
	active          *Handler
	ctx             context.Context
	pc              net.PacketConn
	mu              sync.Mutex
	peers           map[string]*udpPeer
	v2Peers         map[string]*v2DatagramConn
	retransmissions atomic.Uint64
	duplicates      atomic.Uint64
	dropped         atomic.Uint64
}

func (s *udpServer) handle(addr net.Addr, seg []byte) {
	handler := s.owner.currentPacketHandler()
	if handler != s.active {
		s.closePeers()
		s.active = handler
	}
	if handler == nil {
		return
	}
	handler.packetServer.Store(s)
	if s.handleV2(handler, addr, seg) {
		return
	}
	cipher, parsed, entry, err := handler.identify(seg)
	if err != nil || !withinWindow(parsed.ts) || entry.user.ID <= 0 {
		return
	}
	key := fmt.Sprintf("%s/%d/%x", addr.String(), entry.user.ID, entry.key)
	s.mu.Lock()
	peer := s.peers[key]
	s.mu.Unlock()
	fingerprint := packetReplayID(seg)
	fresh := handler.checkPacketReplay(seg)
	if !fresh {
		if peer == nil {
			return
		}
		if _, samePeer := peer.received[fingerprint]; !samePeer {
			return
		}
	}
	if parsed.flags&flagAck != 0 {
		if peer != nil && len(parsed.payload) >= 4 {
			if len(peer.received) < 4096 {
				peer.received[fingerprint] = struct{}{}
			}
			peer.ps.acked(binary.BigEndian.Uint32(parsed.payload[:4]))
		}
		return
	}
	if parsed.code != segPacket {
		return
	}
	dest, n, err := decodeAddr(parsed.payload)
	if err != nil {
		return
	}
	if peer != nil && peer.dest != dest {
		if !fresh {
			return
		}
		_ = peer.Close()
		peer = nil
	}
	if peer == nil {
		s.mu.Lock()
		full := len(s.peers)+len(s.v2Peers) >= v2MaxPeers
		s.mu.Unlock()
		if full {
			s.dropped.Add(1)
			return
		}
		ctx, cancel := context.WithCancel(s.ctx)
		peer = &udpPeer{srv: s, key: key, client: addr, cipher: cipher, dest: dest, ctx: ctx, cancel: cancel, done: make(chan struct{}), received: make(map[uint64]struct{})}
		peer.ps = NewPacketSession(peer.send)
		peer.ps.setNext(parsed.seq)
		s.mu.Lock()
		s.peers[key] = peer
		s.mu.Unlock()
		go func() {
			defer peer.Close()
			_ = handler.packetRelay(ctx, &core.Session{UserID: entry.user.ID, Packets: peer, SourceIP: socks.FromNetAddr(addr).IP(), AuthValid: func() bool { return s.owner.currentPacketHandler() == handler }})
		}()
	}
	peer.lastSeen.Store(time.Now().UnixNano())
	if len(peer.received) < 4096 {
		peer.received[fingerprint] = struct{}{}
	}
	peer.ps.mu.Lock()
	inWindow := parsed.seq <= peer.ps.nextSeq+reorderWindow
	peer.ps.mu.Unlock()
	peer.ps.Input(parsed.seq, parsed.payload[n:])
	if inWindow {
		var ack [4]byte
		binary.BigEndian.PutUint32(ack[:], parsed.seq)
		_ = peer.send(peer.cipher.sealWithFlags(segPacket, flagAck, uint32(time.Now().Unix()), parsed.seq, ack[:]))
	}
}

// Packet fingerprints retain replay protection when credential snapshots replace
// the ordered per-peer PacketSession. The cache is shared with the prior handler.
func packetReplayID(seg []byte) uint64 {
	sum := sha256.Sum256(seg)
	return binary.BigEndian.Uint64(sum[:8])
}

func (h *Handler) checkPacketReplay(seg []byte) bool {
	return h.rememberReplay(packetReplayID(seg))
}

type udpPeer struct {
	srv      *udpServer
	key      string
	client   net.Addr
	cipher   *segmentCipher
	dest     socks.Addr
	ps       *PacketSession
	ctx      context.Context
	cancel   context.CancelFunc
	once     sync.Once
	writeMu  sync.Mutex
	done     chan struct{}
	lastSeen atomic.Int64
	received map[uint64]struct{}
}

func (p *udpPeer) send(seg []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	n, err := p.srv.pc.WriteTo(seg, p.client)
	if err == nil && n != len(seg) {
		err = io.ErrShortWrite
	}
	return err
}

func (p *udpPeer) RemoteAddr() net.Addr { return p.client }
func (p *udpPeer) ReadPacket(buf []byte) (int, socks.Addr, error) {
	select {
	case <-p.done:
		return 0, socks.Addr{}, net.ErrClosed
	default:
	}
	n, err := p.ps.Read(buf)
	select {
	case <-p.done:
		return 0, socks.Addr{}, net.ErrClosed
	default:
	}
	return n, p.dest, err
}
func (p *udpPeer) WritePacket(buf []byte, dest socks.Addr) error {
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	payload := append(encodeAddr(dest), buf...)
	err := p.ps.Write(func(seq uint32) []byte { return p.cipher.seal(segPacket, uint32(time.Now().Unix()), seq, payload) })
	if err == nil {
		p.lastSeen.Store(time.Now().UnixNano())
	}
	return err
}
func (p *udpPeer) Close() error {
	p.once.Do(func() {
		p.cancel()
		p.writeMu.Lock()
		close(p.done)
		p.writeMu.Unlock()
		_ = p.ps.Close()
		p.srv.mu.Lock()
		if p.srv.peers[p.key] == p {
			delete(p.srv.peers, p.key)
		}
		p.srv.mu.Unlock()
	})
	return nil
}
func (s *udpServer) closePeers() {
	s.mu.Lock()
	list := make([]*udpPeer, 0, len(s.peers))
	for _, p := range s.peers {
		list = append(list, p)
	}
	v2List := make([]*v2DatagramConn, 0, len(s.v2Peers))
	for _, p := range s.v2Peers {
		v2List = append(v2List, p)
	}
	s.mu.Unlock()
	for _, p := range list {
		_ = p.Close()
	}
	for _, p := range v2List {
		p.abort(net.ErrClosed)
	}
}
func (s *udpServer) sweep(done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			list := make([]*udpPeer, 0, len(s.peers))
			for _, p := range s.peers {
				if time.Since(time.Unix(0, p.lastSeen.Load())) > udpPeerTTL {
					list = append(list, p)
				}
			}
			s.mu.Unlock()
			for _, p := range list {
				_ = p.Close()
			}
		}
	}
}

var _ core.PacketStream = (*udpPeer)(nil)
