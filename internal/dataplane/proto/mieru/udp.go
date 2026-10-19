package mieru

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// UDP transport. Evidence: ListenUDP @0x7e6ae0 plus
// UDPServer.{read,handle,identify,scanner,opened,dispatch@0x7e82c0,open,
// write,sweep} and NewPacketSession @0x7e0700 (notes/rev-proto-udp.md §3.4).
// Each peer address owns one virtual connection (a PacketSession) and one
// destination socket; (UDPServer).sweep reclaims idle peers.
//
// UNVERIFIED: the datagram body's address/data split is our own framing (the
// sample's was not decoded). It is: payload = address || datagram, where address
// is the SOCKS5-style encoding from segment.go.

// udpPeerTTL is how long an idle UDP peer is kept.
const udpPeerTTL = 2 * time.Minute

type udpPeer struct {
	ps       *PacketSession
	cipher   *segmentCipher
	entry    *keyEntry
	dest     socks.Addr
	conn     net.Conn
	lastSeen atomic.Int64
}

// ListenUDP serves the packet transport on an already bound socket.
func (h *Handler) ListenUDP(pc net.PacketConn) error {
	h.udpMu.Lock()
	if h.peers == nil {
		h.peers = make(map[string]*udpPeer)
	}
	h.udpMu.Unlock()

	go h.sweepLoop()
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		seg := make([]byte, n)
		copy(seg, buf[:n])
		h.handleDatagram(pc, addr, seg)
	}
}

// ServePackets satisfies core.PacketHandler; the node passes the socket.
func (h *Handler) ServePackets(ctx context.Context, pc net.PacketConn) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = pc.Close()
		case <-done:
		}
	}()
	err := h.ListenUDP(pc)
	close(done)
	return err
}

// handleDatagram identifies one inbound segment and routes it.
func (h *Handler) handleDatagram(pc net.PacketConn, addr net.Addr, seg []byte) {
	cipher, parsed, entry, err := h.identify(seg)
	if err != nil {
		return
	}
	if !withinWindow(parsed.ts) {
		return
	}
	key := addr.String()
	h.udpMu.Lock()
	peer := h.peers[key]
	h.udpMu.Unlock()

	if peer == nil {
		if parsed.code != segPacket || len(parsed.payload) == 0 {
			return
		}
		peer, err = h.openPeer(pc, addr, cipher, entry, parsed)
		if err != nil {
			h.log.Debug("mieru: udp dial failed", "error", err)
			return
		}
	}
	peer.lastSeen.Store(time.Now().UnixNano())

	if parsed.flags&flagAck != 0 {
		if len(parsed.payload) >= 4 {
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
	if dest != peer.dest {
		// A peer that switches destination is a new association.
		h.dropPeer(addr.String())
		return
	}
	peer.ps.Input(parsed.seq, parsed.payload[n:])
}

// openPeer dials a destination and starts the two pumps.
func (h *Handler) openPeer(pc net.PacketConn, addr net.Addr, cipher *segmentCipher, entry *keyEntry, first *parsedSegment) (*udpPeer, error) {
	dest, n, err := decodeAddr(first.payload)
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", dest.String())
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	peer := &udpPeer{
		cipher: cipher,
		entry:  entry,
		dest:   dest,
		conn:   conn,
	}
	peer.lastSeen.Store(time.Now().UnixNano())
	addrPrefix := encodeAddr(dest)
	peer.ps = NewPacketSession(func(seg []byte) error {
		_, err := pc.WriteTo(seg, addr)
		return err
	})
	// Inbound: session -> destination socket.
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := peer.ps.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	// Outbound: destination socket -> session (address-prefixed payload).
	go func() {
		buf := make([]byte, 64<<10)
		var seq uint32
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			payload := make([]byte, 0, len(addrPrefix)+n)
			payload = append(payload, addrPrefix...)
			payload = append(payload, buf[:n]...)
			s := seq
			seq++
			if err := peer.ps.Write(func(seq uint32) []byte {
				return cipher.seal(segPacket, uint32(time.Now().Unix()), s, payload)
			}); err != nil {
				return
			}
		}
	}()
	// Drop the first payload's address prefix before delivering it.
	h.udpMu.Lock()
	h.peers[addr.String()] = peer
	h.udpMu.Unlock()
	peer.ps.setNext(first.seq)
	peer.ps.Input(first.seq, first.payload[n:])
	return peer, nil
}

// dropPeer removes and closes one peer.
func (h *Handler) dropPeer(key string) {
	h.udpMu.Lock()
	peer := h.peers[key]
	delete(h.peers, key)
	h.udpMu.Unlock()
	if peer != nil {
		_ = peer.ps.Close()
		_ = peer.conn.Close()
	}
}

// sweepLoop removes idle peers (UDPServer.sweep).
func (h *Handler) sweepLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-udpPeerTTL).UnixNano()
		h.udpMu.Lock()
		var stale []string
		for k, p := range h.peers {
			if p.lastSeen.Load() < cutoff {
				stale = append(stale, k)
			}
		}
		h.udpMu.Unlock()
		for _, k := range stale {
			h.dropPeer(k)
		}
	}
}
