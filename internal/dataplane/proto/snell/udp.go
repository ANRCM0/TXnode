package snell

import (
	"net"
	"sync"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// packets is the UDP-over-TCP packet stream of a v3 session. Evidence: the
// binary has (*packets).{ReadPacket,WritePacket,Close} and UDP is only offered
// on version 3 (notes/rev-proto-udp.md §4.6; string "clients: version 3 for
// UDP"). The per-packet chunk layout (address || datagram) is our framing
// (notes §7 item 9 leaves the sample's layout unresolved).
type packets struct {
	coder *chunkCoder

	mu     sync.Mutex
	closed bool
}

var _ interface {
	ReadPacket([]byte) (int, socks.Addr, error)
	WritePacket([]byte, socks.Addr) error
	Close() error
} = (*packets)(nil)

// ReadPacket returns one datagram and its destination address.
func (p *packets) ReadPacket(b []byte) (int, socks.Addr, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return 0, socks.Addr{}, net.ErrClosed
	}
	chunk, err := p.coder.ReadChunk()
	if err != nil {
		return 0, socks.Addr{}, err
	}
	addr, n, err := decodeAddr(chunk)
	if err != nil {
		return 0, socks.Addr{}, err
	}
	payload := chunk[n:]
	if len(payload) > len(b) {
		return 0, socks.Addr{}, ErrChunkTooLarge
	}
	copy(b, payload)
	return len(payload), addr, nil
}

// WritePacket sends one datagram to addr.
func (p *packets) WritePacket(b []byte, addr socks.Addr) error {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	enc := encodeAddr(addr)
	chunk := make([]byte, 0, len(enc)+len(b))
	chunk = append(chunk, enc...)
	chunk = append(chunk, b...)
	return p.coder.WriteChunk(chunk)
}

// Close marks the packet stream closed.
func (p *packets) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}
