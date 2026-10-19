package mux

// UDP over mux.
//
// Framing recovered from (*Packets).ReadPacket @0x7764a0 and WritePacket
// @0x7767a0:
//
//	[LEN BE16][socks address][payload]
//
// LEN covers the address and the payload (WritePacket rejects anything above
// 0xffff), the address is the same encoding mux stream requests use
// (socks.AppendAddr / socks.ReadAddr), and each side keeps its own 300 s read
// deadline.
//
// UNVERIFIED: how the peer marks a stream as UDP (readStreamRequest exposes a
// boolean at +0x60 that the sample consults before dispatching to Packets); this
// package exposes Packets for the caller that owns that decision.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/pool"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

const (
	packetsIdle    = 300 * time.Second
	packetsMaxSize = 0xffff
)

// Packets adapts one mux stream to core.PacketStream.
type Packets struct {
	c  net.Conn
	mu sync.Mutex
}

// NewPackets wraps a mux stream.
func NewPackets(c net.Conn) *Packets { return &Packets{c: c} }

// ReadPacket reads one datagram and its destination address.
func (p *Packets) ReadPacket(buf []byte) (int, socks.Addr, error) {
	_ = p.c.SetReadDeadline(time.Now().Add(packetsIdle))
	var hdr [2]byte
	if _, err := io.ReadFull(p.c, hdr[:]); err != nil {
		return 0, socks.Addr{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	body := pool.Get(n)
	defer pool.Put(body)
	if _, err := io.ReadFull(p.c, body); err != nil {
		return 0, socks.Addr{}, err
	}
	br := bytes.NewReader(body)
	addr, err := ReadAddr(br)
	if err != nil {
		return 0, socks.Addr{}, err
	}
	data := body[len(body)-br.Len():]
	if len(data) > len(buf) {
		data = data[:len(buf)]
	}
	copy(buf, data)
	return len(data), addr, nil
}

// WritePacket writes one datagram to addr.
func (p *Packets) WritePacket(data []byte, addr socks.Addr) error {
	head := AppendAddr(nil, addr)
	if len(head)+len(data) > packetsMaxSize {
		return errors.New("mux: UDP packet is too large")
	}
	frame := make([]byte, 2, 2+len(head)+len(data))
	binary.BigEndian.PutUint16(frame, uint16(len(head)+len(data)))
	frame = append(frame, head...)
	frame = append(frame, data...)
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.c.Write(frame)
	return err
}

// Close closes the underlying stream.
func (p *Packets) Close() error { return p.c.Close() }
