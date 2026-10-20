package mux

// Wire reference: sing-box v1.14.3 pins sing-mux caf09fe32475.
// Fixed-target UDP: [payload length BE16][payload]; packet-address UDP:
// [SOCKS address][payload length BE16][payload]. The first server reply
// starts with stream status, outside the datagram length.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

const (
	packetsIdle    = 300 * time.Second
	packetsMaxSize = 0xffff
)

// Packets strips framing before the core relay meters application datagrams.
type Packets struct {
	c               net.Conn
	dest            socks.Addr
	packetAddr      bool
	server          bool
	responseRead    bool
	responseWritten bool
	readMu          sync.Mutex
	writeMu         sync.Mutex
}

// NewPackets wraps packet-address framing without a stream response exchange.
// Callers serving a client request must use NewServerPackets instead.
func NewPackets(c net.Conn) *Packets {
	return &Packets{c: c, packetAddr: true, responseRead: true, responseWritten: true}
}

// NewServerPackets accepts the UDP mode selected by the stream flags.
func NewServerPackets(c net.Conn, flags uint16, dest socks.Addr) *Packets {
	return &Packets{c: c, dest: dest, packetAddr: flags&FlagAddr != 0, server: true, responseRead: true}
}

func newClientPackets(c net.Conn, flags uint16, dest socks.Addr) *Packets {
	return &Packets{c: c, dest: dest, packetAddr: flags&FlagAddr != 0, responseWritten: true}
}

func (p *Packets) ReadPacket(buf []byte) (int, socks.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	_ = p.c.SetReadDeadline(time.Now().Add(packetsIdle))
	if !p.responseRead {
		if err := readStreamResponse(p.c); err != nil {
			return 0, socks.Addr{}, err
		}
		p.responseRead = true
	}
	addr := p.dest
	if p.packetAddr {
		var err error
		addr, err = ReadAddr(p.c)
		if err != nil {
			return 0, socks.Addr{}, err
		}
	}
	var hdr [2]byte
	if _, err := io.ReadFull(p.c, hdr[:]); err != nil {
		return 0, socks.Addr{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(buf) {
		// Preserve framing if a caller continues after rejecting this datagram.
		if _, err := io.CopyN(io.Discard, p.c, int64(n)); err != nil {
			return 0, socks.Addr{}, err
		}
		return 0, socks.Addr{}, io.ErrShortBuffer
	}
	n, err := io.ReadFull(p.c, buf[:n])
	return n, addr, err
}

func (p *Packets) WritePacket(data []byte, addr socks.Addr) error {
	_, err := p.WritePacketCount(data, addr)
	return err
}

// WritePacketCount preserves an actual payload tail even when the underlying
// stream also reports shutdown. Status, destination and length are not usage.
func (p *Packets) WritePacketCount(data []byte, addr socks.Addr) (int, error) {
	if len(data) > packetsMaxSize {
		return 0, errors.New("mux: UDP packet is too large")
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	frame := make([]byte, 0, 1+260+2+len(data))
	if p.server && !p.responseWritten {
		frame = append(frame, 0)
	}
	if p.packetAddr {
		if addr.IsZero() {
			addr = p.dest
		}
		if addr.IsZero() || len(addr.Host) > 255 {
			return 0, errors.New("mux: invalid UDP packet address")
		}
		frame = AppendAddr(frame, addr)
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(data)))
	prefix := len(frame)
	frame = append(frame, data...)
	n, err := writeFullCount(p.c, frame)
	n -= prefix
	if n < 0 {
		n = 0
	}
	if err != nil {
		_ = p.c.Close()
		return n, err
	}
	p.responseWritten = true
	return n, nil
}

func (p *Packets) Close() error { return p.c.Close() }
