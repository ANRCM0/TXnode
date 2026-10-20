// Plain UDP over a VLESS stream (cmd==2).
//
// Evidence: notes/rev-round2-proto.md §C.2 — the cmd==2 branch allocates a
// struct that holds the connection, the destination and its port and nothing
// else (type 0xea6b40 at 0xb3dae9); there is no reference to core.NewUoT and no
// reference to xudp. The framing lives in the package's own packet stream:
//
//	(*packetStream).WritePacket @0xb3f260:
//	  0xb3f2a0  cmp r8, 0xffff / jg        payload larger than 65535 is dropped
//	  0xb3f2d0  lock cmpxchg [rcx+0x28]    per-stream write mutex
//	  0xb3f367  rol r8w,8 / mov [rax],r8w  BE16 length prefix
//	  0xb3f3e9  memmove [buf+2], payload
//	  0xb3f435  SetWriteDeadline(now+30s)  (0x6fc23ac00 ns)
//	  0xb3f48f  conn.Write(buf)
//
//	(*packetStream).ReadPacket @0xb3f020:
//	  0xb3f032  SetReadDeadline(now+300s)  (0x45d964b800 ns)
//	  0xb3f0b6  io.ReadFull(conn, len[2])
//	  0xb3f0cd  rol dx,8                   BE16
//	  0xb3f140  io.ReadFull(conn, payload)
package vless

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

const (
	// 0x45d964b800 ns = 300 s read timeout (0xb3f03c).
	udpReadTimeout = 300 * time.Second
	// 0x6fc23ac00 ns = 30 s write timeout (0xb3f43a).
	udpWriteTimeout = 30 * time.Second
	// 0xffff: payloads above this are silently dropped (0xb3f2a0 jg).
	udpMaxPayload = 0xffff
)

// packetStream carries datagrams as length-prefixed records on the VLESS
// stream. It implements core.PacketStream.
type packetStream struct {
	conn net.Conn
	dest socks.Addr

	mu  sync.Mutex // write serialisation (0xb3f2d0)
	buf []byte     // reused frame buffer (packetStream+0x30..0x40)
}

// ReadPacket reads one datagram into p and reports the flow's destination.
func (s *packetStream) ReadPacket(p []byte) (int, socks.Addr, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(udpReadTimeout))
	var hdr [2]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return 0, s.dest, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return 0, s.dest, nil
	}
	if n > len(p) {
		// The sample allocates its own buffer; the core.PacketStream contract
		// reads into the caller's slice, so a short slice is an explicit error
		// and the datagram is discarded.
		discard := make([]byte, n)
		if _, err := io.ReadFull(s.conn, discard); err != nil {
			return 0, s.dest, err
		}
		return 0, s.dest, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(s.conn, p[:n]); err != nil {
		return 0, s.dest, err
	}
	return n, s.dest, nil
}

// WritePacket writes one datagram. Datagrams above 65535 bytes are dropped
// silently, matching the sample's length guard.
func (s *packetStream) WritePacket(p []byte, addr socks.Addr) error {
	if len(p) > udpMaxPayload {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	need := 2 + len(p)
	if cap(s.buf) < need {
		s.buf = make([]byte, need)
	}
	buf := s.buf[:need]
	binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
	copy(buf[2:], p)
	_ = s.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
	_, err := s.conn.Write(buf)
	return err
}

// Close closes the flow.
func (s *packetStream) Close() error { return s.conn.Close() }

var _ core.PacketStream = (*packetStream)(nil)
