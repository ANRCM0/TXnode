package muxcool

// UDP sessions of a Mux.Cool connection.
//
// A UDP session is a NEW frame with NETWORK=UDP. Each subsequent frame carries
// exactly one chunk (SIZE(2) | payload) and that payload is one datagram, so the
// frame boundary is the chunk boundary — the connection reader never has to
// guess where a body ends. Xray reads its own mux link with a chunk reader
// capped at one chunk for the same reason.
//
// Evidence (captured against Xray 26.3.27, see docs/INTEROP.md):
//
//	client NEW:  000c | 0000 01 01 02 <port> 01 7f000001
//	client body: 000a | "capture-me"
//	server KEEP: 000c | 0000 02 01 02 <port> 01 7f000001
//	server body: 000a | "capture-me"
//
// The metadata carries the target; the body is the bare datagram. Some peers
// prefix a body with a full XUDP frame instead (UUID/GlobalID prelude plus a
// per-packet destination), so a body that parses as one is decoded that way.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

const (
	xudpStatusNew       = 1
	xudpStatusKeep      = 2
	xudpStatusEnd       = 3
	xudpStatusKeepAlive = 4

	xudpOptionData  = 1 << 0
	xudpOptionError = 1 << 1
)

// packet is one decoded datagram with its destination.
type packet struct {
	dest    socks.Addr
	payload []byte
}

// looksLikeXUDP reports whether body starts with an XUDP frame header:
// LEN(2) covering the rest of the body, a known STATUS/OPTION and a network.
func looksLikeXUDP(body []byte) bool {
	if len(body) < 7 {
		return false
	}
	length := int(binary.BigEndian.Uint16(body[0:2]))
	if length < 5 || len(body) != 2+length {
		return false
	}
	switch body[4] {
	case xudpStatusNew, xudpStatusKeep, xudpStatusEnd, xudpStatusKeepAlive:
	default:
		return false
	}
	if body[5]&^byte(xudpOptionData|xudpOptionError) != 0 {
		return false
	}
	return body[6] == NetworkUDP || body[6] == NetworkTCP
}

// decodeXUDPFrame decodes one XUDP frame body into a datagram.
func decodeXUDPFrame(body []byte) (packet, error) {
	// LEN(2) | SESSION(2) | STATUS(1) | OPTION(1) | NETWORK(1) | PORT(2) | ADDR |
	// LEN(2) | payload
	length := int(binary.BigEndian.Uint16(body[0:2]))
	if 2+length > len(body) {
		return packet{}, errors.New("muxcool: short xudp frame")
	}
	if body[5]&xudpOptionError != 0 {
		return packet{}, io.ErrClosedPipe
	}
	rest := body[6 : 2+length]
	if len(rest) < 4 {
		return packet{}, errors.New("muxcool: short xudp address")
	}
	dest, used, err := readAddress(rest[1:])
	if err != nil {
		return packet{}, err
	}
	tail := rest[1+used:]
	if len(tail) < 2 {
		return packet{}, errors.New("muxcool: short xudp payload")
	}
	n := int(binary.BigEndian.Uint16(tail[0:2]))
	payload := tail[2:]
	if len(payload) < n {
		return packet{}, errors.New("muxcool: truncated xudp payload")
	}
	return packet{dest: dest, payload: payload[:n]}, nil
}

// UDPSession is one Mux.Cool UDP session as a core.PacketStream.
type UDPSession struct {
	conn net.Conn
	id   uint16
	dest socks.Addr

	wmu  chan struct{}
	pkts chan packet
	done chan struct{}
	once chan struct{}
}

// newUDPSession builds a session for one NEW NETWORK=UDP frame.
func newUDPSession(conn net.Conn, id uint16, dest socks.Addr) *UDPSession {
	return &UDPSession{
		conn: conn,
		id:   id,
		dest: dest,
		wmu:  make(chan struct{}, 1),
		pkts: make(chan packet, 32),
		done: make(chan struct{}),
		once: make(chan struct{}, 1),
	}
}

// feed decodes one frame body and queues its datagram. A body that is not an
// XUDP frame is the datagram itself.
func (u *UDPSession) feed(body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var pkt packet
	if looksLikeXUDP(body) {
		var err error
		pkt, err = decodeXUDPFrame(body)
		if err != nil {
			return err
		}
	} else {
		pkt = packet{payload: append([]byte(nil), body...)}
	}
	if pkt.dest.IsZero() {
		pkt.dest = u.dest
	}
	select {
	case u.pkts <- pkt:
		return nil
	case <-u.done:
		return io.ErrClosedPipe
	}
}

// ReadPacket returns the next datagram and its destination.
func (u *UDPSession) ReadPacket(p []byte) (int, socks.Addr, error) {
	select {
	case pkt := <-u.pkts:
		n := copy(p, pkt.payload)
		if n < len(pkt.payload) {
			return n, pkt.dest, io.ErrShortBuffer
		}
		return n, pkt.dest, nil
	case <-u.done:
		return 0, u.dest, io.EOF
	}
}

// WritePacket sends one datagram back as a KEEP frame: metadata with the target
// followed by one chunk holding the datagram.
func (u *UDPSession) WritePacket(p []byte, dest socks.Addr) error {
	u.wmu <- struct{}{}
	defer func() { <-u.wmu }()
	if dest.IsZero() {
		dest = u.dest
	}
	meta := buildUDPKeepMetadata(u.id, dest)
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(p)))
	frame := make([]byte, 0, len(meta)+2+len(p))
	frame = append(frame, meta...)
	frame = append(frame, size[:]...)
	frame = append(frame, p...)
	_, err := u.conn.Write(frame)
	return err
}

// buildUDPKeepMetadata serialises LEN(2) | SESSION(2) | STATUS | OPTION |
// NETWORK | PORT | ADDR for a UDP KEEP frame.
func buildUDPKeepMetadata(id uint16, dest socks.Addr) []byte {
	addr := appendAddress(nil, dest)
	body := make([]byte, 0, 5+len(addr))
	body = binary.BigEndian.AppendUint16(body, id)
	body = append(body, StatusKeep, OptionData, NetworkUDP)
	body = append(body, addr...)
	out := make([]byte, 0, 2+len(body))
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

// LocalAddr and RemoteAddr expose the parent connection's addresses.
func (u *UDPSession) LocalAddr() net.Addr  { return u.conn.LocalAddr() }
func (u *UDPSession) RemoteAddr() net.Addr { return u.conn.RemoteAddr() }

// close releases the session without writing to the peer.
func (u *UDPSession) close() {
	select {
	case <-u.done:
	default:
		close(u.done)
	}
}

// Close ends the session with an End frame.
func (u *UDPSession) Close() error {
	u.close()
	return writeMetadata(u.conn, &Metadata{SessionID: u.id, Status: StatusEnd})
}
