package mieru

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// v2SocksSession consumes only the inner request, including when the official
// low-entropy client sends it after an empty openSessionRequest.
func v2SocksSession(conn net.Conn, userID int) (*core.Session, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	if head[0] != 5 || head[2] != 0 || (head[1] != 1 && head[1] != 3) {
		return nil, errors.New("mieru: unsupported inner SOCKS5 request")
	}
	length := 0
	var address []byte
	switch head[3] {
	case 1:
		length = 6
	case 4:
		length = 18
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		if size[0] == 0 {
			return nil, errors.New("mieru: empty inner SOCKS5 host")
		}
		address = append(address, size[0])
		length = int(size[0]) + 2
	default:
		return nil, errors.New("mieru: invalid inner SOCKS5 address type")
	}
	address = append(address, make([]byte, length)...)
	if _, err := io.ReadFull(conn, address[len(address)-length:]); err != nil {
		return nil, err
	}
	request := append(head[:], address...)
	command := request[1]
	request[1] = 1
	dest, err := parseSocks5Request(request)
	if err != nil {
		return nil, err
	}
	sess := &core.Session{UserID: userID, Dest: dest, Conn: conn, SourceIP: socks.FromNetAddr(conn.RemoteAddr()).IP()}
	if command == 3 {
		// The association remains inside the authenticated Mieru session; all
		// destination sockets and policy stay owned by the common packet relay.
		if err := writeFull(conn, v2Socks5Reply(0, nil)); err != nil {
			return nil, err
		}
		sess.Conn = nil
		sess.Packets = &v2PacketTunnel{conn: conn}
	}
	return sess, nil
}

type v2PacketTunnel struct {
	conn net.Conn
	rmu  sync.Mutex
	wmu  sync.Mutex
}

func (p *v2PacketTunnel) RemoteAddr() net.Addr { return p.conn.RemoteAddr() }
func (p *v2PacketTunnel) Close() error         { return p.conn.Close() }

func (p *v2PacketTunnel) ReadPacket(dst []byte) (int, socks.Addr, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	var head [3]byte
	if _, err := io.ReadFull(p.conn, head[:]); err != nil {
		return 0, socks.Addr{}, err
	}
	length := int(binary.BigEndian.Uint16(head[1:]))
	if head[0] != 0 || length < 7 {
		return 0, socks.Addr{}, errors.New("mieru: invalid packet-over-stream header")
	}
	packet := make([]byte, length+1)
	if _, err := io.ReadFull(p.conn, packet); err != nil {
		return 0, socks.Addr{}, err
	}
	if packet[length] != 0xff || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return 0, socks.Addr{}, errors.New("mieru: invalid SOCKS5 UDP packet or unsupported fragment")
	}
	dest, n, err := decodeAddr(packet[3:length])
	if err != nil {
		return 0, socks.Addr{}, err
	}
	payload := packet[3+n : length]
	if len(payload) > len(dst) {
		return 0, socks.Addr{}, io.ErrShortBuffer
	}
	return copy(dst, payload), dest, nil
}

func (p *v2PacketTunnel) WritePacket(payload []byte, dest socks.Addr) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	address := encodeAddr(dest)
	length := 3 + len(address) + len(payload)
	if length > 65535 {
		return errors.New("mieru: packet-over-stream payload too large")
	}
	packet := make([]byte, 3+length+1)
	binary.BigEndian.PutUint16(packet[1:3], uint16(length))
	copy(packet[6:], address)
	copy(packet[6+len(address):], payload)
	packet[len(packet)-1] = 0xff
	return writeFull(p.conn, packet)
}

var _ core.PacketStream = (*v2PacketTunnel)(nil)
