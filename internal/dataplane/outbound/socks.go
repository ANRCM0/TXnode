package outbound

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// socksOutbound is the SOCKS5 client. In the sample this lives in
// core.(*ProxyOutbound) (socksConnect/socksAssociate, catalog-strings.md
// #1089-#1092); the contract puts it here so outbound.New covers all seven
// whitelisted types.
type socksOutbound struct {
	addr socks.Addr
	user string
	pass string
}

func newSocks(s settings) (core.Outbound, error) {
	addr, err := serverAddr(s, "socks")
	if err != nil {
		return nil, err
	}
	user := s.str(keysUser...)
	pass := s.str(keysPassword...)
	if len(user) > 255 || len(pass) > 255 {
		return nil, errors.New("a socks outbound's username and password are at most 255 bytes each")
	}
	return &socksOutbound{addr: addr, user: user, pass: pass}, nil
}

func (o *socksOutbound) Name() string { return "socks" }

// serverAddr reads address+port and validates them.
func serverAddr(s settings, protocol string) (socks.Addr, error) {
	host := s.str(keysAddress...)
	port := s.int(keysPort...)
	if host == "" || port <= 0 || port > 65535 {
		return socks.Addr{}, errors.New("outbound needs a server address and port")
	}
	if !isServerAddress(host) {
		return socks.Addr{}, fmt.Errorf("outbound %q is not a server address: %q", protocol, host)
	}
	return socks.Addr{Host: host, Port: uint16(port)}, nil
}

// isServerAddress accepts IP literals and domain names.
func isServerAddress(host string) bool {
	if host == "" || len(host) > 255 {
		return false
	}
	if a := (socks.Addr{Host: host}).IP(); a.IsValid() {
		return true
	}
	for _, c := range host {
		if c == ' ' || c == '/' || c == 0 {
			return false
		}
	}
	return true
}

// dialWithContext dials TCP honouring ctx.
func dialWithContext(ctx context.Context, addr socks.Addr) (net.Conn, error) {
	var d net.Dialer
	if deadline, ok := ctx.Deadline(); ok {
		d.Deadline = deadline
	} else {
		d.Timeout = 15 * time.Second
	}
	return d.DialContext(ctx, "tcp", addr.String())
}

// socksHandshake performs the greeting, optional RFC 1929 auth and one request.
func (o *socksOutbound) socksHandshake(ctx context.Context, dest socks.Addr, cmd byte) (net.Conn, socks.Addr, error) {
	c, err := dialWithContext(ctx, o.addr)
	if err != nil {
		return nil, socks.Addr{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	}

	// Greeting: offer no-auth and username/password.
	methods := []byte{0x00}
	if o.user != "" || o.pass != "" {
		methods = append(methods, 0x02)
	}
	greet := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := c.Write(greet); err != nil {
		c.Close()
		return nil, socks.Addr{}, err
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		c.Close()
		return nil, socks.Addr{}, err
	}
	if sel[0] != 0x05 {
		c.Close()
		return nil, socks.Addr{}, errors.New("socks outbound: the server is not a SOCKS5 server")
	}
	switch sel[1] {
	case 0x00:
	case 0x02:
		if o.user == "" && o.pass == "" {
			c.Close()
			return nil, socks.Addr{}, errors.New("socks outbound rejected the username or password")
		}
		req := append([]byte{0x01, byte(len(o.user))}, o.user...)
		req = append(req, byte(len(o.pass)))
		req = append(req, o.pass...)
		if _, err := c.Write(req); err != nil {
			c.Close()
			return nil, socks.Addr{}, err
		}
		var st [2]byte
		if _, err := io.ReadFull(c, st[:]); err != nil {
			c.Close()
			return nil, socks.Addr{}, err
		}
		if st[1] != 0x00 {
			c.Close()
			return nil, socks.Addr{}, errors.New("socks outbound rejected the username or password")
		}
	default:
		c.Close()
		return nil, socks.Addr{}, errors.New("socks outbound refused the authentication method")
	}

	// Request: VER CMD RSV ATYP ADDR PORT.
	req := []byte{0x05, cmd, 0x00}
	req, err = appendSocksAddr(req, dest)
	if err != nil {
		c.Close()
		return nil, socks.Addr{}, err
	}
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, socks.Addr{}, err
	}
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		c.Close()
		return nil, socks.Addr{}, err
	}
	if head[0] != 0x05 {
		c.Close()
		return nil, socks.Addr{}, errors.New("socks outbound: the server answered a bad request version")
	}
	if head[1] != 0x00 {
		c.Close()
		if cmd == 0x03 {
			return nil, socks.Addr{}, fmt.Errorf("socks outbound does not offer UDP (code %d)", head[1])
		}
		return nil, socks.Addr{}, fmt.Errorf("socks outbound could not connect (code %d)", head[1])
	}
	// Read BND.ADDR/BND.PORT.
	bound, err := readSocksBound(c, head[3])
	if err != nil {
		c.Close()
		return nil, socks.Addr{}, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, bound, nil
}

// readSocksBound reads the bound address of a SOCKS5 reply.
func readSocksBound(c net.Conn, atyp byte) (socks.Addr, error) {
	switch atyp {
	case socksAtypIPv4:
		var b [6]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return socks.Addr{}, err
		}
		return socks.Addr{Host: net.IP(b[:4]).String(), Port: binary.BigEndian.Uint16(b[4:6])}, nil
	case socksAtypIPv6:
		var b [18]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return socks.Addr{}, err
		}
		return socks.Addr{Host: net.IP(b[:16]).String(), Port: binary.BigEndian.Uint16(b[16:18])}, nil
	case socksAtypDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return socks.Addr{}, err
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(c, b); err != nil {
			return socks.Addr{}, err
		}
		return socks.Addr{Host: string(b[:l[0]]), Port: binary.BigEndian.Uint16(b[l[0]:])}, nil
	}
	return socks.Addr{}, errors.New("socks outbound: unknown address type in the reply")
}

func (o *socksOutbound) DialTCP(ctx context.Context, dest socks.Addr) (net.Conn, error) {
	c, _, err := o.socksHandshake(ctx, dest, 0x01)
	return c, err
}

// DialPacket performs UDP ASSOCIATE and returns a datagram stream. The
// destination is carried in every datagram's SOCKS5 UDP header, so dest is
// only used to keep the signature.
func (o *socksOutbound) DialPacket(ctx context.Context, dest socks.Addr) (core.PacketStream, error) {
	c, bound, err := o.socksHandshake(ctx, socks.Addr{Host: "0.0.0.0", Port: 0}, 0x03)
	if err != nil {
		return nil, err
	}
	relay := bound
	if relay.Host == "0.0.0.0" || relay.Host == "::" {
		relay.Host = o.addr.Host
	}
	var d net.Dialer
	if deadline, ok := ctx.Deadline(); ok {
		d.Deadline = deadline
	} else {
		d.Timeout = 15 * time.Second
	}
	pc, err := d.DialContext(ctx, "udp", relay.String())
	if err != nil {
		c.Close()
		return nil, err
	}
	go func() {
		// The TCP control connection must stay open for the association.
		io.Copy(io.Discard, c) //nolint:errcheck
		c.Close()
	}()
	return &socksPacketConn{pc: pc, ctrl: c, relay: relay}, nil
}

// socksPacketConn wraps a UDP socket with the SOCKS5 UDP request header
// (RSV 2 bytes, FRAG 1 byte, ATYP+ADDR+PORT, payload).
type socksPacketConn struct {
	pc    net.Conn
	ctrl  net.Conn
	relay socks.Addr
}

func (s *socksPacketConn) WritePacket(p []byte, a socks.Addr) error {
	buf := make([]byte, 0, 4+len(a.Host)+2+len(p))
	buf = append(buf, 0, 0, 0) // RSV, RSV, FRAG=0
	var err error
	buf, err = appendSocksAddr(buf, a)
	if err != nil {
		return err
	}
	buf = append(buf, p...)
	_, err = s.pc.Write(buf)
	return err
}

func (s *socksPacketConn) ReadPacket(p []byte) (int, socks.Addr, error) {
	buf := make([]byte, 64*1024)
	n, err := s.pc.Read(buf)
	if err != nil {
		return 0, socks.Addr{}, err
	}
	if n < 4 {
		return 0, socks.Addr{}, errors.New("socks: short UDP datagram")
	}
	if buf[2] != 0 {
		return 0, socks.Addr{}, errors.New("socks: fragmented UDP datagrams are not supported")
	}
	addr, used, err := parseSocksAddr(buf[3:n])
	if err != nil {
		return 0, socks.Addr{}, err
	}
	return copy(p, buf[3+used:n]), addr, nil
}

func (s *socksPacketConn) Close() error {
	_ = s.pc.Close()
	if s.ctrl != nil {
		_ = s.ctrl.Close()
	}
	return nil
}
