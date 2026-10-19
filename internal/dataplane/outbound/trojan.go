package outbound

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// trojanToken is hex(SHA-224(password)), the 56-byte first-packet credential
// (contract §3.2: "首包 hex 口令 + CRLF 命令"; proto/trojan.Key @0xb30080 hashes
// the same way on the server side).
func trojanToken(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

// newTrojan builds the Trojan client. Trojan is TLS by default: the local-mode
// node always serves it over TLS (REPORT.md §22.4 "local 模式默认就带 TLS"),
// so tls=false has to be explicit.
func newTrojan(s settings, o opt.Opt) (*Proxy, error) {
	addr, err := serverAddr(s, "trojan")
	if err != nil {
		return nil, err
	}
	password := s.str(keysPassword...)
	if password == "" {
		return nil, errors.New("trojan outbound needs a password")
	}
	st, err := readStream(o)
	if err != nil {
		return nil, fmt.Errorf("trojan outbound: %w", err)
	}
	if st.security == "none" && !explicitlyDisabledTLS(o) {
		st.security = "tls"
		st.tls.enabled = true
	}
	if pl, err := readPlugin(s, o, nil); err != nil {
		return nil, err
	} else if pl != nil {
		return nil, errors.New("a trojan outbound takes no Shadowsocks plugin")
	}
	p := &Proxy{protocol: "trojan", opt: o, stream: st, addr: addr, password: password}
	via, err := readVia(o)
	if err != nil {
		return nil, err
	}
	p.via = via
	return p, nil
}

// explicitlyDisabledTLS reports whether the settings said tls=false (as
// opposed to not mentioning tls at all).
func explicitlyDisabledTLS(o opt.Opt) bool {
	s := settings(o)
	if v, ok := s.get(keysTLS...); ok {
		if b, ok := v.(bool); ok {
			return !b
		}
		if str, ok := v.(string); ok {
			return strings.EqualFold(strings.TrimSpace(str), "false") || strings.EqualFold(strings.TrimSpace(str), "none")
		}
	}
	if v, ok := s.get(keysSecurity...); ok {
		if str, ok := v.(string); ok && strings.EqualFold(strings.TrimSpace(str), "none") {
			return true
		}
	}
	return false
}

// trojanStream writes the request:
//
//	hex(sha224(password)) CRLF [cmd=1][ATYP][addr][port] CRLF
//
// then relays payload unchanged.
func (p *Proxy) trojanStream(c net.Conn, dest socks.Addr) (net.Conn, error) {
	buf := make([]byte, 0, 56+2+1+1+len(dest.Host)+2+2)
	buf = append(buf, trojanToken(p.password)...)
	buf = append(buf, '\r', '\n')
	buf = append(buf, 0x01) // CONNECT
	var err error
	buf, err = appendSocksAddr(buf, dest)
	if err != nil {
		return nil, fmt.Errorf("trojan outbound: %w", err)
	}
	buf = append(buf, '\r', '\n')
	if _, err := c.Write(buf); err != nil {
		return nil, fmt.Errorf("trojan outbound: %w", err)
	}
	return c, nil
}

// trojanPacket carries UDP as Trojan UDP frames on a dedicated TCP stream
// (outbound.(*trojanPacket).WriteTo @0xb81fa0, .ReadFrom @0xb82480):
//
//	[ATYP][addr][port][len BE16][CRLF][payload]
type trojanPacket struct {
	conn net.Conn

	wmu sync.Mutex
	rmu sync.Mutex
	buf []byte
}

// trojanPacket performs the command-3 handshake (UDP ASSOCIATE) on a fresh
// TCP stream.
func (p *Proxy) trojanPacket(ctx context.Context, dest socks.Addr) (core.PacketStream, error) {
	c, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 58+1+len(dest.Host)+2)
	buf = append(buf, trojanToken(p.password)...)
	buf = append(buf, '\r', '\n')
	buf = append(buf, 0x03) // UDP ASSOCIATE
	var err2 error
	buf, err2 = appendSocksAddr(buf, dest)
	if err2 != nil {
		c.Close()
		return nil, err2
	}
	buf = append(buf, '\r', '\n')
	if _, err := c.Write(buf); err != nil {
		c.Close()
		return nil, err
	}
	return &trojanPacket{conn: c}, nil
}

func (t *trojanPacket) WritePacket(p []byte, a socks.Addr) error {
	buf := make([]byte, 0, 1+len(a.Host)+2+2+2+len(p))
	var err error
	buf, err = appendSocksAddr(buf, a)
	if err != nil {
		return err
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(p)))
	buf = append(buf, '\r', '\n')
	buf = append(buf, p...)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_, err = t.conn.Write(buf)
	return err
}

func (t *trojanPacket) ReadPacket(p []byte) (int, socks.Addr, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	if len(t.buf) == 0 {
		var head [1]byte
		if _, err := readFull(t.conn, head[:]); err != nil {
			return 0, socks.Addr{}, err
		}
		// Re-read the address with the first byte known.
		addr, used, err := parseSocksAddrWithFirst(head[0], t.conn)
		if err != nil {
			return 0, socks.Addr{}, err
		}
		_ = used
		var lb [2]byte
		if _, err := readFull(t.conn, lb[:]); err != nil {
			return 0, socks.Addr{}, err
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		var crlf [2]byte
		if _, err := readFull(t.conn, crlf[:]); err != nil {
			return 0, socks.Addr{}, err
		}
		if crlf[0] != '\r' || crlf[1] != '\n' {
			return 0, socks.Addr{}, errors.New("trojan outbound: malformed UDP frame")
		}
		body := make([]byte, n)
		if _, err := readFull(t.conn, body); err != nil {
			return 0, socks.Addr{}, err
		}
		copied := copy(p, body)
		return copied, addr, nil
	}
	return 0, socks.Addr{}, errors.New("trojan outbound: no buffered packet")
}

func (t *trojanPacket) Close() error { return t.conn.Close() }

// readFull is io.ReadFull without importing io twice in this file's namespace.
func readFull(c net.Conn, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := c.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// parseSocksAddrWithFirst parses an address whose first byte has already been
// consumed.
func parseSocksAddrWithFirst(first byte, c net.Conn) (socks.Addr, int, error) {
	var rest []byte
	switch first {
	case socksAtypIPv4:
		rest = make([]byte, 6)
	case socksAtypIPv6:
		rest = make([]byte, 18)
	case socksAtypDomain:
		var l [1]byte
		if _, err := readFull(c, l[:]); err != nil {
			return socks.Addr{}, 0, err
		}
		rest = make([]byte, int(l[0])+2)
		if _, err := readFull(c, rest); err != nil {
			return socks.Addr{}, 0, err
		}
		addr, n, err := parseSocksAddr(append([]byte{first, l[0]}, rest...))
		return addr, n, err
	default:
		return socks.Addr{}, 0, fmt.Errorf("trojan outbound: unknown address type %d", first)
	}
	if _, err := readFull(c, rest); err != nil {
		return socks.Addr{}, 0, err
	}
	addr, n, err := parseSocksAddr(append([]byte{first}, rest...))
	return addr, n, err
}
