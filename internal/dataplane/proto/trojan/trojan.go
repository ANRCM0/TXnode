// Package trojan is the Trojan inbound of kaze v0.5.18.
//
// Evidence:
//   - REPORT.md §6.4 ("只有 4 条错误串 … 靠首包 hex 密码 + CRLF 命令识别"),
//     §22.4 (Trojan + TLS self-interop works: A's trojan outbound -> B, B logs
//     `proto=http` after sniffing the plaintext tunnel), notes/protocols.md §2.3.
//   - notes/rev-proto-tcp.md §3 (25 functions / 6,016 B):
//     trojan.Key @0xb30080, trojan.peekCredential @0xb30a60,
//     trojan.(*Handler).Handshake @0xb30300, trojan.(*packetStream).ReadPacket
//     @0xb30e31, error literals at @0xf70293 / @0xf6d43a / @0xf6be0a.
//
// Request layout (notes §3.1, addresses as in the sample sha256 723d4e20…f900):
//
//	hex(sha224(password)) 56 B   trojan.Key @0xb30080: Sum224 -> 28 bytes ->
//	                             56 lower-case hex chars via the "0123456789abcdef"
//	                             table @0xf6142f
//	CRLF                          eaten by Discard(2) @0xb3051a
//	cmd 1 B                      ReadByte @0xb30527: 1 = connect, 3 = UDP
//	addr                         socks.ReadAddr @0xb30548 (ATYP/ADDR/PORT)
//	CRLF                         io.ReadAtLeast(2) + `cmp word [rcx],0xa0d` @0xb305b1
//	payload…
//
// The password check is a Go map lookup (`runtime.mapaccess2_faststr` @0xb304e6)
// on the 56-char hex string after `cmp rcx,0x38` (@0xb304ca) — not a constant
// time compare; recorded, not dramatised (notes §3.2).
package trojan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Commands carried by the first packet.
const (
	CmdConnect = 0x01
	CmdUDP     = 0x03
)

// Error strings are the binary's own literals.
var (
	// ErrNotClient ← "trojan: not a trojan client" @0xf70278. A wrong password is
	// answered with this too: the docs say every non-user (wrong password,
	// browser, probe) is served the fallback page (notes/protocols.md §2.3).
	ErrNotClient = errors.New("trojan: not a trojan client")
	// ErrMalformed ← "trojan: malformed packet" @0xf6be0a
	// (trojan.(*packetStream).ReadPacket @0xb30e31).
	ErrMalformed = errors.New("trojan: malformed packet")
	// ErrMalformedRequest ← "trojan: malformed request, through a reverse proxy"
	// @0xf6d43a — the trailing CRLF did not arrive, i.e. something in front of the
	// node ate part of the request.
	ErrMalformedRequest = errors.New("trojan: malformed request, through a reverse proxy")
	// ErrUnsupportedCommand ← "trojan: unsupported command" @0xf70293.
	ErrUnsupportedCommand = errors.New("trojan: unsupported command")
)

// Key derives the 56-character credential for a password: hex(sha224(pwd))
// (trojan.Key @0xb30080: crypto/sha256.Sum224 -> 28 bytes -> nibble table).
func Key(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

// Options is the package contract (REPLICATION.md §3.2).
type Options struct {
	// Users are the admitted accounts; a user's UUID is its Trojan password.
	Users []core.User
	// Fallback is what a non-client is handed to. When it implements
	// core.Handler it runs on the same connection; otherwise the handler returns
	// a *core.Stranger so core can answer with the fallback page / file
	// (REPORT.md §7.9: transport.newDecoySite is the in-memory decoy site).
	Fallback any
}

// Handler is the Trojan inbound.
type Handler struct {
	users    map[string]*core.User // hex credential -> user
	fallback any
}

var _ core.Handler = (*Handler)(nil)

// NewHandler validates Options and builds the handler.
func NewHandler(o Options) (*Handler, error) {
	h := &Handler{
		users:    make(map[string]*core.User, len(o.Users)),
		fallback: o.Fallback,
	}
	for i := range o.Users {
		if o.Users[i].UUID == "" {
			continue
		}
		h.users[Key(o.Users[i].UUID)] = &o.Users[i]
	}
	return h, nil
}

// Handle parses the Trojan request and returns the session for core to relay.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	// The binary wraps the connection in a 2048-byte bufio reader
	// (@0xb3037c `cmp qword [rcx+8],0x800`).
	br := bufio.NewReaderSize(conn, 2048)
	cred, err := peekCredential(br)
	if err != nil {
		return nil, h.notAClient(ctx, conn, err)
	}
	user, ok := h.users[cred]
	if !ok {
		// Wrong password: indistinguishable from "not a trojan client" so that
		// probes get the fallback page (notes/protocols.md §2.3).
		return nil, h.notAClient(ctx, conn, ErrNotClient)
	}

	// Consume the credential and its CRLF: 56 hex digits + CRLF = 58 bytes
	// (@0xb3051a bufio.(*Reader).Discard, then @0xb30527 ReadByte reads the
	// command).
	if _, err := br.Discard(56 + 2); err != nil {
		return nil, err
	}
	cmd, err := br.ReadByte()
	if err != nil {
		return nil, err
	}
	dest, err := ReadAddr(br)
	if err != nil {
		return nil, ErrMalformedRequest
	}
	var tail [2]byte
	if _, err := io.ReadFull(br, tail[:]); err != nil || tail[0] != '\r' || tail[1] != '\n' {
		return nil, ErrMalformedRequest
	}

	switch cmd {
	case CmdConnect:
		return &core.Session{
			UserID: user.ID,
			Dest:   dest,
			Conn:   &bufConn{Conn: conn, r: br},
			Socket: tcpConn(conn),
		}, nil
	case CmdUDP:
		return &core.Session{
			UserID:  user.ID,
			Dest:    dest,
			Conn:    &bufConn{Conn: conn, r: br},
			Packets: &packetStream{conn: conn, r: br},
		}, nil
	}
	return nil, ErrUnsupportedCommand
}

// notAClient hands the connection to the fallback when one is configured,
// otherwise reports a stranger so core can answer like a web server.
func (h *Handler) notAClient(ctx context.Context, conn net.Conn, cause error) error {
	if handler, ok := h.fallback.(core.Handler); ok && handler != nil {
		_, err := handler.Handle(ctx, conn)
		if err != nil {
			return err
		}
		return cause
	}
	return &core.Stranger{Conn: conn, Err: cause}
}

// peekCredential inspects the first 58 bytes without consuming them
// (trojan.peekCredential @0xb30a60): 56 hex digits then CRLF, byte by byte,
// growing the peek window as data arrives.
func peekCredential(br *bufio.Reader) (string, error) {
	for i := 0; i < 58; i++ {
		b, err := br.Peek(i + 1)
		if err != nil {
			return "", ErrNotClient
		}
		c := b[i]
		switch {
		case i < 56:
			if !isHex(c) {
				return "", ErrNotClient
			}
		case i == 56:
			if c != '\r' {
				return "", ErrNotClient
			}
		default:
			if c != '\n' {
				return "", ErrNotClient
			}
		}
	}
	b, err := br.Peek(56)
	if err != nil {
		return "", ErrNotClient
	}
	return string(b), nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}

// bufConn is trojan.bufConn: the reader's buffered bytes come first, then the
// connection (notes §3.3: the leftover payload is replayed).
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Pending reports the bytes already buffered (trojan.(*bufConn).Pending @0xb30c20).
func (c *bufConn) Pending() int { return c.r.Buffered() }

func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// packetStream carries UDP over the trojan connection
// (trojan.(*packetStream).ReadPacket @0xb30d40 / WritePacket @0xb30f40).
//
// Datagram layout follows the Trojan spec: ATYP ADDR PORT LENGTH CRLF PAYLOAD.
// notes/rev-proto-tcp.md §3.3 only fixes that the type exists and that
// "trojan: malformed packet" comes from ReadPacket.
type packetStream struct {
	conn net.Conn
	r    *bufio.Reader
}

func (p *packetStream) ReadPacket(b []byte) (int, socks.Addr, error) {
	addr, err := ReadAddr(p.r)
	if err != nil {
		return 0, socks.Addr{}, ErrMalformed
	}
	var l [2]byte
	if _, err := io.ReadFull(p.r, l[:]); err != nil {
		return 0, socks.Addr{}, ErrMalformed
	}
	n := int(l[0])<<8 | int(l[1])
	var crlf [2]byte
	if _, err := io.ReadFull(p.r, crlf[:]); err != nil || crlf[0] != '\r' || crlf[1] != '\n' {
		return 0, socks.Addr{}, ErrMalformed
	}
	if n > len(b) {
		// Drain the rest so the stream stays in sync, then report the truncation.
		if _, err := io.CopyN(io.Discard, p.r, int64(n)); err != nil {
			return 0, socks.Addr{}, ErrMalformed
		}
		return 0, socks.Addr{}, ErrMalformed
	}
	if _, err := io.ReadFull(p.r, b[:n]); err != nil {
		return 0, socks.Addr{}, ErrMalformed
	}
	return n, addr, nil
}

func (p *packetStream) WritePacket(b []byte, addr socks.Addr) error {
	if len(b) > 0xffff {
		return ErrMalformed
	}
	buf := make([]byte, 0, len(addr.Host)+9+len(b))
	buf = appendAddr(buf, addr)
	buf = append(buf, byte(len(b)>>8), byte(len(b)), '\r', '\n')
	buf = append(buf, b...)
	_, err := p.conn.Write(buf)
	return err
}

func (p *packetStream) Close() error { return p.conn.Close() }

func tcpConn(c net.Conn) *net.TCPConn {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc
	}
	return nil
}
