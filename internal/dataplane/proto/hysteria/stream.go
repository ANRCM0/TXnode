package hysteria

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Data-plane stream format.
//
// A hysteria TCP request travels on a QUIC bidirectional stream, after the
// /auth exchange, as
//
//	[varint addrLen][addr][varint paddingLen][padding]
//
// and the server answers with
//
//	[status byte][varint msgLen][msg]
//
// Status 0 means the tunnel is open and the rest of the stream is payload.
//
// UNVERIFIED: the report only locates the data-plane functions (dispatch @0xaa34e0,
// serveTCP @0xaa37e0, parseUDP @0xaa3f40, appendUDP @0xaa4220,
// readDatagrams @0xaa4400, session @0xaa4580, makeRoom @0xaa4a20,
// parseHostPort @0xaa3e60) without decoding their bytes
// (notes/rev-proto-udp.md §1.6, item U). The framing above is the upstream
// hysteria2 shape (varint address length, SOCKS5 address, varint padding, status
// byte) and is what both ends of this replication use; it is not byte-verified
// against the sample.
//
// Address encoding is SOCKS5: 1 = IPv4, 3 = domain, 4 = IPv6, each followed by
// the address bytes and a big-endian port. INFERRED from upstream; the sample's
// parseHostPort name suggests host:port text parsing, which the report does not
// resolve.
const (
	statusOK    = 0x00
	statusError = 0x01

	// frameTypeTCPRequest is the QUIC varint prefix of a hysteria2 TCP request
	// (github.com/apernet/hysteria core/internal/protocol.FrameTypeTCPRequest).
	frameTypeTCPRequest = 0x401
	// maxAddrLen bounds the address field so a hostile client cannot make the
	// server allocate unbounded memory before authentication has paid off.
	maxAddrLen = 2048
	// maxPaddingLen bounds the per-request padding.
	maxPaddingLen = 4096
)

// readRequest parses a hysteria2 TCP request from a stream:
//
//	[varint 0x401][varint addrLen]["host:port"][varint paddingLen][padding]
func readRequest(r io.Reader) (socks.Addr, int, error) {
	br := quicvarint.NewReader(r)
	frameType, err := quicvarint.Read(br)
	if err != nil {
		return socks.Addr{}, 0, err
	}
	if frameType != frameTypeTCPRequest {
		return socks.Addr{}, 0, fmt.Errorf("hysteria: unexpected frame type %#x", frameType)
	}
	addrLen, err := quicvarint.Read(br)
	if err != nil {
		return socks.Addr{}, 0, err
	}
	if addrLen == 0 || addrLen > maxAddrLen {
		return socks.Addr{}, 0, fmt.Errorf("hysteria: bad address length %d", addrLen)
	}
	buf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return socks.Addr{}, 0, err
	}
	host, portStr, err := net.SplitHostPort(string(buf))
	if err != nil {
		return socks.Addr{}, 0, fmt.Errorf("hysteria: bad address %q: %w", string(buf), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return socks.Addr{}, 0, fmt.Errorf("hysteria: bad port %q", portStr)
	}
	padLen, err := quicvarint.Read(br)
	if err != nil {
		return socks.Addr{}, 0, err
	}
	if padLen > maxPaddingLen {
		return socks.Addr{}, 0, fmt.Errorf("hysteria: padding %d too long", padLen)
	}
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return socks.Addr{}, 0, err
		}
	}
	return socks.Addr{Host: host, Port: uint16(port)}, int(padLen), nil
}

// writeRequest serialises a request header (client side of the pair).
func writeRequest(w io.Writer, dest socks.Addr, paddingLen int) error {
	addr := dest.String()
	buf := make([]byte, 0, 2*quicvarint.Len(frameTypeTCPRequest)+2*quicvarint.Len(uint64(len(addr)))+len(addr)+quicvarint.Len(uint64(paddingLen))+paddingLen)
	buf = quicvarint.Append(buf, frameTypeTCPRequest)
	buf = quicvarint.Append(buf, uint64(len(addr)))
	buf = append(buf, addr...)
	buf = quicvarint.Append(buf, uint64(paddingLen))
	buf = append(buf, make([]byte, paddingLen)...)
	if err := writeAll(w, buf); err != nil {
		return err
	}
	return nil
}

// writeResponse writes the status byte and a length-prefixed message.
func writeResponse(w io.Writer, status byte, msg string) error {
	buf := make([]byte, 0, 3+quicvarint.Len(uint64(len(msg)))+len(msg))
	buf = append(buf, status)
	buf = quicvarint.Append(buf, uint64(len(msg)))
	buf = append(buf, msg...)
	buf = quicvarint.Append(buf, 0) // padding length
	return writeAll(w, buf)
}

// readResponse parses the server's answer.
func readResponse(r io.Reader) (byte, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return 0, "", err
	}
	n, err := binary.ReadUvarint(byteReader{r})
	if err != nil {
		return 0, "", err
	}
	if n > 4096 {
		return 0, "", fmt.Errorf("hysteria: response message %d bytes", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return 0, "", err
	}
	return status[0], string(msg), nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// byteReader adapts io.Reader to io.ByteReader for varint decoding.
type byteReader struct{ r io.Reader }

func (b byteReader) ReadByte() (byte, error) {
	var c [1]byte
	if _, err := io.ReadFull(b.r, c[:]); err != nil {
		return 0, err
	}
	return c[0], nil
}

// encodeAddr serialises a SOCKS5 address.
func encodeAddr(a socks.Addr) []byte {
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			v4 := ip.As4()
			out := make([]byte, 0, 1+4+2)
			out = append(out, 0x01)
			out = append(out, v4[:]...)
			return binary.BigEndian.AppendUint16(out, a.Port)
		}
		v6 := ip.As16()
		out := make([]byte, 0, 1+16+2)
		out = append(out, 0x04)
		out = append(out, v6[:]...)
		return binary.BigEndian.AppendUint16(out, a.Port)
	}
	out := make([]byte, 0, 1+1+len(a.Host)+2)
	out = append(out, 0x03, byte(len(a.Host)))
	out = append(out, a.Host...)
	return binary.BigEndian.AppendUint16(out, a.Port)
}

// decodeAddr parses a SOCKS5 address.
func decodeAddr(b []byte) (socks.Addr, error) {
	if len(b) < 1 {
		return socks.Addr{}, errors.New("hysteria: empty address")
	}
	switch b[0] {
	case 0x01:
		if len(b) < 1+4+2 {
			return socks.Addr{}, errors.New("hysteria: short IPv4 address")
		}
		ip := net.IP(b[1:5])
		return socks.Addr{Host: ip.String(), Port: binary.BigEndian.Uint16(b[5:7])}, nil
	case 0x04:
		if len(b) < 1+16+2 {
			return socks.Addr{}, errors.New("hysteria: short IPv6 address")
		}
		ip := net.IP(b[1:17])
		return socks.Addr{Host: ip.String(), Port: binary.BigEndian.Uint16(b[17:19])}, nil
	case 0x03:
		if len(b) < 2 {
			return socks.Addr{}, errors.New("hysteria: short domain address")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return socks.Addr{}, errors.New("hysteria: truncated domain address")
		}
		return socks.Addr{
			Host: string(b[2 : 2+l]),
			Port: binary.BigEndian.Uint16(b[2+l : 2+l+2]),
		}, nil
	}
	return socks.Addr{}, fmt.Errorf("hysteria: unknown address type %d", b[0])
}

// handleStream serves one hysteria request stream: parse, dial, answer, relay.
func (st *connState) handleStream(str *quic.Stream) {
	srv := st.srv
	ctx, cancel := context.WithCancel(st.conn.Context())
	defer cancel()

	_ = str.SetReadDeadline(time.Now().Add(srv.handshakeTimeout()))
	dest, _, err := readRequest(str)
	if err != nil {
		srv.log.Debug("hysteria: bad request", "error", err)
		str.CancelRead(quic.StreamErrorCode(1))
		str.CancelWrite(quic.StreamErrorCode(1))
		return
	}
	_ = str.SetReadDeadline(time.Time{})

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", dest.String())
	if err != nil {
		_ = writeResponse(str, statusError, err.Error())
		str.CancelRead(quic.StreamErrorCode(1))
		str.Close()
		return
	}
	if err := writeResponse(str, statusOK, "connected"); err != nil {
		conn.Close()
		return
	}

	sess := &core.Session{
		UserID: st.userIDValue(),
		Dest:   dest,
		Conn:   &streamConn{Stream: str, conn: st.conn},
	}
	if relay := srv.opts.Relay; relay != nil {
		if err := relay(ctx, sess); err != nil {
			srv.log.Debug("hysteria: relay finished", "error", err)
		}
		return
	}
	// No relay wired (tests, or a node that lets the protocol forward): pipe.
	pipeStream(ctx, sess.Conn, conn)
}

// pipeStream is the fallback bidirectional copy used when Options.Relay is nil.
func pipeStream(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		closeWrite(dst)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = a.Close()
	_ = b.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// streamConn adapts *quic.Stream to net.Conn. Evidence: the binary has the same
// adapter in github.com/ANRCM0/TX-Node/internal/dataplane/qstream (qstream.New @0xa9a240, notes/rev-transport.md
// §4.5), which is another owner's package here.
type streamConn struct {
	Stream *quic.Stream
	conn   *quic.Conn
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.Stream.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.Stream.Write(p) }
func (c *streamConn) Close() error                { return c.Stream.Close() }
func (c *streamConn) CloseWrite() error           { return c.Stream.Close() }
func (c *streamConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }
func (c *streamConn) SetDeadline(t time.Time) error {
	if err := c.Stream.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Stream.SetWriteDeadline(t)
}
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.Stream.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.Stream.SetWriteDeadline(t) }
