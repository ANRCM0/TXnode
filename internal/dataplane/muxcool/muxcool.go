package muxcool

// Server side of Xray Mux.Cool ("v1.mux.cool"), the multiplexing Xray uses when
// `mux.enabled` is set. It is a different protocol from the sing-box
// address-header mux in internal/dataplane/mux:
//
//	metadata: LEN(2 BE) | SESSION_ID(2) | STATUS(1) | OPTION(1)
//	          STATUS=NEW adds NETWORK(1) + ADDRESS/PORT
//	          OPTION bit0 (Data) means a chunked body follows
//	body:     (SIZE(2 BE) | payload)*  (Xray's PlainChunkSizeParser, 8192 chunks)
//
// One connection interleaves frames of every session, so a single reader
// demultiplexes: each frame's chunked body is appended to that session's pipe.
// The server answers with KEEP frames on the same connection.
//
// Evidence: xray-core common/mux ({frame.go,server.go,writer.go,reader.go},
// v26.3.27). UDP sessions travel as XUDP inside the chunked body and are not
// carried here; a NEW UDP session is closed with an End frame.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Session status and option constants (common/mux/frame.go).
const (
	StatusNew       = 0x01
	StatusKeep      = 0x02
	StatusEnd       = 0x03
	StatusKeepAlive = 0x04

	OptionData = 1 << 0
)

// Target network values.
const (
	NetworkTCP = 0x01
	NetworkUDP = 0x02
)

const (
	// maxMetadata bounds the metadata length field (Xray rejects >512).
	maxMetadata = 512
	// chunkSize is the plain chunk payload size Xray writes.
	chunkSize = 8192
)

// Metadata is one decoded Mux.Cool frame header.
type Metadata struct {
	SessionID uint16
	Status    byte
	Option    byte
	Network   byte
	Dest      socks.Addr
	HasTarget bool
}

// HasData reports whether a chunked body follows the metadata.
func (m *Metadata) HasData() bool { return m.Option&OptionData != 0 }

// readMetadata decodes one frame header.
func readMetadata(r io.Reader) (*Metadata, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 4 || n > maxMetadata {
		return nil, fmt.Errorf("muxcool: metadata length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	m := &Metadata{
		SessionID: binary.BigEndian.Uint16(body[0:2]),
		Status:    body[2],
		Option:    body[3],
	}
	if m.Status != StatusNew && m.Status != StatusKeep {
		return m, nil
	}
	// NEW always carries a target; a KEEP only when it switches to a UDP target.
	if m.Status == StatusKeep && (len(body) <= 4 || body[4] != NetworkUDP) {
		return m, nil
	}
	if len(body) < 8 {
		return nil, errors.New("muxcool: short target")
	}
	m.Network = body[4]
	dest, _, err := readAddress(body[5:])
	if err != nil {
		return nil, err
	}
	m.Dest = dest
	m.HasTarget = true
	return m, nil
}

// writeMetadata serialises a NEW, KEEP-without-body, KeepAlive or End frame.
func writeMetadata(w io.Writer, m *Metadata) error {
	body := make([]byte, 0, 32)
	var id [2]byte
	binary.BigEndian.PutUint16(id[:], m.SessionID)
	body = append(body, id[:]...)
	body = append(body, m.Status, m.Option)
	if m.Status == StatusNew {
		body = append(body, NetworkTCP)
		body = appendAddress(body, m.Dest)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// readAddress decodes Xray's port-then-address encoding: PORT(2) | ATYP |
// address (protocol.PortThenAddress).
func readAddress(b []byte) (socks.Addr, int, error) {
	if len(b) < 3 {
		return socks.Addr{}, 0, errors.New("muxcool: short address")
	}
	port := binary.BigEndian.Uint16(b)
	switch b[2] {
	case 1:
		if len(b) < 7 {
			return socks.Addr{}, 0, errors.New("muxcool: short ipv4")
		}
		return socks.Addr{Host: net.IP(b[3:7]).String(), Port: port}, 7, nil
	case 2:
		if len(b) < 4 {
			return socks.Addr{}, 0, errors.New("muxcool: short domain")
		}
		l := int(b[3])
		if len(b) < 4+l {
			return socks.Addr{}, 0, errors.New("muxcool: short domain body")
		}
		return socks.Addr{Host: string(b[4 : 4+l]), Port: port}, 4 + l, nil
	case 3:
		if len(b) < 19 {
			return socks.Addr{}, 0, errors.New("muxcool: short ipv6")
		}
		return socks.Addr{Host: net.IP(b[3:19]).String(), Port: port}, 19, nil
	}
	return socks.Addr{}, 0, fmt.Errorf("muxcool: address type %d", b[2])
}

func appendAddress(b []byte, a socks.Addr) []byte {
	b = binary.BigEndian.AppendUint16(b, a.Port)
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			v4 := ip.As4()
			b = append(b, 1)
			b = append(b, v4[:]...)
		} else {
			v6 := ip.As16()
			b = append(b, 3)
			b = append(b, v6[:]...)
		}
	} else {
		b = append(b, 2, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	return b
}

// Stream is one Mux.Cool session as a net.Conn: reads drain the demultiplexer
// pipe, writes emit a KEEP frame with a chunked body.
type Stream struct {
	conn net.Conn
	pr   *io.PipeReader
	mu   sync.Mutex
	id   uint16
	dest socks.Addr
	done bool
}

// Read reads application bytes delivered to this session.
func (s *Stream) Read(p []byte) (int, error) { return s.pr.Read(p) }

// Write writes application bytes as chunked payload inside a KEEP frame.
func (s *Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunkSize {
			n = chunkSize
		}
		// LEN(2)=4 | SESSION_ID(2) | STATUS | OPTION | SIZE(2) | payload
		buf := make([]byte, 0, 6+2+n)
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], 4)
		buf = append(buf, lenBuf[:]...)
		var id [2]byte
		binary.BigEndian.PutUint16(id[:], s.id)
		buf = append(buf, id[:]...)
		buf = append(buf, StatusKeep, OptionData)
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(n))
		buf = append(buf, size[:]...)
		buf = append(buf, p[:n]...)
		if _, err := s.conn.Write(buf); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite terminates the chunked body with a zero-size chunk and then sends
// an End frame. The peer's chunk reader treats the zero chunk as EOF, so the
// following End metadata is not mistaken for payload (Xray's own writer closes
// the body the same way).
func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil
	}
	s.done = true
	if _, err := s.conn.Write([]byte{0, 0}); err != nil {
		return err
	}
	return writeMetadata(s.conn, &Metadata{SessionID: s.id, Status: StatusEnd})
}

// Close ends the session; the read side closes when the peer ends it or the
// connection dies.
func (s *Stream) Close() error {
	_ = s.CloseWrite()
	return nil
}

// LocalAddr implements net.Conn.
func (s *Stream) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// RemoteAddr implements net.Conn.
func (s *Stream) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// SetDeadline implements net.Conn.
func (s *Stream) SetDeadline(t time.Time) error { return s.conn.SetDeadline(t) }

// SetReadDeadline implements net.Conn.
func (s *Stream) SetReadDeadline(t time.Time) error { return s.conn.SetReadDeadline(t) }

// SetWriteDeadline implements net.Conn.
func (s *Stream) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// Handler relays one Mux.Cool session.
type Handler func(id uint16, dest socks.Addr, stream *Stream) error

type session struct {
	stream *Stream
	pw     *io.PipeWriter
}

// Serve demultiplexes one Mux.Cool connection and relays every NEW TCP session
// with h.
//
// Framing note: the sender switches frames only at chunk boundaries, so one
// reader goroutine owns the connection. It parses each metadata frame and then
// copies that frame's chunked body into the session pipe before parsing the
// next frame. A session that keeps streaming therefore holds the connection
// until it ends, which matches how Xray's own server reads its mux link.
func Serve(conn net.Conn, h Handler) error {
	br := bufio.NewReader(conn)
	open := make(map[uint16]*session)
	defer func() {
		for _, s := range open {
			_ = s.pw.Close()
		}
	}()

	for {
		meta, err := readMetadata(br)
		if err != nil {
			return err
		}
		switch meta.Status {
		case StatusNew:
			if !meta.HasTarget {
				return errors.New("muxcool: NEW without target")
			}
			if meta.Network != NetworkTCP {
				// xudp sessions are not carried; end the session so the peer
				// fails cleanly.
				_ = writeMetadata(conn, &Metadata{SessionID: meta.SessionID, Status: StatusEnd})
				if meta.HasData() {
					_, _ = io.Copy(io.Discard, &chunkReader{r: br})
				}
				continue
			}
			pr, pw := io.Pipe()
			st := &Stream{conn: conn, pr: pr, id: meta.SessionID, dest: meta.Dest}
			open[meta.SessionID] = &session{stream: st, pw: pw}
			go func(id uint16, dest socks.Addr, st *Stream) {
				_ = h(id, dest, st)
				_ = st.CloseWrite()
			}(meta.SessionID, meta.Dest, st)
			if meta.HasData() {
				// Blocks until this frame's chunked body ends; that is the next
				// frame boundary.
				_, _ = io.Copy(pw, &chunkReader{r: br})
			}
		case StatusKeep:
			s := open[meta.SessionID]
			if s == nil {
				_ = writeMetadata(conn, &Metadata{SessionID: meta.SessionID, Status: StatusEnd})
				if meta.HasData() {
					_, _ = io.Copy(io.Discard, &chunkReader{r: br})
				}
				continue
			}
			if meta.HasData() {
				if _, err := io.Copy(s.pw, &chunkReader{r: br}); err != nil {
					_ = s.pw.Close()
					delete(open, meta.SessionID)
				}
			}
		case StatusEnd:
			if s := open[meta.SessionID]; s != nil {
				_ = s.pw.Close()
				delete(open, meta.SessionID)
			}
			if meta.HasData() {
				_, _ = io.Copy(io.Discard, &chunkReader{r: br})
			}
		case StatusKeepAlive:
			if meta.HasData() {
				_, _ = io.Copy(io.Discard, &chunkReader{r: br})
			}
		default:
			return errors.New("muxcool: unknown status")
		}
	}
}

// chunkReader decodes Xray's plain chunk stream: SIZE(2 BE) then payload,
// repeated until the reader returns EOF.
type chunkReader struct {
	r      io.Reader
	remain int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for c.remain == 0 {
		var size [2]byte
		if _, err := io.ReadFull(c.r, size[:]); err != nil {
			return 0, err
		}
		c.remain = int(binary.BigEndian.Uint16(size[:]))
		if c.remain == 0 {
			continue
		}
	}
	if c.remain < len(p) {
		p = p[:c.remain]
	}
	n, err := c.r.Read(p)
	c.remain -= n
	return n, err
}
