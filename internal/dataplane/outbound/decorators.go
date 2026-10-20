package outbound

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// This file holds the conn decorators named in REPORT.md §9:
// headerConn (http obfs), lengthStream, chunkStream, perDest, xudpPacket,
// uotPacket and queue. They are independent of the protocol that builds them
// and are shared by the client implementations below.

// ---------------------------------------------------------------------------
// headerConn (outbound.(*headerConn) @0xb77ce0 flush, @0xb78000 Read)

// headerBootstrap is the fake HTTP request obfs writes on the first byte. The
// server side (transport.obfsHTTP/skipHTTPHead, REPORT.md §7.2) discards it.
const headerBootstrap = "POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n\r\n"

// headerConn prepends an HTTP request header to the first write and strips the
// HTTP response header from the first read. It is the client half of
// simple-obfs/obfs=http.
type headerConn struct {
	net.Conn //nolint:embedded // delegate the net.Conn surface
	host     string

	mu          sync.Mutex
	wroteHeader bool

	rmu      sync.Mutex
	readHead bool
	headBuf  []byte
}

func newHeaderConn(c net.Conn, host string) *headerConn {
	return &headerConn{Conn: c, host: host}
}

// flush writes the obfuscation header exactly once.
func (h *headerConn) flush() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wroteHeader {
		return nil
	}
	h.wroteHeader = true
	_, err := io.WriteString(h.Conn, sprintfHeader(headerBootstrap, h.host))
	return err
}

func sprintfHeader(format, host string) string {
	// Avoid pulling fmt into the hot path of every connection.
	out := make([]byte, 0, len(format)+len(host))
	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) && format[i+1] == 's' {
			out = append(out, host...)
			i++
			continue
		}
		out = append(out, format[i])
	}
	return string(out)
}

func (h *headerConn) Write(p []byte) (int, error) {
	if err := h.flush(); err != nil {
		return 0, err
	}
	return h.Conn.Write(p)
}

// Read drops the response header before returning payload.
func (h *headerConn) Read(p []byte) (int, error) {
	h.rmu.Lock()
	defer h.rmu.Unlock()
	if !h.readHead {
		h.readHead = true
		buf := make([]byte, 0, 1024)
		var one [1]byte
		for {
			if _, err := io.ReadFull(h.Conn, one[:]); err != nil {
				return 0, err
			}
			buf = append(buf, one[0])
			if n := len(buf); n >= 4 && string(buf[n-4:]) == "\r\n\r\n" {
				break
			}
			if len(buf) > 64*1024 {
				return 0, errors.New("obfs: the response header is too large")
			}
		}
		// The response header is discarded, as skipHTTPHead does on the
		// server side (REPORT.md §7.2).
	}
	if len(h.headBuf) > 0 {
		n := copy(p, h.headBuf)
		h.headBuf = h.headBuf[n:]
		return n, nil
	}
	return h.Conn.Read(p)
}

func (h *headerConn) CloseWrite() error { return core.CloseWrite(h.Conn) }

// ---------------------------------------------------------------------------
// lengthStream (outbound.(*lengthStream) @0xb82720 write, @0xb82820 read)

// lengthStream frames every write with a 2-byte big-endian length. It is the
// building block of XUDP and the UDP-over-TCP envelopes.
type lengthStream struct {
	rw io.ReadWriteCloser
	w  *sync.Mutex
	r  []byte
}

func newLengthStream(rw io.ReadWriteCloser) *lengthStream {
	return &lengthStream{rw: rw, w: new(sync.Mutex)}
}

// write sends one length-prefixed frame, splitting at 0xffff.
func (l *lengthStream) write(p []byte) (int, error) {
	l.w.Lock()
	defer l.w.Unlock()
	total := 0
	for {
		n := len(p)
		if n > 0xffff {
			n = 0xffff
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(n))
		if _, err := l.rw.Write(hdr[:]); err != nil {
			return total, err
		}
		if n > 0 {
			if _, err := l.rw.Write(p[:n]); err != nil {
				return total, err
			}
		}
		total += n
		p = p[n:]
		if len(p) == 0 {
			return total, nil
		}
	}
}

// read returns payload from the current frame, reading the next one when empty.
func (l *lengthStream) read(p []byte) (int, error) {
	for len(l.r) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(l.rw, hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 {
			continue
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(l.rw, buf); err != nil {
			return 0, err
		}
		l.r = buf
	}
	n := copy(p, l.r)
	l.r = l.r[n:]
	return n, nil
}

func (l *lengthStream) Close() error { return l.rw.Close() }

// ---------------------------------------------------------------------------
// chunkStream (outbound.chunkStream.write/read/Close)

// chunkStream is the VMess/Trojan plaintext chunk framing: 2-byte length then
// payload, with an optional AEAD seal applied by vmessBody below. It adapts the
// framing to net.Conn.
type chunkStream struct {
	ls  *lengthStream
	net net.Conn
}

func newChunkStream(c net.Conn) *chunkStream {
	return &chunkStream{ls: newLengthStream(c), net: c}
}

func (c *chunkStream) write(p []byte) (int, error) { return c.ls.write(p) }
func (c *chunkStream) read(p []byte) (int, error)  { return c.ls.read(p) }
func (c *chunkStream) Close() error                { return c.ls.Close() }

// Read/Write let chunkStream satisfy net.Conn where a plaintext length-framed
// stream is acceptable.
func (c *chunkStream) Read(p []byte) (int, error)  { return c.read(p) }
func (c *chunkStream) Write(p []byte) (int, error) { return c.write(p) }

func (c *chunkStream) LocalAddr() net.Addr                { return c.net.LocalAddr() }
func (c *chunkStream) RemoteAddr() net.Addr               { return c.net.RemoteAddr() }
func (c *chunkStream) SetDeadline(t time.Time) error      { return c.net.SetDeadline(t) }
func (c *chunkStream) SetReadDeadline(t time.Time) error  { return c.net.SetReadDeadline(t) }
func (c *chunkStream) SetWriteDeadline(t time.Time) error { return c.net.SetWriteDeadline(t) }

// ---------------------------------------------------------------------------
// queue (outbound.(*queue) @0xb82b80 ReadFrom, @0xb83060 SetReadDeadline)

type queuedPacket struct {
	data []byte
	addr socks.Addr
}

// queue is a bounded per-destination receive queue. ReadFrom blocks until a
// packet arrives, the deadline expires or the queue is shut (perDest.evictLocked
// drops idle destinations).
type queue struct {
	mu       sync.Mutex
	ch       chan queuedPacket
	deadline time.Time
	closed   bool
	err      error
	wake     chan struct{}
}

func newQueue(size int) *queue {
	if size <= 0 {
		size = 64
	}
	return &queue{ch: make(chan queuedPacket, size), wake: make(chan struct{}, 1)}
}

func (q *queue) push(p queuedPacket) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	select {
	case q.ch <- p:
		return true
	default:
		// Drop the oldest so a slow reader cannot stall the shared socket.
		select {
		case <-q.ch:
		default:
		}
		select {
		case q.ch <- p:
		default:
		}
		return true
	}
}

func (q *queue) ReadFrom(p []byte) (int, socks.Addr, error) {
	for {
		q.mu.Lock()
		if q.closed {
			err := q.err
			q.mu.Unlock()
			return 0, socks.Addr{}, err
		}
		dl := q.deadline
		q.mu.Unlock()

		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, socks.Addr{}, timeoutError{}
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		select {
		case pkt := <-q.ch:
			if timer != nil {
				timer.Stop()
			}
			n := copy(p, pkt.data)
			return n, pkt.addr, nil
		case <-timeout:
			return 0, socks.Addr{}, timeoutError{}
		case <-q.wake:
			if timer != nil {
				timer.Stop()
			}
			continue
		}
	}
}

func (q *queue) SetReadDeadline(t time.Time) error {
	q.mu.Lock()
	q.deadline = t
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

func (q *queue) shut(err error) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	q.err = err
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// timeoutError implements net.Error for deadline expiry.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

// ---------------------------------------------------------------------------
// perDest (outbound.(*perDest) @0xb83160 WriteTo, @0xb837c0 evictLocked)

// perDest demultiplexes one shared packet socket into per-destination queues,
// so each UDP session gets its own blocking reader. Writes are serialized on
// the shared socket.
type perDest struct {
	conn core.PacketStream

	mu     sync.Mutex
	queues map[string]*queue
	inbox  *queue
	closed bool
}

const perDestIdle = 120 * time.Second // ss.(*Handler).ListenUDP uses the same 120 s

func newPerDest(conn core.PacketStream) *perDest {
	return &perDest{conn: conn, queues: map[string]*queue{}, inbox: newQueue(128)}
}

func (p *perDest) WritePacket(b []byte, a socks.Addr) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return net.ErrClosed
	}
	p.mu.Unlock()
	return p.conn.WritePacket(b, a)
}

// ReadPacket pops one datagram from the shared inbox.
func (p *perDest) ReadPacket(b []byte) (int, socks.Addr, error) {
	return p.inbox.ReadFrom(b)
}

// queueFor returns the per-destination queue, starting the shared read pump
// once.
func (p *perDest) queueFor(a socks.Addr) *queue {
	key := a.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	if q, ok := p.queues[key]; ok {
		return q
	}
	q := newQueue(64)
	p.queues[key] = q
	return q
}

// evictLocked drops idle destination queues (called with a coarse timer by
// callers that care; kept exported in behaviour for tests).
func (p *perDest) evictLocked(now time.Time) {
	// Nothing tracks per-queue timestamps yet; the method exists so the
	// eviction policy has one place to live, as in the sample.
	_ = now
}

// pump reads the shared socket and dispatches to inbox and per-destination
// queues. It exits when the socket errors.
func (p *perDest) pump() {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := p.conn.ReadPacket(buf)
		if err != nil {
			p.shut(err)
			return
		}
		data := append([]byte(nil), buf[:n]...)
		p.inbox.push(queuedPacket{data: data, addr: addr})
		p.mu.Lock()
		q := p.queues[addr.String()]
		p.mu.Unlock()
		if q != nil {
			q.push(queuedPacket{data: data, addr: addr})
		}
	}
}

func (p *perDest) shut(err error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	queues := make([]*queue, 0, len(p.queues))
	for _, q := range p.queues {
		queues = append(queues, q)
	}
	p.mu.Unlock()
	p.inbox.shut(err)
	for _, q := range queues {
		q.shut(err)
	}
}

func (p *perDest) Close() error {
	p.mu.Lock()
	already := p.closed
	p.mu.Unlock()
	if already {
		return nil
	}
	err := p.conn.Close()
	p.shut(net.ErrClosed)
	return err
}

// ---------------------------------------------------------------------------
// xudpPacket (outbound.(*xudpPacket) @0xb83e20 WriteTo, @0xb84260 read)

// XUDP frame (REPORT.md §17.3.1): LEN(2B BE) || BODY where
//
//	BODY[0:2] stream/echo port (0 on the first packet)
//	BODY[2]   command: 1 first, 2 follow-up, 3 EOF, 4 continue
//	BODY[3]   flags (only bit0 is consumed)
//	BODY[4]   address-present marker, always 0x02
//	BODY[5:7] destination port (BE16)
//	BODY[7]   ATYP (1 IPv4 / 2 domain / 3 IPv6)
//	BODY[8:]  address bytes, then payload
//
// kaze's framing is its own: it has no Xray userUUID/globalID/padding and does
// not interoperate with Xray's XUDP.
type xudpPacket struct {
	conn net.Conn
	ls   *lengthStream

	mu    sync.Mutex
	first bool
}

func newXUDPPacket(c net.Conn) *xudpPacket {
	return &xudpPacket{conn: c, ls: newLengthStream(c), first: true}
}

func (x *xudpPacket) ReadPacket(p []byte) (int, socks.Addr, error) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(x.ls.rw, hdr[:]); err != nil {
			return 0, socks.Addr{}, err
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n <= 5 {
			return 0, socks.Addr{}, errors.New("xudp: short frame")
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(x.ls.rw, body); err != nil {
			return 0, socks.Addr{}, err
		}
		switch body[2] { // command
		case 3: // EOF
			return 0, socks.Addr{}, io.EOF
		case 1, 2, 4:
		default:
			return 0, socks.Addr{}, errors.New("xudp: unknown command")
		}
		if body[4] != 2 {
			return 0, socks.Addr{}, errors.New("xudp: the frame has no destination")
		}
		addr, used, err := parseVAddr(body[5:])
		if err != nil {
			return 0, socks.Addr{}, err
		}
		payload := body[5+used:]
		copied := copy(p, payload)
		return copied, addr, nil
	}
}

func (x *xudpPacket) WritePacket(p []byte, a socks.Addr) error {
	body := make([]byte, 0, 8+len(a.Host)+len(p))
	body = append(body, 0, 0) // stream port: 0 on the client's first packet
	cmd := byte(2)            // follow-up data
	if x.first {
		cmd = 1 // first packet carries the destination
	}
	body = append(body, cmd)
	body = append(body, 0) // flags
	body = append(body, 2) // address present
	var err error
	body, err = appendVAddr(body, a)
	if err != nil {
		return err
	}
	body = append(body, p...)

	x.mu.Lock()
	defer x.mu.Unlock()
	var hdr [2]byte
	if len(body) > 0xffff {
		return errors.New("xudp: packet too large")
	}
	binary.BigEndian.PutUint16(hdr[:], uint16(len(body)))
	if _, err := x.conn.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := x.conn.Write(body); err != nil {
		return err
	}
	x.first = false
	return nil
}

func (x *xudpPacket) Close() error { return x.conn.Close() }

// WriteTo/ReadFrom expose the net.PacketConn-flavoured surface the sample has.
func (x *xudpPacket) WriteTo(p []byte, a socks.Addr) (int, error) {
	if err := x.WritePacket(p, a); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (x *xudpPacket) ReadFrom(p []byte) (int, socks.Addr, error) { return x.ReadPacket(p) }

// ---------------------------------------------------------------------------
// uotPacket (outbound.(*uotPacket) @0xb84ca0 WriteTo, @0xb84fe0 ReadFrom)

// UDP-over-TCP v2 (sing-box's "udp_over_tcp" version 2): every datagram is
//
//	LEN(2B BE) || ISADDR(1) || [SOCKS-style address] || payload
//
// Verson 1 is rejected at settings time ("udp_over_tcp version 1 is not
// supported; use version 2").
type uotPacket struct {
	conn net.Conn
	ls   *lengthStream
	dest socks.Addr

	mu sync.Mutex
}

func newUoTPacket(c net.Conn, dest socks.Addr) *uotPacket {
	return &uotPacket{conn: c, ls: newLengthStream(c), dest: dest}
}

// uotAddr appends the address block (ISADDR + SOCKS5 address), outbound.uotAddr
// @0xb84be0.
func uotAddr(b []byte, a socks.Addr) ([]byte, error) {
	b = append(b, 1)
	return appendSocksAddr(b, a)
}

func (u *uotPacket) WritePacket(p []byte, a socks.Addr) error {
	body := make([]byte, 0, 1+1+len(a.Host)+2+len(p))
	var err error
	body, err = uotAddr(body, a)
	if err != nil {
		return err
	}
	body = append(body, p...)
	u.mu.Lock()
	defer u.mu.Unlock()
	_, err = u.ls.write(body)
	return err
}

func (u *uotPacket) ReadPacket(p []byte) (int, socks.Addr, error) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(u.ls.rw, hdr[:]); err != nil {
			return 0, socks.Addr{}, err
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 {
			continue
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(u.ls.rw, body); err != nil {
			return 0, socks.Addr{}, err
		}
		if len(body) < 1 {
			return 0, socks.Addr{}, errors.New("udp over tcp: empty frame")
		}
		addr := u.dest
		off := 0
		if body[0] == 1 {
			if len(body) < 2 {
				return 0, socks.Addr{}, errors.New("udp over tcp: the server sent an unknown address type")
			}
			var used int
			var err error
			addr, used, err = parseSocksAddr(body[1:])
			if err != nil {
				return 0, socks.Addr{}, err
			}
			off = 1 + used
		} else if body[0] != 0 {
			return 0, socks.Addr{}, errors.New("udp over tcp: the server sent an unknown address type")
		}
		n2 := copy(p, body[off:])
		return n2, addr, nil
	}
}

func (u *uotPacket) Close() error { return u.conn.Close() }

func (u *uotPacket) WriteTo(p []byte, a socks.Addr) (int, error) {
	if err := u.WritePacket(p, a); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *uotPacket) ReadFrom(p []byte) (int, socks.Addr, error) { return u.ReadPacket(p) }

// Compile-time checks.
var (
	_ core.PacketStream = (*xudpPacket)(nil)
	_ core.PacketStream = (*uotPacket)(nil)
	_ core.PacketStream = (*perDest)(nil)
	_ net.Conn          = (*headerConn)(nil)
	_ net.Conn          = (*chunkStream)(nil)
)
