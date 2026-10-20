// Package qstream adapts a QUIC stream (the apernet/quic-go fork kaze links)
// to net.Conn for Hysteria2 and TUIC.
//
// Evidence: notes/rev-transport.md §4.5: qstream.New @0xa9a240 wraps
// github.com/apernet/quic-go's Stream with thin methods (~0xc0 B each), and
// adds ClientIP @0xa9a460, LocalIP @0xa9a520 and SetPriority @0xa9ab40 so the
// Hysteria compatibility layer can see the peer/local address and the
// stream priority.
package qstream

import (
	"net"
	"net/netip"
	"time"

	quic "github.com/apernet/quic-go"
)

// Stream is the part of *quic.Stream the adapter uses. Keeping it an
// interface lets the UDP protocols and tests substitute a fake.
type Stream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	StreamID() quic.StreamID
}

// Prioritized is implemented by streams that accept a send priority.
type Prioritized interface {
	SetPriority(urgency int8, incremental bool)
}

// Conn is a QUIC stream seen as a net.Conn.
type Conn struct {
	stream Stream
	conn   *quic.Conn

	local  net.Addr
	remote net.Addr
}

// New wraps stream; conn may be nil when the caller only has the stream.
func New(stream *quic.Stream, conn *quic.Conn) *Conn {
	c := &Conn{stream: stream, conn: conn}
	if conn != nil {
		c.local = conn.LocalAddr()
		c.remote = conn.RemoteAddr()
	}
	return c
}

// NewWith wraps any Stream implementation (used by the UDP protocol packages
// and by tests). local/remote may be nil.
func NewWith(stream Stream, local, remote net.Addr) *Conn {
	return &Conn{stream: stream, local: local, remote: remote}
}

func (c *Conn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *Conn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *Conn) Close() error                { return c.stream.Close() }

func (c *Conn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return quicAddr("quic-local")
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return quicAddr("quic-remote")
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.stream.SetReadDeadline(t); err != nil {
		return err
	}
	return c.stream.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// StreamID is the QUIC stream id.
func (c *Conn) StreamID() quic.StreamID { return c.stream.StreamID() }

// ClientIP is the peer address the stream's connection was opened from.
func (c *Conn) ClientIP() netip.Addr { return addrIP(c.RemoteAddr()) }

// LocalIP is this side's address for the connection.
func (c *Conn) LocalIP() netip.Addr { return addrIP(c.LocalAddr()) }

// SetPriority sets the send scheduling priority (the apernet fork exposes
// (*quic.Stream).SetPriority(urgency int8, incremental bool)). Streams that do
// not implement it ignore the call.
func (c *Conn) SetPriority(urgency int8, incremental bool) {
	if p, ok := c.stream.(Prioritized); ok {
		p.SetPriority(urgency, incremental)
	}
}

// Connection exposes the underlying QUIC connection when there is one.
func (c *Conn) Connection() *quic.Conn { return c.conn }

func addrIP(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	switch v := a.(type) {
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return ip.Unmap()
		}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return ip.Unmap()
		}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

type quicAddr string

func (a quicAddr) Network() string { return "quic" }
func (a quicAddr) String() string  { return string(a) }
