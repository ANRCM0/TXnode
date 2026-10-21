package mux

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/xtaci/smux"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Pool is the client mux pool: several sessions share one mux connection.
// Evidence: REPORT.md §7.1 ("muxPool != nil -> muxPool_dial 0xb54880") and
// §7.5 ("muxPool.dial / (*muxPool).conn" 0xb53440); each stream starts with a
// SOCKS address header (readStreamRequest 0x774de0).
type Pool struct {
	mu      sync.Mutex
	kind    byte
	maxLive int
	// Brutal is the receive rate announced to the server (bytes/s); 0 disables
	// the _BrutalBwExchange negotiation.
	Brutal   uint64
	sessions []*poolSession
	closed   bool
}

type poolSession struct {
	conn    net.Conn
	smux    *smux.Session
	yamux   *yamux.Session
	streams int
	closed  bool
}

// NewPool returns a client pool. kind is KindSmux (default) or KindYamux; the
// server sniffs it from the second byte, so both ends agree.
func NewPool(kind byte) *Pool {
	if kind != KindYamux {
		kind = KindSmux
	}
	return &Pool{kind: kind, maxLive: 8}
}

// Dial opens (or reuses) a stream to dest. dial is called only when a new mux
// connection is needed; it must return a secured connection (TLS/REALITY
// already applied).
func (p *Pool) Dial(ctx context.Context, dest socks.Addr, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	stream, err := p.dial(ctx, 0, dest, dial)
	if err != nil {
		return nil, err
	}
	return &responseConn{Conn: stream}, nil
}

// DialPacket opens a stream marked as UDP (flags bit 0) and returns the packet
// adapter. The peer's mux handler sees Session.Packets instead of Session.Conn.
func (p *Pool) DialPacket(ctx context.Context, dest socks.Addr, dial func(context.Context) (net.Conn, error)) (*Packets, error) {
	stream, err := p.dial(ctx, FlagUDP|FlagAddr, dest, dial)
	if err != nil {
		return nil, err
	}
	return newClientPackets(stream, FlagUDP|FlagAddr, dest), nil
}

func (p *Pool) dial(ctx context.Context, flags uint16, dest socks.Addr, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	stream, err := p.open(flags, dest)
	if err == nil {
		return stream, nil
	}
	if !errors.Is(err, errNoSession) {
		// A dead session was dropped by open; retry once on a fresh one.
	}
	c, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := p.add(c); err != nil {
		c.Close()
		return nil, err
	}
	stream, err = p.open(flags, dest)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

var errNoSession = errors.New("mux: no session")

func (p *Pool) open(flags uint16, dest socks.Addr) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	for _, s := range p.sessions {
		if s.closed {
			continue
		}
		var stream net.Conn
		var err error
		switch {
		case s.smux != nil:
			stream, err = s.smux.OpenStream()
		case s.yamux != nil:
			stream, err = s.yamux.OpenStream()
		default:
			continue
		}
		if err != nil {
			s.closed = true
			continue
		}
		if err := WriteStreamRequest(stream, flags, dest); err != nil {
			stream.Close()
			s.closed = true
			continue
		}
		s.streams++
		return stream, nil
	}
	return nil, errNoSession
}

func (s *poolSession) open() (net.Conn, error) {
	switch {
	case s.smux != nil:
		return s.smux.OpenStream()
	case s.yamux != nil:
		return s.yamux.OpenStream()
	}
	return nil, errNoSession
}

func (p *Pool) add(c net.Conn) error {
	// Protocol prefix: version 0 (only 0/1 are accepted by Serve), then the
	// kind byte (notes/rev-transport.md §4.1/§4.2).
	if _, err := c.Write([]byte{0, p.kind}); err != nil {
		return err
	}
	s := &poolSession{conn: c}
	if p.Brutal > 0 {
		if st, err := s.open(); err == nil {
			_ = st.SetDeadline(time.Now().Add(10 * time.Second))
			if werr := WriteStreamRequest(st, 0, socks.Addr{Host: BrutalExchangeHost}); werr == nil {
				if rate, xerr := ClientExchange(st, p.Brutal); xerr == nil {
					_ = SetBrutal(c, rate)
				}
			}
			st.Close()
		}
	}
	switch p.kind {
	case KindYamux:
		ys, err := yamux.Client(c, YamuxConfig())
		if err != nil {
			return err
		}
		s.yamux = ys
	default:
		ss, err := smux.Client(c, SmuxConfig())
		if err != nil {
			return err
		}
		s.smux = ss
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Forget sessions whose underlying connection died (smux/yamux expose it
	// through IsClosed / CloseChan).
	live := p.sessions[:0]
	for _, old := range p.sessions {
		if old.closed || old.isClosed() {
			continue
		}
		live = append(live, old)
	}
	p.sessions = append(live, s)
	return nil
}

func (s *poolSession) isClosed() bool {
	switch {
	case s.smux != nil:
		return s.smux.IsClosed()
	case s.yamux != nil:
		select {
		case <-s.yamux.CloseChan():
			return true
		default:
			return false
		}
	}
	return true
}

// Close closes every mux connection.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, s := range p.sessions {
		if s.smux != nil {
			_ = s.smux.Close()
		}
		if s.yamux != nil {
			_ = s.yamux.Close()
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}
	p.sessions = nil
	return nil
}

// KeepAlive is a no-op hook kept for the client's optional keep-alive period.
func (p *Pool) KeepAlive(time.Duration) {}
