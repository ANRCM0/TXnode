package core

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// ServeSession is (*Server).ServeSession @0x7b18c0: the entry point every
// successfully authenticated session goes through, including sessions handed
// over by QUIC protocols (hysteria/tuic) through their Relay callback.
//
// Dispatch order (notes/rev-core.md §2.2, notes/rev-proto-tcp.md §B):
//
//	Dest.Host == "sp.mux.sing-box.arpa"      -> serveMux
//	Dest.Host == "sp.udp-over-tcp.arpa"      -> UoT v1 -> relayUDP
//	Dest.Host == "sp.v2.udp-over-tcp.arpa"   -> UoT v2 -> relayUDP
//	Session.Packets != nil                   -> servePackets -> relayUDP
//	otherwise                                -> relayTCP
//
// The tracker quota is reserved here, before any relay work, and released when
// the session ends. The TCP accept path calls serveSession directly after
// reserving the same quota, so a session is never counted twice.
func (s *Server) ServeSession(ctx context.Context, sess *Session) error {
	if sess == nil {
		return errors.New("session refused: nil session")
	}
	if sess.ConnID == 0 {
		sess.ConnID = s.connSeq.Add(1)
	}
	if o := s.snapshot(); o.Admission != nil && !o.Admission() {
		if sess.Conn != nil {
			_ = sess.Conn.Close()
		}
		if sess.Packets != nil {
			_ = sess.Packets.Close()
		}
		return errors.New("session refused: admission closed")
	}
	if sess.Conn == nil && sess.Packets == nil {
		return errors.New("session refused: no transport")
	}
	src := clientIP(sess.Conn)
	o := s.snapshot()
	lease, ok := s.acquire(sess, src, o.Logger)
	if !ok {
		if sess.Conn != nil {
			_ = sess.Conn.Close()
		}
		return ErrSessionRefused
	}
	defer lease.Release()
	if u, ok := sess.Packets.(*uotStream); ok {
		// The UoT stream owns the TCP connection.
		defer u.Close()
	}
	return s.serveSession(ctx, sess, src)
}

// serveSession dispatches an already-accounted session.
func (s *Server) serveSession(ctx context.Context, sess *Session, src netip.Addr) error {
	switch strings.ToLower(sess.Dest.Host) {
	case "sp.mux.sing-box.arpa", "v1.mux.cool":
		// v1.mux.cool is the VLESS cmd==3 pseudo-destination; the stream framing
		// is the address-header mux used by the smux/yamux transports.
		return s.serveMux(ctx, sess, src)
	case "sp.udp-over-tcp.arpa":
		if sess.Packets == nil {
			if sess.Conn == nil {
				return errors.New("session refused: no transport")
			}
			sess.Packets = NewUoT(sess.Conn, 1)
		}
		return s.servePackets(ctx, sess)
	case "sp.v2.udp-over-tcp.arpa":
		if sess.Packets == nil {
			if sess.Conn == nil {
				return errors.New("session refused: no transport")
			}
			sess.Packets = NewUoT(sess.Conn, 2)
		}
		return s.servePackets(ctx, sess)
	}
	if sess.Packets != nil {
		return s.servePackets(ctx, sess)
	}
	return s.relayTCP(ctx, sess)
}

// MuxRelay is the per-stream callback core hands to the mux implementation: the
// mux package reports a fresh stream plus its SOCKS destination and core relays
// it exactly like a normal TCP session (../mux owns the framing). packets is
// non-nil for a UDP stream (flags bit 0) and then conn is nil.
type MuxRelay func(ctx context.Context, conn net.Conn, packets PacketStream, dest socks.Addr) error

type muxServerFunc func(ctx context.Context, parent *Session, src netip.Addr, conn net.Conn, relay MuxRelay) error

var muxServer atomic.Pointer[muxServerFunc]

// SetMuxServer installs the mux implementation used for
// sp.mux.sing-box.arpa / v1.mux.cool sessions (internal/mux.Serve @0x773b40).
// Keeping it behind a hook avoids a core -> mux import cycle: mux needs
// socks/core types, core only needs the callback.
func SetMuxServer(fn func(ctx context.Context, parent *Session, src netip.Addr, conn net.Conn, relay MuxRelay) error) {
	if fn == nil {
		return
	}
	f := muxServerFunc(fn)
	muxServer.Store(&f)
}

// InstallMuxServer bridges an application-owned mux server into this Server.
// The application keeps the framing and the Server keeps routing, accounting,
// audit and admission.
func (s *Server) InstallMuxServer(serve func(ctx context.Context, parent *Session, src netip.Addr, conn net.Conn, relay MuxRelay) error) {
	SetMuxServer(serve)
}

// MuxStreamSession builds the child session for one mux stream and relays it.
// Streams share the parent lease: the parent was already accounted by
// ServeSession, and charging or gating each stream again would let one
// multiplexed connection exceed the device/connection limits.
func (s *Server) MuxStreamSession(ctx context.Context, parent *Session, src netip.Addr, conn net.Conn, packets PacketStream, dest socks.Addr) error {
	if parent == nil {
		if conn != nil {
			_ = conn.Close()
		}
		if packets != nil {
			_ = packets.Close()
		}
		return errors.New("mux: stream without a parent session")
	}
	child := &Session{
		UserID:  parent.UserID,
		Dest:    dest,
		Conn:    conn,
		Packets: packets,
		Local:   parent.Local,
		Socket:  tcpWriter(conn),
	}
	return s.serveSession(ctx, child, src)
}

// serveMux is (*Server).serveMux @0x7b2200. Streams share the parent session's
// user and local address; each stream gets its own route/dial.
func (s *Server) serveMux(ctx context.Context, sess *Session, src netip.Addr) error {
	fn := muxServer.Load()
	if fn == nil {
		return errors.New("mux: no mux server installed")
	}
	if sess.Conn == nil {
		return errors.New("session refused: no transport")
	}
	return (*fn)(ctx, sess, src, sess.Conn, func(ctx context.Context, conn net.Conn, packets PacketStream, dest socks.Addr) error {
		return s.MuxStreamSession(ctx, sess, src, conn, packets, dest)
	})
}
