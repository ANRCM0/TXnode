package txnode

// Server side of the mux transports (Xray "Mux.Cool" / sing-box "multiplex").
//
// A multiplexed client opens one transport connection and then sends every
// proxy session as a stream whose head is the SOCKS address header. The
// session destination is the mux pseudo-host (sp.mux.sing-box.arpa or
// v1.mux.cool), which core.ServeSession dispatches to the relay installed
// through core.SetMuxServer. Before this file the data plane implemented mux
// but nothing installed the server, so every mux-enabled client failed with
// "mux: no mux server installed".
//
// The bridge is installed once per process and resolves the active kernel at
// call time, so a reload (Start swapping the listener) keeps working and Stop
// makes new mux sessions fail closed.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/mux"
	"github.com/ANRCM0/TX-Node/internal/dataplane/muxcool"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
	"github.com/ANRCM0/TX-Node/internal/dataplane/transport"
)

var (
	activeMux    atomic.Pointer[Kernel]
	muxInstalled atomic.Bool
)

// installMuxServer wires the data plane's mux hooks to internal/dataplane/mux.
// It is idempotent; every Start calls it, the installed functions resolve the
// running kernel per session.
func installMuxServer() {
	if !muxInstalled.CompareAndSwap(false, true) {
		return
	}
	// kind 2 (HTTP/2) borrows the transport HTTP/2 server; its per-stream
	// callback already builds a core.Session, so the bridge only has to hand it
	// the parent context and the mux relay.
	mux.H2Conn = func(ctx context.Context, conn net.Conn, h mux.Handler) error {
		parent := muxParent(ctx)
		return transport.ServeMuxH2(ctx, conn, parent, func(ctx context.Context, sess *core.Session) error {
			rt := activeMux.Load()
			if rt == nil || rt.srv == nil {
				return errors.New("mux: the node is not running")
			}
			_ = h
			// ServeMuxH2 already parsed the stream request, so the stream only
			// needs the shared child-session relay.
			child := sess.Conn
			if child != nil {
				child = &singboxStreamShim{Conn: child}
			}
			return rt.srv.MuxStreamSession(ctx, parent, netip.Addr{}, child, sess.Packets, sess.Dest)
		})
	}
	core.SetMuxCoolServer(func(ctx context.Context, parent *core.Session, src netip.Addr, conn net.Conn, relay core.MuxCoolRelay) error {
		rt := activeMux.Load()
		if rt == nil || rt.srv == nil {
			return errors.New("mux: the node is not running")
		}
		err := muxcool.Serve(conn, func(_ uint16, dest socks.Addr, stream *muxcool.Stream) error {
			return relay(ctx, stream, dest)
		})
		return err
	})
	core.SetMuxServer(func(ctx context.Context, parent *core.Session, src netip.Addr, conn net.Conn, relay core.MuxRelay) error {
		rt := activeMux.Load()
		if rt == nil || rt.srv == nil {
			return errors.New("mux: the node is not running")
		}
		return mux.Serve(withMuxParent(ctx, parent), conn, func(ctx context.Context, s *mux.Session) error {
			child := s.Conn
			if child != nil {
				child = &singboxStreamShim{Conn: child}
			}
			return relay(ctx, child, packetsOf(s), s.Dest)
		})
	})
}

// muxParent carries the parent session through the h2 callback, whose signature
// only receives the child session.
type muxParentKey struct{}

func withMuxParent(ctx context.Context, parent *core.Session) context.Context {
	return context.WithValue(ctx, muxParentKey{}, parent)
}

func muxParent(ctx context.Context) *core.Session {
	if p, ok := ctx.Value(muxParentKey{}).(*core.Session); ok {
		return p
	}
	return &core.Session{}
}

// packetsOf adapts a UDP mux stream; mux.Session exposes Conn or Packets.
// singboxStreamShim reproduces the first-payload lifeline of the sing-box mux
// client. sing-box 1.14 (smux and yamux alike) drops the first byte of the
// server's first stream payload, so the reference server prefixes the record
// with one framing byte that the client consumes. Without the prefix the client
// parses the response one byte short ("malformed HTTP version \"TTP/1.1\"").
//
// The shim is applied only to multiplexed child streams, and only to the first
// write, so ordinary sessions and binary payloads are untouched.
type singboxStreamShim struct {
	net.Conn
	first bool
}

func (c *singboxStreamShim) Write(p []byte) (int, error) {
	if !c.first {
		c.first = true
		if _, err := c.Conn.Write([]byte{0}); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(p)
}

func (c *singboxStreamShim) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func packetsOf(s *mux.Session) core.PacketStream {
	if s.Packets == nil {
		return nil
	}
	return s.Packets
}

// publishMux makes k the kernel that answers mux sessions.
func publishMux(k *Kernel) { activeMux.Store(k) }

// unpublishMux clears k when it is still the active kernel.
func unpublishMux(k *Kernel) {
	for {
		cur := activeMux.Load()
		if cur == nil || cur != k {
			return
		}
		if activeMux.CompareAndSwap(cur, nil) {
			return
		}
	}
}
