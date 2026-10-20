package txnode

// Mux hooks are process-wide framing adapters. Every child is handed back to
// the relay supplied by its owning core.Server; no active-kernel lookup may
// select another Node instance's users, routes or meter.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/mux"
	"github.com/ANRCM0/TX-Node/internal/dataplane/muxcool"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
	"github.com/ANRCM0/TX-Node/internal/dataplane/transport"
)

var muxInstalled atomic.Bool

func installMuxServer() {
	if !muxInstalled.CompareAndSwap(false, true) {
		return
	}
	mux.H2Conn = func(ctx context.Context, conn net.Conn, _ mux.Handler) error {
		owner, ok := ctx.Value(muxOwnerKey{}).(muxOwner)
		if !ok || owner.parent == nil || owner.relay == nil {
			return errors.New("mux: no parent relay")
		}
		return transport.ServeMuxH2(ctx, conn, owner.parent, func(ctx context.Context, sess *core.Session) error {
			return owner.relay(ctx, muxResponseStream(sess.Conn), sess.Packets, sess.Dest)
		})
	}
	core.SetMuxCoolServer(func(ctx context.Context, parent *core.Session, src netip.Addr, conn net.Conn, relay core.MuxCoolRelay) error {
		return muxcool.Serve(conn, func(_ uint16, dest socks.Addr, stream *muxcool.Stream, packets *muxcool.UDPSession) error {
			var child net.Conn
			if stream != nil {
				child = stream
			}
			var ps core.PacketStream
			if packets != nil {
				ps = packets
			}
			return relay(ctx, child, ps, dest)
		})
	})
	core.SetMuxServer(func(ctx context.Context, parent *core.Session, src netip.Addr, conn net.Conn, relay core.MuxRelay) error {
		ctx = context.WithValue(ctx, muxOwnerKey{}, muxOwner{parent: parent, relay: relay})
		return mux.Serve(ctx, conn, func(ctx context.Context, s *mux.Session) error {
			return relay(ctx, muxResponseStream(s.Conn), packetsOf(s), s.Dest)
		})
	})
}

type muxOwnerKey struct{}
type muxOwner struct {
	parent *core.Session
	relay  core.MuxRelay
}

func muxResponseStream(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	return &singboxStreamShim{Conn: conn}
}

// sing-mux caf09fe32475 serverConn prefixes the first payload with success
// status 0. This is protocol framing, not a discarded application byte.
type singboxStreamShim struct {
	net.Conn
	mu    sync.Mutex
	first bool
}

func (c *singboxStreamShim) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.first {
		return c.Conn.Write(p)
	}
	frame := make([]byte, 1, 1+len(p))
	frame = append(frame, p...)
	n, err := c.Conn.Write(frame)
	c.first = true
	if n < 0 || n > len(frame) {
		_ = c.Conn.Close()
		return 0, io.ErrShortWrite
	}
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = c.Conn.Close()
	}
	if n > 0 {
		n--
	}
	return n, err
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

// Kept as lifecycle compatibility hooks; mux ownership now follows the relay.
func publishMux(*Kernel)   {}
func unpublishMux(*Kernel) {}
