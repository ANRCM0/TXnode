// Package mux is kaze's multiplexing layer: the server sniffs the protocol
// from the first bytes and hands each stream to the session relay, and the
// client side keeps a mux pool so several sessions share one connection.
//
// Evidence: REPORT.md §7.6 and notes/rev-transport.md §4.1:
//
//	mux.Serve (0x773b40) reads 2 bytes: b0 = version (only 0/1), b1 = kind;
//	kind 0 -> xtaci/smux.Serve (0x724840), kind 1 -> hashicorp/yamux.Serve
//	(0x71d900), kind 2 -> x/net/http2 (*Server).serveConn (0x74d600),
//	otherwise "mux: unknown protocol"; b0 > 1 -> "mux: unsupported version".
//
// Every stream starts with a SOCKS5 address header (readStreamRequest
// 0x774de0 -> socks.ReadAddr 0x771f80), which is the V2Ray/smux convention.
package mux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/xtaci/smux"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Protocol kinds, as sniffed from the second byte of the connection.
const (
	KindSmux  = 0
	KindYamux = 1
	KindH2    = 2
)

// SmuxConfig is the server/client smux configuration. The sample's six fields
// are smux.DefaultConfig() unchanged (notes/rev-transport.md §4.1 table).
func SmuxConfig() *smux.Config {
	return smux.DefaultConfig()
}

// YamuxConfig is the server/client yamux configuration: the sample tightens
// the stock 75 s / 300 s timeouts to 15 s (immediate 0x37e11d600 at
// 0x773fee) and keeps the other fields at their defaults.
func YamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 256
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.MaxStreamWindowSize = 256 * 1024
	cfg.StreamCloseTimeout = 15 * time.Second
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

// Session is one multiplexed stream together with the destination the peer
// asked for (the SOCKS address header at the head of the stream).
type Session struct {
	Conn    net.Conn
	Dest    socks.Addr
	Packets *Packets // non-nil when the peer set FlagUDP
}

// Handler relays one multiplexed session. The transport layer wires it to
// core.(*Server).ServeSession.
type Handler func(ctx context.Context, s *Session) error

// Sniff reads the protocol prefix and returns the kind. It also consumes the
// optional b0==1 handshake byte pair the sample reads (1 byte that must be 1,
// then 2 big-endian bytes).
func Sniff(c net.Conn) (kind byte, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] > 1 {
		return 0, errors.New("mux: unsupported version")
	}
	if hdr[0] == 1 {
		var x [1]byte
		if _, err := io.ReadFull(c, x[:]); err != nil {
			return 0, err
		}
		if x[0] != 0 {
			return 0, fmt.Errorf("mux: session padding is not supported")
		}
	}
	switch hdr[1] {
	case KindSmux, KindYamux, KindH2:
		return hdr[1], nil
	default:
		return 0, errors.New("mux: unknown protocol")
	}
}

// Serve sniffs the protocol of c and serves its streams with h. kind 2 (h2)
// is left to the transport package, which owns the HTTP/2 stack; Serve reports
// it back through the callback so the caller can hand the composite
// connection over.
func Serve(ctx context.Context, c net.Conn, h Handler) error {
	kind, err := Sniff(c)
	if err != nil {
		return err
	}
	// The rate exchange runs on the parent connection: TCP Brutal is a socket
	// option on the mux transport, not on the individual stream.
	wrapped := Handler(func(ctx context.Context, s *Session) error {
		if s.Dest.Host == BrutalExchangeHost {
			rate, xerr := ServerExchange(s.Conn, 0)
			if xerr == nil {
				_ = SetBrutal(c, rate)
			}
			return xerr
		}
		return h(ctx, s)
	})
	switch kind {
	case KindSmux:
		sess, err := smux.Server(c, SmuxConfig())
		if err != nil {
			return err
		}
		return serveSmux(ctx, sess, wrapped)
	case KindYamux:
		sess, err := yamux.Server(c, YamuxConfig())
		if err != nil {
			return err
		}
		return serveYamux(ctx, sess, wrapped)
	case KindH2:
		if H2Conn != nil {
			return H2Conn(ctx, c, wrapped)
		}
		return ErrH2
	}
	return errors.New("mux: unknown protocol")
}

// ErrH2 is returned by Serve when the peer speaks HTTP/2 and no H2Conn bridge
// is installed.
var ErrH2 = errors.New("mux: the peer speaks HTTP/2")

// H2Conn serves a kind-2 (HTTP/2) connection: the node installs it with
// transport's HTTP/2 stack, so one mux port accepts mux frames and h2/gRPC
// alike (REPORT.md §7.6, the kind 2 branch at 0x774108). Streams are handed
// to h exactly like smux/yamux streams.
var H2Conn func(ctx context.Context, conn net.Conn, h Handler) error

func serveSmux(ctx context.Context, sess *smux.Session, h Handler) error {
	ctx, cancel := context.WithCancel(ctx)
	var children sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer stop()
	defer func() { cancel(); _ = sess.Close(); children.Wait() }()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		children.Add(1)
		go func() { defer children.Done(); handleStream(ctx, stream, h) }()
	}
}

func serveYamux(ctx context.Context, sess *yamux.Session, h Handler) error {
	ctx, cancel := context.WithCancel(ctx)
	var children sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer stop()
	defer func() { cancel(); _ = sess.Close(); children.Wait() }()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		children.Add(1)
		go func() { defer children.Done(); handleStream(ctx, stream, h) }()
	}
}

func handleStream(ctx context.Context, stream net.Conn, h Handler) {
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	flags, addr, err := ReadStreamRequest(stream)
	if err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	if flags&FlagUDP != 0 {
		packets := NewServerPackets(stream, flags, addr)
		if flags&FlagAddr != 0 {
			addr = socks.Addr{}
		}
		_ = h(ctx, &Session{Dest: addr, Packets: packets})
		return
	}
	_ = h(ctx, &Session{Conn: stream, Dest: addr})
}
