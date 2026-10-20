package core

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Relay paths: (*Server).relayTCP @0x7b36a0 and (*Server).relayUDP @0x7b5440
// (notes/rev-core.md §2.2). Both route the destination through
// (*Router).RouteProto, dial either the rule's outbound or the Dialer, and
// account bytes through the Tracker / OnTraffic hook.

// earlyConn is core.earlyConn (type @0xf03080, size 0x48): a connection that is
// allowed to read a first chunk before the destination is known, then replays
// those bytes to the protocol (core.earlyConn.peek @0x7b32a0, Read @0x7b3500).
type earlyConn struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte
	done bool
}

func newEarlyConn(c net.Conn) *earlyConn { return &earlyConn{Conn: c} }

// peek performs the readAhead read (core.readAhead @0x7b3020): one Read bounded
// by the handshake deadline. The bytes stay available through Read.
func (e *earlyConn) peek(timeout time.Duration) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done {
		return e.buf, nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	_ = e.Conn.SetReadDeadline(time.Now().Add(timeout))
	tmp := make([]byte, 8192)
	n, err := e.Conn.Read(tmp)
	_ = e.Conn.SetReadDeadline(time.Time{})
	if n > 0 {
		e.buf = append(e.buf, tmp[:n]...)
		e.done = true
		return e.buf, nil
	}
	if err != nil {
		e.done = true
		return nil, err
	}
	return nil, nil
}

func (e *earlyConn) Read(p []byte) (int, error) {
	e.mu.Lock()
	if len(e.buf) > 0 {
		n := copy(p, e.buf)
		e.buf = e.buf[n:]
		e.mu.Unlock()
		return n, nil
	}
	e.mu.Unlock()
	return e.Conn.Read(p)
}

func (e *earlyConn) CloseWrite() error { return CloseWrite(e.Conn) }

// blockReason renders the log reason for a blocked decision. Built-in reasons
// are verbatim ("bittorrent", "private address"), rule reasons carry the
// observed "rule <name>" prefix (REPORT.md §20.6/§24.3, dyn/ logs).
func blockReason(err error) string {
	var eb *ErrBlocked
	if errors.As(err, &eb) {
		switch eb.Rule {
		case "", "blocked":
			return "blocked"
		case "bittorrent", "private address":
			return eb.Rule
		default:
			return "rule " + eb.Rule
		}
	}
	return "blocked"
}

// relayTCP is the main TCP path. Order (notes/rev-core.md §2.3):
// readAhead -> earlyConn.peek -> SniffTCP -> Router.Route -> DialTCPFrom ->
// track -> pipe/splice.
func (s *Server) relayTCP(ctx context.Context, sess *Session) error {
	o := s.snapshot()
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	user := sess.UserID
	dest := sess.Dest
	from := sessionSourceIP(sess)

	ec := newEarlyConn(sess.Conn)
	meta := Chunk{ConnID: sess.ConnID, UserID: user, Path: "conn"}
	if o.Hooks != nil {
		defer o.Hooks.Close(meta)
	}
	// A protocol that carries an inner SOCKS5 handshake (mieru) must answer the
	// peer before the relay can read application bytes: the peer legitimately
	// sends nothing until it sees the SOCKS5 reply. For those sessions the peek
	// moves after the dial and the reply, and sniffing sees no head bytes.
	reply, _ := sess.Conn.(HandshakeReply)
	var head []byte
	var err error
	if reply == nil {
		var token any
		if o.Hooks != nil {
			c := meta
			c.Dir, c.N = DirUpload, 8192
			token, err = o.Hooks.Begin(c)
			if err != nil {
				return err
			}
		}
		head, err = ec.peek(o.HandshakeTimeout)
		if o.Hooks != nil {
			c := meta
			c.Dir, c.N, c.Err = DirUpload, int64(len(head)), err
			o.Hooks.Complete(c, token)
		}
		if err != nil && len(head) == 0 {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
	proto, sni := SniffTCP(head)
	domain := RequestedName(dest.Host, sni)

	router := s.Router()
	var dec Decision
	if router != nil {
		dec, err = router.RouteProto("tcp", proto, dest, sni)
	} else {
		dec = Decision{Action: ActionDirect}
	}
	if err != nil {
		var eb *ErrBlocked
		if errors.As(err, &eb) {
			log.Info("blocked", "user", user, "from", from.String(),
				"dest", dest.String(), "domain", domain, "reason", blockReason(err))
		}
		if reply != nil {
			_ = reply.HandshakeFailed(err)
		}
		return err
	}

	var remote net.Conn
	if dec.Outbound != nil {
		remote, err = dec.Outbound.DialTCP(ctx, dest)
	} else {
		var res Resolver
		if dec.Action == ActionDNS {
			res = dec.Resolver
		}
		remote, err = s.getDialer(o.HandshakeTimeout).DialTCPFrom(ctx, sess.Local, dest, res, router)
	}
	// Answer the inner SOCKS5 client only after the destination dial resolved,
	// so a failure is visible to the client instead of a silent reset.
	if err != nil {
		log.Debug("dial failed", "dest", dest.String(), "err", err)
		if reply != nil {
			_ = reply.HandshakeFailed(err)
		}
		return err
	}
	if reply != nil {
		if rerr := reply.HandshakeSucceeded(remote.LocalAddr()); rerr != nil {
			log.Debug("handshake reply failed", "dest", dest.String(), "err", rerr)
			_ = remote.Close()
			return rerr
		}
	}
	defer remote.Close()
	defer sess.Conn.Close()

	log.Debug("tcp", "user", user, "from", from.String(), "dest", dest.String(), "proto", proto)

	if o.OnAudit != nil {
		targetIP := ""
		if ip, err := netip.ParseAddr(dest.Host); err == nil {
			targetIP = ip.String()
		}
		fromStr := ""
		if from.IsValid() {
			fromStr = from.String()
		}
		o.OnAudit(user, domain, targetIP, fromStr)
	}

	// Accounting: OnTraffic when the node supplied one, else the Tracker.
	count := func(up bool) func(int64) {
		return func(n int64) {
			if n <= 0 {
				return
			}
			if o.OnTraffic != nil {
				if up {
					o.OnTraffic(user, n, 0)
				} else {
					o.OnTraffic(user, 0, n)
				}
				return
			}
			if o.Tracker != nil {
				if up {
					o.Tracker.Traffic(user, n, 0)
				} else {
					o.Tracker.Traffic(user, 0, n)
				}
			}
		}
	}

	upLims, downLims := s.limiters(o, user)

	// Idle TCP timeout (tcp_timeout, default 5 minutes).
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	// touch records activity for the idle timeout. The timeout is measured in
	// minutes while traffic counters fire per chunk, so the timestamp is only
	// refreshed once a second: a 1 MiB transfer would otherwise call
	// time.Now() twice per chunk (profiling showed 2.4x the sample's
	// clock_gettime calls).
	touch := func() {
		now := time.Now().UnixNano()
		old := last.Load()
		if now-old >= int64(time.Second) {
			last.Store(now)
		}
	}
	stop := make(chan struct{})
	defer close(stop)
	if o.TCPTimeout > 0 {
		go func() {
			tick := o.TCPTimeout / 2
			if tick > 5*time.Second {
				tick = 5 * time.Second
			}
			if tick < 100*time.Millisecond {
				tick = 100 * time.Millisecond
			}
			t := time.NewTicker(tick)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ctx.Done():
					_ = ec.Close()
					_ = remote.Close()
					return
				case <-t.C:
					if time.Since(time.Unix(0, last.Load())) > o.TCPTimeout {
						_ = ec.Close()
						_ = remote.Close()
						return
					}
				}
			}
		}()
	}

	upTraffic, downTraffic := count(true), count(false)
	upCount := func(n int64) { touch(); upTraffic(n) }
	downCount := func(n int64) { touch(); downTraffic(n) }

	// Flush the peeked bytes to the remote, then relay the bare connections so
	// splice(2) stays available on a plain TCP node. Buffered wrappers are
	// rejected by tcpWriter, which keeps TLS/REALITY on the io.Copy path.
	if len(head) > 0 {
		if err := waiterSet(upLims).Wait(ctx, int64(len(head))); err != nil {
			return err
		}
		n, err := remote.Write(head)
		upCount(int64(n))
		if err != nil {
			log.Debug("dial failed", "dest", dest.String(), "err", err)
			return err
		}
		if n != len(head) {
			return io.ErrShortWrite
		}
	}
	return pipeLimited(ctx, sess.Conn, remote, upLims, downLims, upCount, downCount, o.Hooks, meta)
}

// limiters collects the per-user and per-node token buckets for a session. Both
// are applied (the smaller effective rate wins by construction: every bucket
// must admit the bytes).
func (s *Server) limiters(o ServerOptions, user int) (up, down []waiter) {
	if o.Tracker == nil {
		return nil, nil
	}
	var uUp, uDown, nUp, nDown *Limiter
	if user > 0 {
		uUp, uDown = o.Tracker.Limiters(user)
	}
	nUp, nDown = o.Tracker.NodeLimiters()
	return activeLimiters(uUp, nUp), activeLimiters(uDown, nDown)
}

// relayUDP relays a PacketStream session (xudp/UoT/socks5 UDP/hysteria/tuic).
// The resolver bound by an ActionDNS rule is injected into every dial
// (REPORT.md §19.2, notes/rev-round3-route.md §3).
func (s *Server) relayUDP(ctx context.Context, sess *Session) error {
	o := s.snapshot()
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	if sess.Packets == nil {
		return errors.New("udp session without packets")
	}
	user := sess.UserID
	from := sessionSourceIP(sess)
	fromStr := ""
	if from.IsValid() {
		fromStr = from.String()
	}
	log.Debug("udp", "user", user, "from", fromStr)

	upLims, downLims := s.limiters(o, user)
	u := &udpRelay{
		srv:      s,
		ctx:      ctx,
		sess:     sess,
		log:      log,
		user:     user,
		from:     fromStr,
		router:   s.Router(),
		opts:     o,
		upLims:   upLims,
		downLims: downLims,
		assocs:   make(map[socks.Addr]*udpAssoc),
	}
	defer func() {
		u.close()
		if o.Hooks != nil {
			o.Hooks.Close(Chunk{ConnID: sess.ConnID, UserID: user, Path: "udp"})
		}
	}()
	u.StartWatchdog()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		meta := Chunk{ConnID: sess.ConnID, UserID: user, Dir: DirUpload, Path: "udp", N: int64(len(buf))}
		var token any
		if o.Hooks != nil {
			var err error
			token, err = o.Hooks.Begin(meta)
			if err != nil {
				return err
			}
		}
		n, dest, err := sess.Packets.ReadPacket(buf)
		if o.Hooks != nil {
			meta.N, meta.Err = int64(n), err
			o.Hooks.Complete(meta, token)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if dest.IsZero() {
			// A packet stream without a per-packet destination rides on the
			// session target.
			dest = sess.Dest
		}
		if n == 0 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		u.forward(pkt, dest)
	}
}

// udpAssoc is one destination association (a connected UDP socket or an
// outbound PacketStream).
type udpAssoc struct {
	dest      socks.Addr
	conn      net.Conn
	stream    PacketStream
	last      atomic.Int64
	closeOnce sync.Once
	closeErr  error
}

func (u *udpRelay) forward(payload []byte, dest socks.Addr) {
	proto := SniffUDP(payload)
	var dec Decision
	var err error
	if u.router != nil {
		dec, err = u.router.RouteProto("udp", proto, dest, "")
	} else {
		dec = Decision{Action: ActionDirect}
	}
	if err != nil {
		var eb *ErrBlocked
		if errors.As(err, &eb) {
			u.log.Info("blocked", "user", u.user, "from", u.from,
				"dest", dest.String(), "domain", dest.Host, "reason", blockReason(err))
			return
		}
		u.log.Debug("udp route failed", "dest", dest.String(), "err", err)
		return
	}

	a := u.assoc(dest)
	if a == nil {
		// Build the association.
		if dec.Outbound != nil {
			uo, ok := dec.Outbound.(UDPOutbound)
			if !ok {
				// Observed string: "udp dropped: the outbound has no UDP channel".
				u.log.Debug("udp dropped: the outbound has no UDP channel", "dest", dest.String())
				return
			}
			st, err := uo.DialPacket(u.ctx, dest)
			if err != nil {
				u.log.Debug("udp through outbound failed; dropping until it can be retried",
					"dest", dest.String(), "err", err)
				return
			}
			a = &udpAssoc{dest: dest, stream: st}
		} else {
			var res Resolver
			if dec.Action == ActionDNS {
				res = dec.Resolver
			}
			d := u.srv.getDialer(u.opts.HandshakeTimeout)
			conn, err := d.DialUDPFrom(u.ctx, u.sess.Local, dest, res, u.router)
			if err != nil {
				u.log.Debug("dial failed", "dest", dest.String(), "err", err)
				return
			}
			a = &udpAssoc{dest: dest, conn: conn}
		}
		a.last.Store(time.Now().UnixNano())
		if u.opts.OnAudit != nil {
			targetIP := ""
			if ip, err := netip.ParseAddr(dest.Host); err == nil {
				targetIP = ip.String()
			}
			u.opts.OnAudit(u.user, dest.Host, targetIP, u.from)
		}
		u.mu.Lock()
		if u.closed {
			u.mu.Unlock()
			_ = a.Close()
			return
		}
		u.assocs[dest] = a
		u.readers.Add(1)
		u.mu.Unlock()
		go func() {
			defer u.readers.Done()
			u.readBack(a)
		}()
	}

	a.last.Store(time.Now().UnixNano())
	if len(u.upLims) > 0 {
		if err := waiterSet(u.upLims).Wait(u.ctx, int64(len(payload))); err != nil {
			return
		}
	}
	n, err := a.Write(payload)
	u.count(true, int64(n))
	if err != nil {
		u.log.Debug("udp through outbound failed; dropping until it can be retried",
			"dest", dest.String(), "err", err)
		u.remove(dest, a)
		return
	}
}

func (a *udpAssoc) Write(payload []byte) (int, error) {
	if a.stream != nil {
		if err := a.stream.WritePacket(payload, a.dest); err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	n, err := a.conn.Write(payload)
	if err == nil && n != len(payload) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Close releases both association shapes exactly once.
func (a *udpAssoc) Close() error {
	a.closeOnce.Do(func() {
		if a.stream != nil {
			a.closeErr = a.stream.Close()
		} else if a.conn != nil {
			a.closeErr = a.conn.Close()
		}
	})
	return a.closeErr
}

type udpRelay struct {
	srv      *Server
	ctx      context.Context
	sess     *Session
	log      *slog.Logger
	user     int
	from     string
	router   *Router
	opts     ServerOptions
	upLims   []waiter
	downLims []waiter
	writeMu  sync.Mutex
	readers  sync.WaitGroup

	mu     sync.Mutex
	assocs map[socks.Addr]*udpAssoc
	closed bool
}

func (u *udpRelay) count(upload bool, n int64) {
	if n <= 0 {
		return
	}
	var up, down int64
	if upload {
		up = n
	} else {
		down = n
	}
	if u.opts.OnTraffic != nil {
		u.opts.OnTraffic(u.user, up, down)
	} else if u.opts.Tracker != nil {
		u.opts.Tracker.Traffic(u.user, up, down)
	}
}

func (u *udpRelay) assoc(dest socks.Addr) *udpAssoc {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.assocs[dest]
}

func (u *udpRelay) remove(dest socks.Addr, a *udpAssoc) {
	u.mu.Lock()
	if cur, ok := u.assocs[dest]; ok && cur == a {
		delete(u.assocs, dest)
	}
	u.mu.Unlock()
	_ = a.Close()
}

// readBack pumps datagrams from the association back into the client stream.
func (u *udpRelay) readBack(a *udpAssoc) {
	buf := make([]byte, 65535)
	for {
		var n int
		var err error
		addr := a.dest
		if a.stream != nil {
			n, addr, err = a.stream.ReadPacket(buf)
		} else {
			n, err = a.conn.Read(buf)
		}
		if err != nil {
			u.remove(a.dest, a)
			return
		}
		if n == 0 {
			continue
		}
		a.last.Store(time.Now().UnixNano())
		if len(u.downLims) > 0 {
			if err := waiterSet(u.downLims).Wait(u.ctx, int64(n)); err != nil {
				u.remove(a.dest, a)
				return
			}
		}
		u.writeMu.Lock()
		if u.isClosed() {
			u.writeMu.Unlock()
			return
		}
		meta := Chunk{ConnID: u.sess.ConnID, UserID: u.user, Dir: DirDownload, Path: "udp", N: int64(n)}
		var token any
		if u.opts.Hooks != nil {
			token, err = u.opts.Hooks.Begin(meta)
			if err != nil {
				u.writeMu.Unlock()
				u.remove(a.dest, a)
				return
			}
		}
		written := n
		if counted, ok := u.sess.Packets.(PacketWriteCounter); ok {
			written, err = counted.WritePacketCount(buf[:n], addr)
			if written < 0 || written > n {
				written, err = 0, errors.Join(err, io.ErrShortWrite)
			} else if written != n && err == nil {
				err = io.ErrShortWrite
			}
		} else {
			err = u.sess.Packets.WritePacket(buf[:n], addr)
			if err != nil {
				written = 0
			}
		}
		if u.opts.Hooks != nil {
			meta.N, meta.Err = int64(written), err
			u.opts.Hooks.Complete(meta, token)
		}
		u.writeMu.Unlock()
		if written > 0 {
			u.count(false, int64(written))
		}
		if err != nil {
			u.remove(a.dest, a)
			return
		}
	}
}

func (u *udpRelay) isClosed() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.closed
}

// close tears down every association and enforces udp_timeout on idle sessions.
func (u *udpRelay) close() {
	u.mu.Lock()
	u.closed = true
	list := make([]*udpAssoc, 0, len(u.assocs))
	for _, a := range u.assocs {
		list = append(list, a)
	}
	u.assocs = make(map[socks.Addr]*udpAssoc)
	u.mu.Unlock()
	// Interrupt client writes before waiting for the readers that issue them.
	_ = u.sess.Close()
	for _, a := range list {
		_ = a.Close()
	}
	u.readers.Wait()
}

// watchdog closes associations idle for longer than udp_timeout.
func (u *udpRelay) watchdog() {
	timeout := u.opts.UDPTimeout
	if timeout <= 0 {
		return
	}
	tick := timeout / 4
	if tick > 15*time.Second {
		tick = 15 * time.Second
	}
	if tick < 100*time.Millisecond {
		tick = 100 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for range t.C {
		if u.isClosed() {
			return
		}
		now := time.Now()
		u.mu.Lock()
		type victim struct {
			dest socks.Addr
			a    *udpAssoc
		}
		var dead []victim
		for d, a := range u.assocs {
			if now.Sub(time.Unix(0, a.last.Load())) > timeout {
				dead = append(dead, victim{d, a})
			}
		}
		u.mu.Unlock()
		for _, v := range dead {
			u.remove(v.dest, v.a)
		}
	}
}

// servePackets is (*Server).servePackets @0x7b2cc0: a UDP session whose client
// side is a PacketStream is relayed through relayUDP.
func (s *Server) servePackets(ctx context.Context, sess *Session) error {
	if sess.Packets == nil {
		return errors.New("session refused: no packet stream")
	}
	return s.relayUDP(ctx, sess)
}

// startUDPWatchdog is called from relayUDP through a tiny helper so tests can
// exercise idle teardown without relying on timing.
func (u *udpRelay) StartWatchdog() { go u.watchdog() }
