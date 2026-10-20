//go:build linux

package txnode

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
)

type mieruFaultCounts struct{ dropped, reordered, duplicated atomic.Int64 }

// Each direction owns at most one held packet. A read deadline flushes it even
// when the peer goes idle, so reordering cannot silently become packet loss.
type mieruFaultDirection struct {
	n       int
	held    []byte
	counts  *mieruFaultCounts
	forward func([]byte) error
}

func (d *mieruFaultDirection) flush() error {
	if d.held == nil {
		return nil
	}
	b := d.held
	d.held = nil
	return d.forward(b)
}

func (d *mieruFaultDirection) send(b []byte) error {
	d.n++
	if d.n%31 == 0 {
		d.counts.dropped.Add(1)
		return nil
	}
	if d.held != nil {
		if err := d.forward(b); err != nil {
			return err
		}
		d.counts.reordered.Add(1)
		return d.flush()
	}
	if d.n%11 == 0 {
		d.held = append([]byte(nil), b...)
		return nil
	}
	if err := d.forward(b); err != nil {
		return err
	}
	if d.n%17 == 0 {
		if err := d.forward(b); err != nil {
			return err
		}
		d.counts.duplicated.Add(1)
	}
	return nil
}

type mieruFaultPeer struct {
	conn   *net.UDPConn
	uplink mieruFaultDirection
	frames [][]byte
}

type mieruFaultRelay struct {
	front  *net.UDPConn
	target *net.UDPAddr
	mu     sync.Mutex
	peers  map[string]*mieruFaultPeer
	counts [2]mieruFaultCounts
	errors chan error
	done   chan struct{}
	wg     sync.WaitGroup
}

func newMieruFaultRelay(t *testing.T, port int) *mieruFaultRelay {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &mieruFaultRelay{front: front, target: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, peers: make(map[string]*mieruFaultPeer), errors: make(chan error, 1), done: make(chan struct{})}
	r.wg.Add(1)
	go r.run()
	t.Cleanup(func() {
		close(r.done)
		_ = r.front.Close()
		r.mu.Lock()
		for _, p := range r.peers {
			_ = p.conn.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
		select {
		case err := <-r.errors:
			t.Errorf("UDP fault relay: %v", err)
		default:
		}
	})
	return r
}

func (r *mieruFaultRelay) fail(err error) {
	select {
	case <-r.done:
		return
	default:
	}
	select {
	case r.errors <- err:
	default:
	}
}

func (r *mieruFaultRelay) run() {
	defer r.wg.Done()
	b := make([]byte, 65536)
	for {
		_ = r.front.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
		n, addr, err := r.front.ReadFromUDP(b)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				r.mu.Lock()
				for _, p := range r.peers {
					if err := p.uplink.flush(); err != nil {
						r.fail(err)
					}
				}
				r.mu.Unlock()
				continue
			}
			r.fail(err)
			return
		}
		r.mu.Lock()
		select {
		case <-r.done:
			r.mu.Unlock()
			return
		default:
		}
		p := r.peers[addr.String()]
		if p == nil {
			if len(r.peers) == 16 {
				r.mu.Unlock()
				r.fail(fmt.Errorf("more than 16 official-client UDP peers"))
				return
			}
			conn, err := net.DialUDP("udp4", nil, r.target)
			if err != nil {
				r.mu.Unlock()
				r.fail(err)
				return
			}
			p = &mieruFaultPeer{conn: conn}
			p.uplink = mieruFaultDirection{counts: &r.counts[0], forward: func(b []byte) error { _, err := conn.Write(b); return err }}
			r.peers[addr.String()] = p
			r.wg.Add(1)
			go r.downlink(conn, addr)
		}
		// Capture the first flight plus initial data, bounded to 256 datagrams
		// per peer. Replays use the original source socket and original nonce.
		if len(p.frames) < 256 {
			p.frames = append(p.frames, append([]byte(nil), b[:n]...))
		}
		err = p.uplink.send(b[:n])
		r.mu.Unlock()
		if err != nil {
			r.fail(err)
			return
		}
	}
}

func (r *mieruFaultRelay) downlink(conn *net.UDPConn, client *net.UDPAddr) {
	defer r.wg.Done()
	d := mieruFaultDirection{counts: &r.counts[1], forward: func(b []byte) error { _, err := r.front.WriteToUDP(b, client); return err }}
	b := make([]byte, 65536)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
		n, err := conn.Read(b)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				if err := d.flush(); err != nil {
					r.fail(err)
					return
				}
				continue
			}
			r.fail(err)
			return
		}
		if err := d.send(b[:n]); err != nil {
			r.fail(err)
			return
		}
	}
}

func (r *mieruFaultRelay) replay(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, p := range r.peers {
		for _, frame := range p.frames {
			if _, err := p.conn.Write(frame); err != nil {
				t.Fatal(err)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("no captured official-client ciphertext to replay")
	}
}

func mieruFaultRoundTrip(t *testing.T, addr, origin string, payload []byte) net.Conn {
	t.Helper()
	conn, err := socksNoAuthConnectE(addr, origin)
	if err != nil {
		t.Fatalf("official UDP CONNECT: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	written := make(chan error, 1)
	go func() { _, err := io.Copy(conn, bytes.NewReader(payload)); written <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("faulted bulk response bytes=%d err=%v equal=%v", len(got), err, bytes.Equal(got, payload))
	}
	if err := <-written; err != nil {
		t.Fatalf("faulted bulk upload: %v", err)
	}
	return conn
}

func mieruFaultTotals(t *testing.T, k *Kernel, meter *usagebucket.Meter, want [2]int64, stable time.Duration) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	matched := time.Time{}
	for {
		snap := meter.Snapshot()
		if snap.Status.Degraded || snap.Status.DroppedEvents != 0 {
			t.Fatalf("NativeMeter observation incomplete: %+v", snap.Status)
		}
		var got [2]int64
		for _, bucket := range append(snap.Sealed, snap.Open) {
			for _, event := range bucket.Events {
				if event.UserID != 7 || !event.CountKnown || event.RawCount < 0 || event.StartedAfterClose {
					t.Fatalf("invalid NativeMeter event: %+v", event)
				}
				dir := 0
				if event.PhysicalDirection == usagebucket.Download {
					dir = 1
				}
				got[dir] += event.RawCount
			}
		}
		up, down := k.tracker.TrafficOf(7)
		coreTotals := [2]int64{up, down}
		if got[0] > want[0] || got[1] > want[1] || up > want[0] || down > want[1] {
			t.Fatalf("duplicate business charge: core=%v NativeMeter=%v want=%v", coreTotals, got, want)
		}
		if got == want && coreTotals == want {
			if matched.IsZero() {
				matched = time.Now()
			}
			if time.Since(matched) >= stable {
				return
			}
		} else {
			matched = time.Time{}
		}
		if time.Now().After(deadline) {
			t.Fatalf("business accounting: core=%v NativeMeter=%v want=%v", coreTotals, got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type mieruFaultOrigin struct {
	listener net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closed   bool
	wg       sync.WaitGroup
}

func newMieruFaultOrigin(t *testing.T) *mieruFaultOrigin {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &mieruFaultOrigin{listener: ln, conns: make(map[net.Conn]struct{})}
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			o.mu.Lock()
			if o.closed {
				o.mu.Unlock()
				_ = conn.Close()
				return
			}
			o.conns[conn] = struct{}{}
			o.mu.Unlock()
			o.wg.Add(1)
			go func() {
				defer o.wg.Done()
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
				o.mu.Lock()
				delete(o.conns, conn)
				o.mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		o.mu.Lock()
		o.closed = true
		for conn := range o.conns {
			_ = conn.Close()
		}
		o.mu.Unlock()
		o.wg.Wait()
	})
	return o
}

func mieruFaultNoSessions(t *testing.T, k *Kernel, origin *mieruFaultOrigin) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		origin.mu.Lock()
		active := len(origin.conns)
		origin.mu.Unlock()
		page := k.srv.ConnectionPage(0, 10)
		if active == 0 && page.Total == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("old service stream not closed: origin=%d core=%d", active, page.Total)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func mieruFaultOldStreamClosed(t *testing.T, k *Kernel, origin *mieruFaultOrigin, conn net.Conn) {
	t.Helper()
	mieruFaultNoSessions(t, k, origin)
	// A UDP peer need not receive a close notification after authorization is
	// gone. Its local SOCKS socket may time out, but cannot deliver more data.
	_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
	_, _ = conn.Write([]byte("must-not-reach-retired-origin"))
	var b [1]byte
	n, err := conn.Read(b[:])
	if n != 0 || err == nil {
		t.Fatalf("old official stream delivered data after retirement: n=%d err=%v", n, err)
	}
	_ = conn.Close()
}

// This is a real Kernel / official Mieru / core relay / NativeMeter joint test.
// NativeMeter's local physical observations are checked here; authorization
// windows and durable usage_v2 settlement have separate collector fault tests.
func TestInteropMieruOfficialPacketFaults(t *testing.T) {
	mieruBinary(t)
	k := New(RuntimeConfig{TrustedProxies: "private", MaxFresh: 64, HandshakeTimeout: 5 * time.Second, DrainTimeout: time.Second})
	meter, err := usagebucket.New(usagebucket.Options{Enabled: true, Window: time.Minute, MaxEvents: 4096, MaxSealed: 15})
	if err != nil {
		t.Fatal(err)
	}
	k.meter = &nativeMeter{events: meter}
	port := freePortTB(t)
	node := &model.NodeSpec{Protocol: "mieru", Transport: "udp", ListenIP: "127.0.0.1", ServerPort: port}
	users := []model.UserSpec{{ID: 7, UUID: "interop:secret"}}
	if err := k.Start(node, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Stop)
	relay := newMieruFaultRelay(t, port)
	client := startMieruOfficial(t, relay.front.LocalAddr().(*net.UDPAddr).Port, "UDP")
	origin := newMieruFaultOrigin(t)
	originAddr := origin.listener.Addr().String()
	payload := bytes.Repeat([]byte("faulted-official-mieru-bulk/"), 45000)
	old := mieruFaultRoundTrip(t, client, originAddr, payload)
	want := [2]int64{int64(len(payload)), int64(len(payload))}
	udpPayload := bytes.Repeat([]byte("fragmented-application-udp/"), 100)
	got, err := udpThroughSocksE(t, client, udpEcho(t), udpPayload)
	if err != nil || !bytes.Equal(got, udpPayload) {
		t.Fatalf("faulted application UDP: bytes=%d err=%v", len(got), err)
	}
	want[0] += int64(len(udpPayload))
	want[1] += int64(len(udpPayload))
	mieruFaultTotals(t, k, meter, want, 150*time.Millisecond)
	for dir := range relay.counts {
		c := &relay.counts[dir]
		if c.dropped.Load() == 0 || c.reordered.Load() == 0 || c.duplicated.Load() == 0 {
			t.Fatalf("fault direction %d not exercised: drop=%d reorder=%d duplicate=%d", dir, c.dropped.Load(), c.reordered.Load(), c.duplicated.Load())
		}
		t.Logf("fault direction %d: drop=%d reorder=%d duplicate=%d", dir, c.dropped.Load(), c.reordered.Load(), c.duplicated.Load())
	}

	if _, _, err := k.UpdateUsers(nil); err != nil {
		t.Fatal(err)
	}
	mieruFaultOldStreamClosed(t, k, origin, old)
	relay.replay(t)
	mieruFaultTotals(t, k, meter, want, 300*time.Millisecond)
	mieruFaultNoSessions(t, k, origin)
	if _, _, err := k.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	// Restoring identical credentials must not restore an old underlay or nonce.
	relay.replay(t)
	mieruFaultTotals(t, k, meter, want, 300*time.Millisecond)
	mieruFaultNoSessions(t, k, origin)
	fresh := startMieruOfficial(t, relay.front.LocalAddr().(*net.UDPAddr).Port, "UDP")
	probe := []byte("fresh-after-revocation")
	rotated := mieruFaultRoundTrip(t, fresh, originAddr, probe)
	want[0] += int64(len(probe))
	want[1] += int64(len(probe))
	mieruFaultTotals(t, k, meter, want, 100*time.Millisecond)
	if _, _, err := k.UpdateUsers([]model.UserSpec{{ID: 7, UUID: "interop:rotated-secret"}}); err != nil {
		t.Fatal(err)
	}
	mieruFaultOldStreamClosed(t, k, origin, rotated)
	relay.replay(t)
	mieruFaultTotals(t, k, meter, want, 300*time.Millisecond)
	mieruFaultNoSessions(t, k, origin)

	previous := k.bind
	if err := k.Reload(node, users, kernel.TLSCert{}); err != nil {
		t.Fatalf("same UDP port Reload: %v", err)
	}
	if k.bind == previous || k.bind.pc == nil || previous.pc != nil || k.bind.pc.LocalAddr().(*net.UDPAddr).Port != port {
		t.Fatal("same-port Reload did not transfer UDP ownership")
	}
	relay.replay(t)
	mieruFaultTotals(t, k, meter, want, 300*time.Millisecond)
	mieruFaultNoSessions(t, k, origin)
	afterReload := startMieruOfficial(t, relay.front.LocalAddr().(*net.UDPAddr).Port, "UDP")
	current := mieruFaultRoundTrip(t, afterReload, originAddr, probe)
	want[0] += int64(len(probe))
	want[1] += int64(len(probe))
	mieruFaultTotals(t, k, meter, want, 100*time.Millisecond)

	previous = k.bind
	bad := *node
	bad.TrafficPattern = "{invalid"
	if err := k.Reload(&bad, users, kernel.TLSCert{}); err == nil {
		t.Fatal("invalid replacement Reload succeeded")
	}
	if k.bind != previous || k.bind.pc == nil || !k.IsRunning() {
		t.Fatal("failed Reload replaced the live UDP binding")
	}
	_ = current.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := current.Write(probe); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(probe))
	if _, err := io.ReadFull(current, response); err != nil || !bytes.Equal(response, probe) {
		t.Fatalf("live stream lost after failed Reload: %q %v", response, err)
	}
	want[0] += int64(len(probe))
	want[1] += int64(len(probe))
	_ = current.Close()
	mieruFaultTotals(t, k, meter, want, 300*time.Millisecond)

	// A real replacement bind failure takes the socket rollback path, rather
	// than stopping at configuration validation. The old owner must regain its
	// original address; a fresh official client then proves service recovery.
	blocker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	bad = *node
	bad.ServerPort = blocker.LocalAddr().(*net.UDPAddr).Port
	previous = k.bind
	oldSocket := previous.pc
	if err := k.Reload(&bad, users, kernel.TLSCert{}); err == nil {
		t.Fatal("Reload bound a UDP port held by another process")
	}
	if k.bind != previous || k.bind.pc == nil || k.bind.pc == oldSocket || k.bind.pc.LocalAddr().(*net.UDPAddr).Port != port || !k.IsRunning() {
		t.Fatal("failed UDP replacement did not restore original listener ownership")
	}
	relay.replay(t)
	mieruFaultTotals(t, k, meter, want, 300*time.Millisecond)
	mieruFaultNoSessions(t, k, origin)
	afterRollback := startMieruOfficial(t, relay.front.LocalAddr().(*net.UDPAddr).Port, "UDP")
	recovered := mieruFaultRoundTrip(t, afterRollback, originAddr, probe)
	want[0] += int64(len(probe))
	want[1] += int64(len(probe))
	_ = recovered.Close()
	mieruFaultTotals(t, k, meter, want, 300*time.Millisecond)
}
