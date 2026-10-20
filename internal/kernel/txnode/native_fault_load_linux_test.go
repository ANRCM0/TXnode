//go:build linux

package txnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
)

type nativeFaultVLESS struct {
	net.Conn
	first bool
}

func (c *nativeFaultVLESS) Read(p []byte) (int, error) {
	if !c.first {
		c.first = true
		var header [2]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		if header[0] != 0 {
			return 0, fmt.Errorf("invalid VLESS response")
		}
		if _, err := io.CopyN(io.Discard, c.Conn, int64(header[1])); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(p)
}

func nativeFaultVLESSDial(port int, uuid, dest string, config *tls.Config) (net.Conn, error) {
	var c net.Conn
	var err error
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if config != nil {
		c, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, config)
	} else {
		c, err = net.DialTimeout("tcp", address, 3*time.Second)
	}
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	id, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil || len(id) != 16 {
		return nil, fmt.Errorf("invalid test UUID")
	}
	host, p, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	targetPort, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, fmt.Errorf("test target must be IPv4")
	}
	header := append([]byte{0}, id...)
	header = append(header, 0, 1)
	header = binary.BigEndian.AppendUint16(header, uint16(targetPort))
	header = append(header, 1)
	header = append(header, ip...)
	if _, err = c.Write(header); err != nil {
		return nil, err
	}
	ok = true
	return &nativeFaultVLESS{Conn: c}, nil
}

func nativeFaultEcho(c net.Conn, payload []byte) error {
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	n, err := c.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("native fault payload mismatch")
	}
	return nil
}

func nativeFaultDisconnected(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

type nativeFaultLoad struct {
	mu          sync.RWMutex
	generation  atomic.Uint64
	last        []atomic.Uint64
	completed   atomic.Int64
	reloads     atomic.Int64
	failed      chan error
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	connections sync.Map
}

func startNativeFaultLoad(t *testing.T, count int, dial func() (net.Conn, error)) *nativeFaultLoad {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f := &nativeFaultLoad{last: make([]atomic.Uint64, count), failed: make(chan error, count), ctx: ctx, cancel: cancel}
	f.generation.Store(1)
	for i := range count {
		f.wg.Add(1)
		go func(i int) {
			defer f.wg.Done()
			payload := bytes.Repeat([]byte{byte(i + 1)}, 1024)
			var c net.Conn
			var generation uint64
			defer func() {
				if c != nil {
					f.connections.Delete(c)
					_ = c.Close()
				}
			}()
			for ctx.Err() == nil {
				if c == nil {
					f.mu.RLock()
					generation = f.generation.Load()
					var err error
					c, err = dial()
					f.mu.RUnlock()
					if err != nil {
						if ctx.Err() == nil {
							f.failed <- fmt.Errorf("worker %d authentication: %w", i, err)
						}
						return
					}
					f.connections.Store(c, struct{}{})
				}
				err := nativeFaultEcho(c, payload)
				if err != nil {
					f.connections.Delete(c)
					_ = c.Close()
					c = nil
					if ctx.Err() != nil {
						return
					}
					if generation < f.generation.Load() && nativeFaultDisconnected(err) {
						f.reloads.Add(1)
						continue
					}
					f.failed <- fmt.Errorf("worker %d generation %d I/O: %w", i, generation, err)
					return
				}
				f.completed.Add(1)
				f.last[i].Store(generation)
				select {
				case <-ctx.Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		}(i)
	}
	t.Cleanup(f.Stop)
	f.WaitGeneration(t, 1)
	return f
}

func (f *nativeFaultLoad) Stop() {
	f.cancel()
	f.connections.Range(func(key, value any) bool { _ = key.(net.Conn).Close(); return true })
	f.wg.Wait()
}
func (f *nativeFaultLoad) Check(t *testing.T) {
	t.Helper()
	select {
	case err := <-f.failed:
		t.Fatal(err)
	default:
	}
}
func (f *nativeFaultLoad) WaitGeneration(t *testing.T, generation uint64) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for {
		f.Check(t)
		complete := true
		for i := range f.last {
			if f.last[i].Load() < generation {
				complete = false
			}
		}
		if complete {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active load did not reach generation %d: completed=%d", generation, f.completed.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// All mutations below target the same native listener that carries 32 live TLS
// streams. Only a transport close from an explicitly retired generation can be
// classified as injected; fresh-generation failures and timeouts remain fatal.
func TestNativeActiveLoadLifecycleFaults(t *testing.T) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	first, second := selfSignedPEM(t), selfSignedPEM(t)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(first.CertPEM) || !roots.AppendCertsFromPEM(second.CertPEM) {
		t.Fatal("test roots invalid")
	}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	port := freePortTB(t)
	spec := &model.NodeSpec{Protocol: "vless", Transport: "tcp", TLS: 1, ListenIP: "127.0.0.1", ServerPort: port}
	stable := model.UserSpec{ID: 1, UUID: interopUUID}
	k := New(RuntimeConfig{MaxFresh: 128, HandshakeTimeout: 3 * time.Second, DrainTimeout: time.Second})
	if err := k.Start(spec, []model.UserSpec{stable}, first); err != nil {
		t.Fatal(err)
	}
	defer k.Stop()
	load := startNativeFaultLoad(t, 32, func() (net.Conn, error) {
		return nativeFaultVLESSDial(port, stable.UUID, origin.Addr().String(), tlsConfig)
	})
	old := model.UserSpec{ID: 7, UUID: "11223344-5566-7788-9900-aabbccddeeff"}
	fresh := model.UserSpec{ID: 7, UUID: "22334455-6677-8899-aabb-ccddeeff0011"}
	if _, err := k.AddUsers([]model.UserSpec{old}); err != nil {
		t.Fatal(err)
	}
	probe, err := nativeFaultVLESSDial(port, old.UUID, origin.Addr().String(), tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := nativeFaultEcho(probe, []byte("owned-tail")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.UpdateUsers([]model.UserSpec{stable, fresh}); err != nil {
		t.Fatal(err)
	}
	_ = probe.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := probe.Read(one[:]); !nativeFaultDisconnected(err) {
		t.Fatalf("rotation did not close old stream: %v", err)
	}
	rejected := func(uuid string) {
		t.Helper()
		c, err := nativeFaultVLESSDial(port, uuid, origin.Addr().String(), tlsConfig)
		if err == nil {
			defer c.Close()
			err = nativeFaultEcho(c, []byte("forbidden"))
		}
		if err == nil {
			t.Fatal("revoked credential authenticated")
		}
	}
	rejected(old.UUID)
	if _, err := k.RemoveUsers([]model.UserSpec{fresh}); err != nil {
		t.Fatal(err)
	}
	rejected(fresh.UUID)
	if _, err := k.AddUsers([]model.UserSpec{fresh}); err != nil {
		t.Fatal(err)
	}
	rejected(old.UUID)
	load.Check(t)
	// A malformed replacement must leave both the current TLS identity and the
	// generation's active sessions intact.
	if err := k.Reload(spec, []model.UserSpec{stable, fresh}, kernel.TLSCert{CertPEM: []byte("invalid"), KeyPEM: []byte("invalid")}); err == nil {
		t.Fatal("invalid certificate replacement succeeded")
	}
	load.Check(t)
	load.mu.Lock()
	load.generation.Add(1)
	err = k.Reload(spec, []model.UserSpec{stable, fresh}, second)
	load.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	load.WaitGeneration(t, 2)
	identity, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	actual := sha256.Sum256(identity.ConnectionState().PeerCertificates[0].Raw)
	_ = identity.Close()
	certPair, err := tls.X509KeyPair(second.CertPEM, second.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if actual != sha256.Sum256(certPair.Certificate[0]) {
		t.Fatal("same-port reload kept old certificate")
	}
	if load.reloads.Load() != 32 {
		t.Fatalf("expected exactly 32 retired-generation disconnects, got %d", load.reloads.Load())
	}
	load.Stop()
	load.Check(t)
	traffic, _, _, err := k.GetUserTraffic(t.Context())
	if err != nil || traffic[7][0] < 10 || traffic[7][1] < 10 {
		t.Fatalf("rotated credential tail missing: %v %v", traffic, err)
	}
	t.Logf("same-node TLS load completed=%d retired_disconnects=%d traffic=%v", load.completed.Load(), load.reloads.Load(), traffic)
}

// The relay's real core.Limiter.Wait must be cancelled by revocation. The
// one-byte ceiling cannot forward the pending 8 KiB within this test budget.
func TestNativeLoadRateCancellation(t *testing.T) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := origin.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	port := freePortTB(t)
	k := New(RuntimeConfig{DrainTimeout: time.Second, HandshakeTimeout: time.Second})
	defer k.Stop()
	if err := k.Start(&model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}, []model.UserSpec{{ID: 7, UUID: "rate-user"}}, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	k.tracker.SetUserLimit(7, 1, 1, 1)
	c := socksConnectTB(t, port, "rate-user", origin.Addr().String())
	defer c.Close()
	if _, err := c.Write(bytes.Repeat([]byte{1}, 8192)); err != nil {
		t.Fatal(err)
	}
	select {
	case remote := <-accepted:
		defer remote.Close()
		_ = remote.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		var one [1]byte
		if _, err := remote.Read(one[:]); err == nil {
			t.Fatal("exhausted limiter forwarded payload")
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("origin closed before revocation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rate limited session did not reach origin")
	}
	if _, err := k.RemoveUsers([]model.UserSpec{{ID: 7}}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := c.Read(one[:]); !nativeFaultDisconnected(err) {
		t.Fatalf("revocation failed to cancel rate wait: %v", err)
	}
}

func TestNativeUpstreamDisconnectKeepsLoadedPeerFlows(t *testing.T) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	failing, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer failing.Close()
	go func() {
		c, err := failing.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var request [8]byte
		if _, err := io.ReadFull(c, request[:]); err == nil {
			_, _ = c.Write([]byte("end"))
		}
	}()
	port := freePortTB(t)
	k := New(RuntimeConfig{MaxFresh: 128, DrainTimeout: time.Second})
	if err := k.Start(&model.NodeSpec{Protocol: "vless", Transport: "tcp", ListenIP: "127.0.0.1", ServerPort: port}, []model.UserSpec{{ID: 1, UUID: interopUUID}, {ID: 7, UUID: "11223344-5566-7788-9900-aabbccddeeff"}}, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer k.Stop()
	load := startNativeFaultLoad(t, 32, func() (net.Conn, error) { return nativeFaultVLESSDial(port, interopUUID, origin.Addr().String(), nil) })
	before := load.completed.Load()
	c, err := nativeFaultVLESSDial(port, "11223344-5566-7788-9900-aabbccddeeff", failing.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("upstream")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "end" {
		t.Fatalf("upstream partial tail=%q err=%v", got, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for load.completed.Load() < before+32 {
		load.Check(t)
		if time.Now().After(deadline) {
			t.Fatal("upstream disconnect interrupted unrelated live flows")
		}
		time.Sleep(10 * time.Millisecond)
	}
	load.Stop()
	load.Check(t)
	traffic, _, _, err := k.GetUserTraffic(t.Context())
	if err != nil || traffic[7] != [2]int64{8, 3} {
		t.Fatalf("upstream disconnect changed actual byte tail: %v %v", traffic, err)
	}
	t.Logf("upstream disconnect preserved partial tail=%v and peer completed=%d", traffic[7], load.completed.Load())
}

type nativeFaultShortWriter struct {
	net.Conn
	written atomic.Int64
}

func (c *nativeFaultShortWriter) Write(p []byte) (int, error) {
	if len(p) > 7 {
		p = p[:7]
	}
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	if err != nil {
		return n, err
	}
	return n, io.ErrShortWrite
}

func TestNativeAuthenticatedShortWriteKeepsActualTail(t *testing.T) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		c, err := origin.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var trigger [1]byte
		if _, err = io.ReadFull(c, trigger[:]); err == nil {
			_, _ = c.Write(bytes.Repeat([]byte{'r'}, 64))
		}
	}()
	k := New(RuntimeConfig{DrainTimeout: time.Second})
	meter, eventMeter := newTestMeter(t)
	k.meter = meter
	if err := k.Start(&model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePortTB(t)}, []model.UserSpec{{ID: 7, UUID: "short-user"}}, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer k.Stop()
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(4 * time.Second))
	short := &nativeFaultShortWriter{Conn: server}
	done := make(chan error, 1)
	go func() {
		sess, err := k.auth.Handle(context.Background(), server)
		if err != nil {
			done <- err
			return
		}
		sess.Conn = short
		done <- k.srv.ServeSession(context.Background(), sess)
	}()
	if _, err = client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err = io.ReadFull(client, method[:]); err != nil || method != [2]byte{5, 2} {
		t.Fatal("short-write method", err)
	}
	if _, err = client.Write(append([]byte{1, 1, 'u', 10}, "short-user"...)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(client, method[:]); err != nil || method != [2]byte{1, 0} {
		t.Fatal("short-write auth", err)
	}
	addr := origin.Addr().(*net.TCPAddr)
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1}
	request = binary.BigEndian.AppendUint16(request, uint16(addr.Port))
	if _, err = client.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err = io.ReadFull(client, reply[:]); err != nil || reply[1] != 0 {
		t.Fatal("short-write CONNECT", err)
	}
	if _, err = client.Write([]byte{'q'}); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "rrrrrrr" || short.written.Load() != 7 {
		t.Fatalf("short write actual=%q n=%d", got, short.written.Load())
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("short writer did not stop authenticated session")
	}
	snapshot := eventMeter.Snapshot()
	buckets := append(snapshot.Sealed, snapshot.Open)
	var down int64
	for _, bucket := range buckets {
		for _, event := range bucket.Events {
			if event.PhysicalDirection == usagebucket.Download && event.CountKnown {
				down += event.RawCount
			}
		}
	}
	if down != 7 {
		t.Fatalf("short-write meter charged requested bytes instead of actual tail: %d", down)
	}
	traffic, _, _, err := k.GetUserTraffic(t.Context())
	if err != nil || traffic[7][1] != 7 {
		t.Fatalf("short-write legacy tail=%v %v", traffic, err)
	}
}
