//go:build linux

package usagebucket_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/kernel/txnode"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
)

// Drive the real Node's NativeMeter and async persistence worker while fsync is
// held at the same durability hook used by the journal crash regressions.
func TestNativeRelayLoadSlowDiskRetainsExclusiveOwnerAndOriginalEvidence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "events")
	entered, release := make(chan struct{}), make(chan struct{})
	var armed atomic.Bool
	var once, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	coordinator, err := usagebucket.NewNativeLoadFaultCoordinator(dir, func(stage string) error {
		if armed.Load() && stage == "before_file_sync" {
			once.Do(func() { close(entered); <-release })
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		unblock()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = coordinator.Close(ctx)
	}()
	wait := func(reason string, fn func() bool) {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for !fn() {
			if time.Now().After(deadline) {
				t.Fatal(reason)
			}
			time.Sleep(time.Millisecond)
		}
	}
	wait("event store did not open", func() bool { return !coordinator.Status().Opening })
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
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	node := txnode.New(txnode.RuntimeConfig{DrainTimeout: time.Second, HandshakeTimeout: time.Second})
	if !node.SetLocalEventConsumer(coordinator) {
		t.Fatal("real Node event consumer refused")
	}
	if err := node.Start(&model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}, []model.UserSpec{{ID: 7, UUID: "slow-disk-user"}}, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer node.Stop()
	var completed atomic.Int64
	var clients []net.Conn
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopLoad := func() {
		stopOnce.Do(func() { close(stop) })
		for _, c := range clients {
			_ = c.Close()
		}
		wg.Wait()
	}
	defer stopLoad()
	errorsSeen := make(chan error, 4)
	for i := 0; i < 4; i++ {
		c, err := slowDiskSOCKS(port, origin.Addr().(*net.TCPAddr).Port)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := []byte("actual-native-slow-disk-payload")
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.SetDeadline(time.Now().Add(time.Second))
				_, err := c.Write(payload)
				if err == nil {
					got := make([]byte, len(payload))
					_, err = io.ReadFull(c, got)
					if err == nil && string(got) != string(payload) {
						err = fmt.Errorf("slow disk relay payload mismatch")
					}
				}
				if err != nil {
					select {
					case <-stop:
						return
					default:
					}
					errorsSeen <- err
					return
				}
				completed.Add(1)
				select {
				case <-stop:
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
		}()
	}
	wait("real relay load did not complete", func() bool { return completed.Load() >= 16 })
	armed.Store(true)
	select {
	case <-entered:
	case err := <-errorsSeen:
		t.Fatal(err)
	case <-time.After(4 * time.Second):
		t.Fatal("actual NativeMeter never reached durable sync")
	}
	before := completed.Load()
	wait("slow disk blocked real forwarding", func() bool { return completed.Load() >= before+16 })
	queued := usagebucket.NativeLoadFaultQueueSnapshot(coordinator)
	if queued.Meters != 1 || !queued.InFlight || queued.SealedBuckets == 0 || queued.RetainedEvents == 0 || queued.RetainedEvents > queued.EventCapacity || queued.Dropped != 0 {
		t.Fatalf("stalled durable worker lost its bounded original queue: %+v", queued)
	}
	t.Logf("slow disk real persistence queue: %+v", queued)
	if _, err := usagebucket.OpenStore(dir, usagebucket.StoreOptions{}); err == nil {
		t.Fatal("slow worker released exclusive event owner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = coordinator.Close(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || coordinator.Status().Closed {
		t.Fatalf("slow sync falsely completed its durable close: %v", err)
	}
	if _, err := usagebucket.OpenStore(dir, usagebucket.StoreOptions{}); err == nil {
		t.Fatal("timed out close surrendered an unsynced owner")
	}
	stopLoad()
	node.Stop()
	unblock()
	wait("released disk sync did not finish original worker", func() bool { return coordinator.Status().Closed })
	status, ok := coordinator.StoreSnapshot()
	if !ok || status.Buckets == 0 {
		t.Fatal("original durable event bucket disappeared")
	}
	var up, down int64
	var unknown bool
	for sequence := uint64(1); sequence <= status.Sequence; sequence++ {
		record, err := coordinator.ReadRecord(sequence)
		if err != nil {
			t.Fatal(err)
		}
		if record.Bucket != nil {
			up += record.Bucket.PhysicalTotals[0]
			down += record.Bucket.PhysicalTotals[1]
			unknown = unknown || record.TailUnknown
			if record.Authorizes {
				t.Fatal("observational slow-disk journal authorized billing")
			}
		}
	}
	if up == 0 || down == 0 || !unknown {
		t.Fatalf("original relay directions/unknown tail lost: up=%d down=%d unknown=%v", up, down, unknown)
	}
	select {
	case err := <-errorsSeen:
		t.Fatal(err)
	default:
	}
	t.Logf("slow disk completed=%d retained_buckets=%d original_up=%d original_down=%d unknown_tail=%v", completed.Load(), status.Buckets, up, down, unknown)
}

func slowDiskSOCKS(port, target int) (net.Conn, error) {
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err = c.Write([]byte{5, 1, 2}); err != nil {
		return nil, err
	}
	var reply [2]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{5, 2} {
		return nil, fmt.Errorf("slow disk method: %v %v", reply, err)
	}
	password := "slow-disk-user"
	if _, err = c.Write(append([]byte{1, 1, 'u', byte(len(password))}, password...)); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{1, 0} {
		return nil, fmt.Errorf("slow disk auth: %v %v", reply, err)
	}
	if _, err = c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(target >> 8), byte(target)}); err != nil {
		return nil, err
	}
	var connected [10]byte
	if _, err = io.ReadFull(c, connected[:]); err != nil || connected[1] != 0 {
		return nil, fmt.Errorf("slow disk connect: %v %v", connected, err)
	}
	ok = true
	return c, nil
}
