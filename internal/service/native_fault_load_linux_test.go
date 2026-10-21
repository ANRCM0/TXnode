//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/reporting"
)

// The same Service carries concurrent real SOCKS relay traffic while its signed
// authorization renews, its reporting mutex stalls, and its final lease expires.
// Recovery then replays the original terminal batch before opening admission.
func TestNativeLoadedAuthorizationExpiryDuringBlockedReport(t *testing.T) {
	svc, plane, port := signedAuthorityFixture(t, "txnode", 8)
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
	plane.mu.Lock()
	plane.reportErr = errors.New("load fixture report offline")
	plane.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	authorityWaitListener(t, port)
	var clients []net.Conn
	var wg sync.WaitGroup
	var completed, written, received, firstErrorAt atomic.Int64
	failures := make(chan error, 16)
	stop := make(chan struct{})
	var stopOnce sync.Once
	shutdown := func() {
		stopOnce.Do(func() { close(stop) })
		for _, c := range clients {
			_ = c.Close()
		}
		wg.Wait()
	}
	defer shutdown()
	for worker := 0; worker < 16; worker++ {
		raw, c := liveProtocolDial(t, "socks", fmt.Sprintf("127.0.0.1:%d", port), liveProtocolUUID, origin.Addr())
		clients = append(clients, c)
		defer raw.Close()
		wg.Add(1)
		go func(c net.Conn, worker int) {
			defer wg.Done()
			payload := bytes.Repeat([]byte{byte(worker + 1)}, 1024)
			got := make([]byte, len(payload))
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				n, err := c.Write(payload)
				written.Add(int64(n))
				if err == nil && n != len(payload) {
					err = io.ErrShortWrite
				}
				if err == nil {
					n, err = io.ReadFull(c, got)
					received.Add(int64(n))
					if err == nil && !bytes.Equal(got, payload) {
						err = errors.New("loaded authorization payload mismatch")
					}
				}
				if err != nil {
					select {
					case <-stop:
						return
					default:
					}
					at := time.Now().UnixNano()
					for old := firstErrorAt.Load(); old == 0 || at < old; old = firstErrorAt.Load() {
						if firstErrorAt.CompareAndSwap(old, at) {
							break
						}
					}
					failures <- err
					return
				}
				completed.Add(1)
				select {
				case <-stop:
					return
				case <-time.After(15 * time.Millisecond):
				}
			}
		}(c, worker)
	}
	// Observe real independent renewal while the loaded streams remain alive.
	deadline := time.Now().Add(5 * time.Second)
	for {
		plane.authMu.Lock()
		renewals := plane.refreshes
		plane.authMu.Unlock()
		if renewals >= 2 && completed.Load() >= 64 {
			break
		}
		select {
		case err := <-failures:
			t.Fatalf("traffic failed before report fault: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("signed authorization did not renew under completed load")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Freeze issuance before blocking the event loop. A counted refresh may
	// still be queued, so observe its accepted revision and published deadline.
	plane.authMu.Lock()
	plane.offline = true
	finalRevision := fmt.Sprint(plane.revision)
	plane.authMu.Unlock()
	deadline = time.Now().Add(2 * time.Second)
	for {
		accepted := svc.authorization.Current()
		svc.authorizationAdmissionMu.Lock()
		published := svc.authorizationDeadline
		svc.authorizationAdmissionMu.Unlock()
		if accepted != nil && accepted.Payload.Revision == finalRevision &&
			published.Equal(time.Unix(accepted.Payload.ExpiresAt, 0)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("final signed renewal revision %s was not applied before report fault", finalRevision)
		}
		time.Sleep(10 * time.Millisecond)
	}
	entered, release, prepared := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	go func() {
		prepared <- svc.reporter.PushAsync(func() reporting.Batch { close(entered); <-release; return reporting.Batch{} }, nil, nil)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("report prepare did not hold the real pending mutex")
	}
	svc.authorizationAdmissionMu.Lock()
	expiry := svc.authorizationDeadline
	svc.authorizationAdmissionMu.Unlock()
	if expiry.IsZero() || time.Until(expiry) < time.Second {
		t.Fatal("finite lease exhausted before load fault was armed")
	}
	timer := time.NewTimer(time.Until(expiry) + 300*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if at := firstErrorAt.Load(); at > 0 && time.Unix(0, at).Before(expiry.Add(-100*time.Millisecond)) {
		t.Fatalf("loaded traffic failed before its authorization deadline: %s < %s", time.Unix(0, at), expiry)
	}
	select {
	case err := <-done:
		t.Fatalf("Service checkpoint bypassed blocked reporting: %v", err)
	default:
	}
	if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatalf("expired loaded listener stayed open behind reporting mutex: revision=%s expiry=%s", finalRevision, expiry)
	}
	loadEnded := make(chan struct{})
	go func() { wg.Wait(); close(loadEnded) }()
	select {
	case <-loadEnded:
	case <-time.After(2 * time.Second):
		t.Fatal("loaded streams did not exit after finite authorization expiry")
	}
	for _, c := range clients {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		var one [1]byte
		if n, err := c.Read(one[:]); n != 0 || err == nil {
			t.Fatal("expired loaded stream still carried bytes")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("expired loaded stream was not closed")
		}
	}
	shutdown()
	unblock()
	select {
	case <-prepared:
	case <-time.After(time.Second):
		t.Fatal("report prepare did not release")
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "NODE_AUTHORIZATION") {
			t.Fatal("loaded expiry reason missing", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("loaded expiry checkpoint did not finish")
	}
	raw, err := os.ReadFile(svc.legacyPendingPath + ".terminal.json")
	if err != nil {
		t.Fatal(err)
	}
	var batch reporting.Batch
	if err := json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	traffic := batch.Payload.Traffic[7]
	minimum := completed.Load() * 1024
	if batch.Payload.BatchID == "" || traffic[0] < minimum || traffic[0] > written.Load() || traffic[1] < received.Load() || traffic[1] > written.Load() {
		t.Fatalf("loaded expiry tail outside actual I/O: batch=%v completed=%d written=%d received=%d", batch.Payload, completed.Load(), written.Load(), received.Load())
	}
	fresh := NewWithControlPlane(svc.cfg, plane)
	if err := fresh.initialSetup(context.Background()); err == nil {
		fresh.kernel.Stop()
		fresh.closeAuthorization()
		t.Fatal("offline restart revived the expired load generation")
	}
	fresh.closeAuthorization()
	plane.authMu.Lock()
	plane.offline = false
	plane.lease = 30
	plane.authMu.Unlock()
	plane.mu.Lock()
	plane.reportErr = nil
	plane.mu.Unlock()
	fresh = NewWithControlPlane(svc.cfg, plane)
	defer fresh.closeAuthorization()
	defer fresh.kernel.Stop()
	if err := fresh.initialSetup(context.Background()); err != nil {
		t.Fatal("online restart failed to replay loaded tail", err)
	}
	plane.mu.Lock()
	found := false
	for _, report := range plane.reports {
		if report.BatchID == batch.Payload.BatchID {
			if report.Traffic[7] != traffic {
				plane.mu.Unlock()
				t.Fatal("restart relabelled the original loaded expiry tail")
			}
			found = true
		}
	}
	plane.mu.Unlock()
	if !found {
		t.Fatal("loaded expiry batch was not replayed before fresh admission")
	}
	rawConn, stream := liveProtocolDial(t, "socks", fmt.Sprintf("127.0.0.1:%d", port), liveProtocolUUID, origin.Addr())
	defer rawConn.Close()
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := stream.Write([]byte("renewed")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 7)
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != "renewed" {
		t.Fatal("fresh higher signed revision did not resume real traffic", err)
	}
	t.Logf("loaded renewal/report/expiry/restart completed=%d batch=%s up=%d down=%d", completed.Load(), batch.Payload.BatchID, traffic[0], traffic[1])
}
