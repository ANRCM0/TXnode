//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	M "github.com/sagernet/sing/common/metadata"
)

// A stalled prepare owns the real reporting pendingMu; no fake authority,
// fake kernel or injected watchdog call can substitute for actual lease expiry.
func TestSignedAuthorizationExpiryClosesActualTrafficBeforeBlockedReportPrepareReturns(t *testing.T) {
	for _, kernelName := range []string{"singbox", "xray"} {
		t.Run(kernelName, func(t *testing.T) {
			initial, plane, port := signedAuthorityFixture(t, kernelName, 3)
			origin, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			go func() {
				conn, err := origin.Accept()
				if err == nil {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}
			}()
			initial.cfg.Kernel.CustomRoute = []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{origin.Addr().(*net.TCPAddr).Port}, "outbound": "direct"}}
			if kernelName == "xray" {
				initial.cfg.Kernel.CustomRoute = []map[string]any{{"type": "field", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": strconv.Itoa(origin.Addr().(*net.TCPAddr).Port), "outboundTag": "direct"}}
			}
			svc := NewWithControlPlane(initial.cfg, plane)
			plane.mu.Lock()
			plane.reportErr = errors.New("synthetic offline report")
			plane.mu.Unlock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- svc.Run(ctx) }()
			authorityWaitListener(t, port)
			raw, stream := liveProtocolDial(t, "vless", fmt.Sprintf("127.0.0.1:%d", port), liveProtocolUUID, M.ParseSocksaddr(origin.Addr().String()))
			defer raw.Close()
			defer stream.Close()
			stream.SetDeadline(time.Now().Add(7 * time.Second))
			body := []byte("lease-tail-before-stalled-report-checkpoint")
			if _, err := stream.Write(body); err != nil {
				t.Fatal(err)
			}
			echoed := make([]byte, len(body))
			if _, err := io.ReadFull(stream, echoed); err != nil || string(echoed) != string(body) {
				t.Fatal("actual stream echo failed", err)
			}
			plane.authMu.Lock()
			plane.offline = true
			plane.authMu.Unlock()

			entered, release, prepareDone := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			go func() {
				prepareDone <- svc.reporter.PushAsync(func() reporting.Batch {
					close(entered)
					<-release
					return reporting.Batch{}
				}, nil, nil)
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("report prepare did not acquire real pending mutex")
			}
			svc.authorizationAdmissionMu.Lock()
			expiry := svc.authorizationDeadline
			svc.authorizationAdmissionMu.Unlock()
			if expiry.IsZero() || !time.Now().Before(expiry) {
				t.Fatal("fixture exhausted lease before blocker was installed")
			}
			wait := time.NewTimer(time.Until(expiry) + 300*time.Millisecond)
			defer wait.Stop()
			<-wait.C
			select {
			case err := <-done:
				t.Fatal("Service checkpoint completed while pending mutex still held", err)
			default:
			}
			select {
			case <-prepareDone:
				t.Fatal("blocked prepare unexpectedly returned")
			default:
			}
			if conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond); err == nil {
				conn.Close()
				t.Fatal("expired listener remained open behind reporting mutex")
			}
			stream.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			var probe [1]byte
			if n, err := stream.Read(probe[:]); n != 0 || err == nil {
				t.Fatal("expired established stream remained usable", n, err)
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("expired established stream was idle but not closed")
			}
			unblock()
			select {
			case <-prepareDone:
			case <-time.After(time.Second):
				t.Fatal("report prepare did not release")
			}
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "NODE_AUTHORIZATION") {
					t.Fatal("authority stop reason lost", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("terminal checkpoint did not complete after reporting mutex release")
			}
			bytes, err := os.ReadFile(svc.legacyPendingPath + ".terminal.json")
			if err != nil {
				t.Fatal("original terminal tail missing", err)
			}
			var batch reporting.Batch
			if err := json.Unmarshal(bytes, &batch); err != nil {
				t.Fatal(err)
			}
			if batch.Payload.BatchID == "" || batch.Payload.Traffic[7] != [2]int64{int64(len(body)), int64(len(body))} {
				t.Fatal("blocked checkpoint lost traffic or stable batch identity", batch.Payload)
			}
		})
	}
}

type blockedSignedRefreshPlane struct {
	*signedAuthorityPlane
	entered  chan struct{}
	release  chan struct{}
	pollSeen chan struct{}
	once     sync.Once
}

func (p *blockedSignedRefreshPlane) RefreshAuthorization(ctx context.Context) (controlplane.Snapshot, error) {
	snapshot, err := p.signedAuthorityPlane.RefreshAuthorization(ctx)
	snapshot.Config = nil // Real native renewal only returns users, not config.
	blocked := false
	p.once.Do(func() { close(p.entered); blocked = true })
	if blocked {
		select {
		case <-p.release:
		case <-ctx.Done():
			return controlplane.Snapshot{}, ctx.Err()
		}
	}
	return snapshot, err
}
func (p *blockedSignedRefreshPlane) Poll(ctx context.Context) (controlplane.Snapshot, error) {
	select {
	case p.pollSeen <- struct{}{}:
	default:
	}
	return p.signedAuthorityPlane.Poll(ctx)
}

func TestSignedAuthorizationConfigHintCoalescesDuringBlockedUsersRenewal(t *testing.T) {
	initial, base, port := signedAuthorityFixture(t, "singbox", 30)
	plane := &blockedSignedRefreshPlane{signedAuthorityPlane: base, entered: make(chan struct{}), release: make(chan struct{}), pollSeen: make(chan struct{}, 1)}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(plane.release) }) }
	defer release()
	svc := NewWithControlPlane(initial.cfg, plane)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	authorityWaitListener(t, port)
	select {
	case <-plane.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("independent users refresh did not begin")
	}
	newPort := authorityPort(t)
	base.mu.Lock()
	updated := *base.bootstrap.Config
	updated.ServerPort = newPort
	base.bootstrap.Config = &updated
	base.mu.Unlock()
	// EventSink goes through the real Service main loop while refresh is in flight.
	svc.push.EventSink() <- controlplane.Event{Type: controlplane.EventSyncConfig, Config: &updated}
	deadline := time.Now().Add(time.Second)
	for !svc.authorizationFullPending.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !svc.authorizationFullPending.Load() {
		release()
		t.Fatal("full config request not latched during users renewal")
	}
	release()
	select {
	case <-plane.pollSeen:
	case <-time.After(time.Second):
		t.Fatal("pending full Poll did not run after users renewal")
	}
	authorityWaitListener(t, newPort)
	if conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("old config listener remained open")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Service failed to join after config reconciliation")
	}
}
