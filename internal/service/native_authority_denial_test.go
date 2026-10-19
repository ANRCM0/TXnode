package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeAuthorityDenialAsyncPollStopsRealListenerAndPreservesUnreportedTail(t *testing.T) {
	port := authorityPort(t)
	denial := &controlerror.AuthorityDenial{Scope: controlerror.NodeScope, NodeID: 42, Code: "NODE_NOT_FOUND", HTTPStatus: 404}
	p := &authorityTestPlane{bootstrap: authorityBootstrap(port), pollErr: denial}
	s := authorityService(t, p)
	s.tracker.Process(map[int][2]int64{7: {23, 41}}, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	authorityWaitListener(t, port)
	select {
	case e := <-done:
		if d, ok := controlerror.AsAuthorityDenial(e); !ok || d != denial {
			t.Fatal("typed denial lost", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("poll failed to stop Service")
	}
	if s.kernel.IsRunning() {
		t.Fatal("kernel running after denial")
	}
	if c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 30*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("listener remained open")
	}
	if !s.reporter.HasTerminalTail() {
		t.Fatal("native traffic not checkpointed")
	}
	p.mu.Lock()
	count := len(p.reports)
	p.mu.Unlock()
	if count != 0 {
		t.Fatal("denied identity used for report")
	}
	if _, e := os.Stat(s.legacyPendingPath + ".terminal.json"); e != nil {
		t.Fatal("durable tail absent", e)
	}
}
func TestNativeAuthorityMachineContextCauseStopsWithoutShutdownHTTP(t *testing.T) {
	port := authorityPort(t)
	p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
	s := authorityService(t, p)
	s.tracker.Process(map[int][2]int64{7: {5, 8}}, nil, 0)
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	authorityWaitListener(t, port)
	d := &controlerror.AuthorityDenial{Scope: controlerror.MachineScope, MachineID: 16, Code: "NODE_UNAUTHORIZED", HTTPStatus: 401}
	cancel(d)
	select {
	case err := <-done:
		if got, ok := controlerror.AsAuthorityDenial(err); !ok || got != d {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("context refusal not terminal")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reports) != 0 || !s.reporter.HasTerminalTail() {
		t.Fatal("machine denial sent HTTP or lost tail")
	}
}
func TestNativeAuthorityRecoveryDrainsTailBeforeListenerIncludingEmptyBootstrap(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprint(empty), func(t *testing.T) {
			port := authorityPort(t)
			p := &authorityTestPlane{bootstrap: authorityBootstrap(port), reportErr: errors.New("temporary")}
			s := authorityService(t, p)
			if e := s.reporter.CheckpointTerminal(func() reporting.Batch {
				return reporting.Batch{Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{7: {9, 13}}}}
			}, nil); e != nil {
				t.Fatal(e)
			}
			fresh := NewWithControlPlane(s.cfg, p)
			if empty {
				p.bootstrap.Users = nil
			}
			if e := fresh.initialSetup(context.Background()); e == nil {
				t.Fatal("failed replay allowed admission")
			}
			if fresh.kernel.IsRunning() {
				t.Fatal("listener opened before recovery")
			}
			p.mu.Lock()
			p.reportErr = nil
			p.mu.Unlock()
			recovered := NewWithControlPlane(s.cfg, p)
			defer recovered.kernel.Stop()
			if e := recovered.initialSetup(context.Background()); e != nil {
				t.Fatal(e)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.initialCalls != 2 || len(p.reports) != 2 || p.reports[0].BatchID != p.reports[1].BatchID || p.reports[1].Traffic[7] != [2]int64{9, 13} {
				t.Fatal("tail not immutable/authenticated before replay")
			}
			if recovered.reporter.HasTerminalTail() {
				t.Fatal("tail remained after ack")
			}
			if empty && recovered.kernel.IsRunning() {
				t.Fatal("empty bootstrap started")
			}
			if _, e := os.Stat(filepath.Clean(s.legacyPendingPath) + ".terminal.json"); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("tail was not removed", e)
			}
		})
	}
}

func TestNativeAuthorityDenialClosesEstablishedStreamAndCheckpointsActualMeter(t *testing.T) {
	origin, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer origin.Close()
	originDone := make(chan struct{})
	go func() {
		defer close(originDone)
		conn, err := origin.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	port := authorityPort(t)
	p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
	s := authorityService(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	authorityWaitListener(t, port)
	raw, client := liveProtocolDial(t, "socks", fmt.Sprintf("127.0.0.1:%d", port), liveProtocolUUID, origin.Addr())
	defer raw.Close()
	defer client.Close()
	client.SetDeadline(time.Now().Add(12 * time.Second))
	payload := []byte("native-authority-real-meter")
	if _, e = client.Write(payload); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(client, got); e != nil {
		t.Fatal("real stream response", e)
	}
	d := &controlerror.AuthorityDenial{Scope: controlerror.NodeScope, NodeID: 42, Code: "NODE_NOT_FOUND", HTTPStatus: 404}
	p.mu.Lock()
	p.pollErr = d
	p.mu.Unlock()
	select {
	case err := <-done:
		if _, ok := controlerror.AsAuthorityDenial(err); !ok {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("active stream prevented terminal shutdown")
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if n, e := client.Read(one[:]); n != 0 || e == nil {
		t.Fatal("revoked established stream still readable")
	}
	body, e := os.ReadFile(s.legacyPendingPath + ".terminal.json")
	if e != nil {
		t.Fatal("actual meter not durable", e)
	}
	if len(body) == 0 || !s.reporter.HasTerminalTail() {
		t.Fatal("actual stream tail absent")
	}
	p.mu.Lock()
	p.reportErr = nil
	p.mu.Unlock()
	fresh := NewWithControlPlane(s.cfg, p)
	if e := fresh.reporter.ReplayRecovery(); e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reports) != 1 || p.reports[0].Traffic[7] != [2]int64{int64(len(payload)), int64(len(payload))} {
		t.Fatal("final actual meter not exactly preserved", p.reports)
	}
}
