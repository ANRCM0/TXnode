package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nodesync"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestMembershipWithdrawalStopsActualProtocolAndDurablyCheckpointsFinalTail(t *testing.T) {
	for _, kind := range []string{"vless", "vmess"} {
		t.Run(kind, func(t *testing.T) {
			origin, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer origin.Close()
			originDone := make(chan struct{})
			go func() {
				defer close(originDone)
				conn, e := origin.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
			port := authorityPort(t)
			p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
			p.bootstrap.Config.Protocol = kind
			s := authorityService(t, p)
			s.cfg.Panel.MachineID = 16
			s.cfg.Kernel.CustomRoute = []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{origin.Addr().(*net.TCPAddr).Port}, "outbound": "direct"}}
			s = NewWithControlPlane(s.cfg, p)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx) }()
			authorityWaitListener(t, port)
			raw, client := liveProtocolDial(t, kind, fmt.Sprintf("127.0.0.1:%d", port), liveProtocolUUID, M.ParseSocksaddr(origin.Addr().String()))
			defer raw.Close()
			defer client.Close()
			client.SetDeadline(time.Now().Add(12 * time.Second))
			payload := []byte("withdrawn-machine-member-tail")
			if _, e := client.Write(payload); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, len(payload))
			if _, e := io.ReadFull(client, got); e != nil {
				t.Fatal("actual protocol echo", e)
			}
			cause := &controlerror.NodeMembershipWithdrawal{NodeID: 42, MachineID: 16}
			cancel(cause)
			select {
			case err := <-done:
				withdrawal, ok := controlerror.AsMembershipWithdrawal(err)
				if !ok || withdrawal != cause {
					t.Fatal("membership type not returned", err)
				}
				if _, ok := controlerror.AsAuthorityDenial(err); ok {
					t.Fatal("list removal forged native HTTP404")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("member Service failed to stop")
			}
			if s.kernel.IsRunning() {
				t.Fatal("withdrawn kernel running")
			}
			if conn, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second); e == nil {
				conn.Close()
				t.Fatal("withdrawn listener open")
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if n, e := client.Read(b[:]); n != 0 || e == nil {
				t.Fatal("withdrawn established stream open")
			}
			tail, e := os.ReadFile(s.legacyPendingPath + ".terminal.json")
			if e != nil {
				t.Fatal("durable terminal tail absent", e)
			}
			var batch reporting.Batch
			if json.Unmarshal(tail, &batch) != nil || batch.Payload.BatchID == "" || batch.Payload.Traffic[7] != [2]int64{int64(len(payload)), int64(len(payload))} {
				t.Fatal("actual final bytes missing", batch.Payload.Traffic)
			}
			p.mu.Lock()
			reported := len(p.reports)
			p.mu.Unlock()
			if reported != 0 {
				t.Fatal("withdrawn identity used for shutdown report")
			}
			fresh := NewWithControlPlane(s.cfg, p)
			if e := fresh.initialSetup(context.Background()); e != nil {
				t.Fatal("current initial snapshot/recovery did not reopen", e)
			}
			defer fresh.kernel.Stop()
			authorityWaitListener(t, port)
			p.mu.Lock()
			if len(p.reports) != 1 || p.reports[0].BatchID != batch.Payload.BatchID || p.reports[0].Traffic[7] != batch.Payload.Traffic[7] {
				p.mu.Unlock()
				t.Fatal("recovered original terminal ID/body changed")
			}
			p.mu.Unlock()
		})
	}
}
func TestOrdinaryContextCancellationKeepsNativeFinalReportPolicy(t *testing.T) {
	port := authorityPort(t)
	p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
	s := authorityService(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	authorityWaitListener(t, port)
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary cancel")
	}
	p.mu.Lock()
	reports := len(p.reports)
	p.mu.Unlock()
	if reports != 1 || s.reporter.HasTerminalTail() {
		t.Fatal("ordinary cancellation became membership checkpoint")
	}
	if _, e := os.Stat(s.legacyPendingPath + ".terminal.json"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("ordinary cancel terminal file", e)
	}
}

func TestMembershipWithdrawalContextWinsQueuedUserAddition(t *testing.T) {
	port := authorityPort(t)
	p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
	p.bootstrap.Users = []model.UserSpec{}
	s := authorityService(t, p)
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := &controlerror.NodeMembershipWithdrawal{NodeID: 42, MachineID: 16}
	// The event was already buffered before Run observes the cancellation.
	s.push.EventSink() <- controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{{ID: 7, UUID: liveProtocolUUID}}}
	cancel(cause)
	err := s.Run(ctx)
	if got, ok := controlerror.AsMembershipWithdrawal(err); !ok || got != cause {
		t.Fatal("withdrawal did not dominate queued startup event", err)
	}
	if s.kernel.IsRunning() {
		t.Fatal("withdrawal opened listener")
	}
	if conn, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond); e == nil {
		conn.Close()
		t.Fatal("withdrawal admission started")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reports) != 0 {
		t.Fatal("withdrawn queued event used shutdown HTTP")
	}
}

func TestMembershipWithdrawalDirectApplicationHelpersCannotBypassStopCause(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(&controlerror.NodeMembershipWithdrawal{NodeID: 42, MachineID: 16})
	k := &fakeKernel{}
	s := snapshotTestService(k)
	old := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig = old
	s.lastConfigHash = computeConfigHash(old)
	s.updateUserState([]model.UserSpec{}, srcBootstrap)
	if !s.authorityTerminal(ctx) {
		t.Fatal("membership context omitted from common terminal helper")
	}
	users := []model.UserSpec{{ID: 7, UUID: liveProtocolUUID}}
	s.applyUserUpdate(ctx, users, computeUserHash(users), srcWSFull)
	s.applyUserDelta(ctx, "add", users)
	s.applySyncResult(ctx, nodesync.Result{Config: &model.NodeSpec{Protocol: "vless", ServerPort: 12346}, Users: users, UserHash: computeUserHash(users)})
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUsers, Users: users})
	s.applyDesiredState(ctx)
	if k.startCalls != 0 || k.addCalls != 0 || k.updateCalls != 0 || s.users.Count() != 0 || s.lastConfig != old {
		t.Fatal("direct helper bypassed membership withdrawal")
	}
	ordinary, cancelOrdinary := context.WithCancel(context.Background())
	cancelOrdinary()
	if s.authorityTerminal(ordinary) {
		t.Fatal("ordinary cancellation inferred authority")
	}
}
