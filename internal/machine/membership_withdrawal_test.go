package machine

import (
	"context"
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"testing"
	"time"
)

type membershipDiscovery struct {
	machineControlPlane
	response *machineDiscovery
	err      error
}

func (p membershipDiscovery) GetMachineNodes() (*machineDiscovery, error) { return p.response, p.err }
func membershipChild(o *Orchestrator, id int, ctx context.Context) <-chan error {
	child, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	cause := make(chan error, 1)
	o.nodes[id] = &nodeHandle{cancelCause: cancel, cancel: func() { cancel(nil) }, done: done, mailbox: controlplane.NewNodeMailbox()}
	o.mailboxes[id] = o.nodes[id].mailbox
	go func() { defer close(done); <-child.Done(); cause <- context.Cause(child) }()
	return cause
}
func TestAcceptedNativeMembershipSnapshotStopsOnlyOmittedChildWithConfiguredIdentity(t *testing.T) {
	o := newTestOrchestrator()
	o.cfg.Panel.Provider = "txboard"
	o.client = membershipDiscovery{response: &machineDiscovery{Nodes: []machineNode{{ID: 2, Type: "vless"}}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := membershipChild(o, 1, ctx)
	second := membershipChild(o, 2, ctx)
	completed := make(chan struct{})
	go func() { o.rediscover(ctx); close(completed) }()
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("discovery withdrawal deadlocked joining child")
	}
	select {
	case cause := <-first:
		got, ok := controlerror.AsMembershipWithdrawal(cause)
		if !ok || got.NodeID != 1 || got.MachineID != 16 {
			t.Fatal("withdrawal not bound to configured Machine identity", cause)
		}
		if _, ok := controlerror.AsAuthorityDenial(cause); ok {
			t.Fatal("list removal forged HTTP denial")
		}
	case <-time.After(time.Second):
		t.Fatal("omitted child not withdrawn")
	}
	select {
	case cause := <-second:
		t.Fatal("authorized sibling cancelled", cause)
	default:
	}
	o.mu.Lock()
	_, one := o.nodes[1]
	_, two := o.nodes[2]
	terminal := o.terminalErr
	o.mu.Unlock()
	if one || !two || terminal != nil {
		t.Fatal("withdrawal wrong scope")
	}
	o.stopAll()
	select {
	case cause := <-second:
		if controlerror.IsAuthoritativeStopCause(cause) {
			t.Fatal("ordinary cleanup inferred withdrawal")
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup")
	}
}
func TestOrdinaryDiscoveryFailureDoesNotWithdrawExistingMembership(t *testing.T) {
	for _, provider := range []string{"txboard", "xboard"} {
		t.Run(provider, func(t *testing.T) {
			o := newTestOrchestrator()
			o.cfg.Panel.Provider = provider
			o.client = membershipDiscovery{err: errors.New("HTTP 503 or transport unavailable")}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			one := membershipChild(o, 1, ctx)
			two := membershipChild(o, 2, ctx)
			o.rediscover(ctx)
			for _, done := range []<-chan error{one, two} {
				select {
				case cause := <-done:
					t.Fatal("failed list treated as empty membership", cause)
				default:
				}
			}
			o.stopAll()
			for _, done := range []<-chan error{one, two} {
				cause := <-done
				if controlerror.IsAuthoritativeStopCause(cause) {
					t.Fatal("ordinary stop inferred authority")
				}
			}
		})
	}
}
func TestLegacyProviderListRemovalKeepsOrdinaryCancellation(t *testing.T) {
	o := newTestOrchestrator()
	o.cfg.Panel.Provider = "xboard"
	o.client = membershipDiscovery{response: &machineDiscovery{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	child := membershipChild(o, 1, ctx)
	o.rediscover(ctx)
	cause := <-child
	if controlerror.IsAuthoritativeStopCause(cause) {
		t.Fatal("Xboard wire policy silently reinterpreted")
	}
}
