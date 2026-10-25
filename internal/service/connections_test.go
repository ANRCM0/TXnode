package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/pushsync"
)

type connectionTestPush struct {
	results []controlplane.ConnectionResult
}

func (*connectionTestPush) Run(context.Context)               {}
func (*connectionTestPush) IsConnected() bool                 { return true }
func (*connectionTestPush) SendDeviceReport(map[int][]string) {}
func (p *connectionTestPush) SendConnectionResult(r controlplane.ConnectionResult) {
	p.results = append(p.results, r)
}

type connectionTestKernel struct {
	fakeKernel
	closed  []string
	queries int
}

func (k *connectionTestKernel) CloseConnection(_ context.Context, id string) error {
	k.closed = append(k.closed, id)
	if len(k.closed) > 1 {
		return kernel.ErrConnectionNotFound
	}
	return nil
}
func (k *connectionTestKernel) Connections(context.Context, string, int) (kernel.ConnectionPage, error) {
	k.queries++
	return kernel.ConnectionPage{Connections: []kernel.Connection{{ID: strings.Repeat("c", 32) + ":1", UserID: 9, Transport: "tcp"}}, Total: 1}, nil
}

func TestConnectionCommandsUseOriginalOwnerAndReplayOnlyOriginalReceipt(t *testing.T) {
	k := &connectionTestKernel{fakeKernel: fakeKernel{running: true}}
	push := &connectionTestPush{}
	s := &Service{cfg: &config.Config{Panel: config.PanelConfig{NodeID: 7}}, kernel: k, push: pushsync.New(nil)}
	s.push.SetBootstrapClient(push)
	c := controlplane.ConnectionCommand{NodeID: 7, RequestID: "nco_" + strings.Repeat("a", 32), Action: "close", Deadline: time.Now().Unix() + 15, ConnectionID: strings.Repeat("c", 32) + ":1"}
	s.handleWSEvent(t.Context(), controlplane.Event{Type: controlplane.EventConnections, Connections: &c})
	s.handleConnectionCommand(t.Context(), &c)
	if len(k.closed) != 1 || len(push.results) != 2 || push.results[0].Status != "closed" || push.results[1].Status != "closed" {
		t.Fatal("duplicate close re-entered owner or lost the original result")
	}
	c.ConnectionID = strings.Repeat("c", 32) + ":2"
	s.handleConnectionCommand(t.Context(), &c)
	if len(k.closed) != 1 || len(push.results) != 2 {
		t.Fatal("same request ID retargeted a different session")
	}
	c.NodeID, c.RequestID = 8, "nco_"+strings.Repeat("b", 32)
	s.handleConnectionCommand(t.Context(), &c)
	if len(k.closed) != 1 || len(push.results) != 2 {
		t.Fatal("foreign node reached kernel")
	}
	c.NodeID, c.Deadline = 7, time.Now().Unix()-1
	s.handleConnectionCommand(t.Context(), &c)
	if len(k.closed) != 1 || push.results[2].Status != "expired" {
		t.Fatal("expired close reached kernel")
	}
	c.RequestID, c.Deadline, c.Action, c.ConnectionID, c.Limit = "nco_"+strings.Repeat("d", 32), time.Now().Unix()+15, "list", "", 50
	s.handleConnectionCommand(t.Context(), &c)
	if k.queries != 1 || push.results[3].Status != "complete" || push.results[3].Page.Connections[0].UserID != 9 {
		t.Fatal("list did not query existing inspector")
	}
	k.running = false
	c.RequestID = "nco_" + strings.Repeat("e", 32)
	s.handleConnectionCommand(t.Context(), &c)
	if k.queries != 1 || push.results[4].Status != "unavailable" {
		t.Fatal("stopped runtime was inspected")
	}
}
