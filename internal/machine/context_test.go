package machine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/txboard"
)

func TestNativeMachineOwnersCancelTheirBlockedRequests(t *testing.T) {
	cases := []struct {
		name string
		call func(context.Context, *Orchestrator) error
	}{
		{"initial_discovery", func(ctx context.Context, o *Orchestrator) error { return o.Run(ctx) }},
		{"rediscovery", func(ctx context.Context, o *Orchestrator) error { o.rediscover(ctx); return nil }},
		{"handshake", func(ctx context.Context, o *Orchestrator) error { o.tryStartWS(ctx); return nil }},
		{"status", func(ctx context.Context, o *Orchestrator) error { o.reportMachineStatusContext(ctx); return nil }},
		{"prefetch", func(ctx context.Context, o *Orchestrator) error {
			_, err := machineConfigContext(ctx, o.client.ForNode(42))
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entered, cancelled, escape := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				select {
				case <-r.Context().Done():
					close(cancelled)
				case <-escape:
				}
			}))
			defer server.Close()
			defer close(escape)
			o := newTestOrchestrator()
			o.cfg.Panel.Provider = "txboard"
			o.client = &txboardMachineControlPlane{client: txboard.NewClient(config.PanelConfig{URL: server.URL, Token: "synthetic-machine-cancellation", MachineID: 16})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- tc.call(ctx, o) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("Machine owner did not reach request blocker")
			}
			cancel()
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Fatal("Machine owner lost cancellation", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Machine owner ignored its request lifetime")
			}
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("Machine request did not cancel at Core")
			}
			o.mu.Lock()
			terminal := o.terminalErr
			o.mu.Unlock()
			if terminal != nil {
				t.Fatal("transport cancellation invented Machine authority denial", terminal)
			}
		})
	}
}
