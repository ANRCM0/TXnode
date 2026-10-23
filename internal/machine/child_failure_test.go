package machine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/txboard"
)

func TestChildFailureRechecksNativeMachineAuthority(t *testing.T) {
	for _, status := range []int{401, 503, 200} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var discoveries, configs, handshakes atomic.Int32
			rechecked := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/machine/nodes") {
					if discoveries.Add(1) == 1 {
						_, _ = w.Write([]byte(`{"data":{"protocol_version":1,"nodes":[],"base_config":{"pull_interval":60,"push_interval":60}}}`))
						return
					}
					defer func() { rechecked <- struct{}{} }()
					if status == 401 {
						w.WriteHeader(401)
						_, _ = w.Write([]byte(`{"request_id":"synthetic-failure-recheck","error":{"code":"NODE_UNAUTHORIZED","message":"unauthorized"}}`))
						return
					}
					if status == 503 {
						w.WriteHeader(503)
						_, _ = w.Write([]byte(`{}`))
						return
					}
					_, _ = w.Write([]byte(`{"data":{"protocol_version":1,"nodes":[{"id":7,"type":"vless"}],"base_config":{}}`))
					return
				}
				if strings.HasSuffix(r.URL.Path, "/handshake") {
					handshakes.Add(1)
				}
				if strings.HasSuffix(r.URL.Path, "/config") {
					configs.Add(1)
				}
				_, _ = w.Write([]byte(`{"data":{"enabled":false}}`))
			}))
			defer server.Close()
			o := newTestOrchestrator()
			o.cfg.Panel.Provider = "txboard"
			o.client = &txboardMachineControlPlane{client: txboard.NewClient(config.PanelConfig{URL: server.URL, Token: "synthetic-child-failure", MachineID: 16})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- o.Run(ctx) }()
			deadline := time.Now().Add(time.Second)
			for discoveries.Load() == 0 {
				if time.Now().After(deadline) {
					t.Fatal("initial discovery missing")
				}
				time.Sleep(time.Millisecond)
			}
			o.recordFailure(7, errors.New("NATIVE_USAGE_FAILED"), time.Now())
			select {
			case <-rechecked:
			case <-time.After(time.Second):
				t.Fatal("child failure did not wake owner discovery")
			}
			if status == 401 {
				select {
				case err := <-done:
					denial, ok := controlerror.AsAuthorityDenial(err)
					if !ok || denial.Scope != controlerror.MachineScope {
						t.Fatal("fresh native denial lost its scope", err)
					}
				case <-time.After(time.Second):
					t.Fatal("fresh native denial did not stop owner")
				}
				return
			}
			deadline = time.Now().Add(time.Second)
			for handshakes.Load() < 2 {
				if time.Now().After(deadline) {
					t.Fatal("owner did not complete failure recheck")
				}
				time.Sleep(time.Millisecond)
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("ordinary discovery failure fabricated denial", err)
				}
			case <-time.After(time.Second):
				t.Fatal("owner failed cancellation")
			}
			if configs.Load() != 0 {
				t.Fatal("failure notification bypassed node backoff")
			}
			o.mu.Lock()
			failure := o.failures[7]
			terminal := o.terminalErr
			o.mu.Unlock()
			if terminal != nil || failure == nil || time.Until(failure.nextRetry) < 10*time.Second {
				t.Fatal("ordinary failure lost original backoff or manufactured terminal")
			}
		})
	}
}

func TestChildFailureNotificationCoalesces(t *testing.T) {
	o := newTestOrchestrator()
	o.childFailure = make(chan struct{}, 1)
	for i := 0; i < 10; i++ {
		o.recordFailure(7, errors.New("local failure"), time.Now())
	}
	if len(o.childFailure) != 1 {
		t.Fatal("failure notifications are not bounded")
	}
}
