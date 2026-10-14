package machine

import (
	"context"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/txboard"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMalformedAuthenticatedNativeMachineListCannotWithdrawCurrentChildren(t *testing.T) {
	for _, body := range []string{`{"data":{"protocol_version":1}}`, `{"data":{"protocol_version":1,"nodes":null}}`, `{"data":{"protocol_version":1,"nodes":[{"id":2},{"id":2}]}}`, `{"data":{"protocol_version":1,"nodes":[{"id":0}]}}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			o := newTestOrchestrator()
			o.cfg.Panel.Provider = "txboard"
			o.client = &txboardMachineControlPlane{client: txboard.NewClient(config.PanelConfig{URL: server.URL, MachineID: 16, Token: "synthetic-membership"})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			one := membershipChild(o, 1, ctx)
			two := membershipChild(o, 2, ctx)
			o.rediscover(ctx)
			for _, done := range []<-chan error{one, two} {
				select {
				case cause := <-done:
					t.Fatal("malformed authenticated list withdrew child", cause)
				default:
				}
			}
			o.mu.Lock()
			active := len(o.nodes)
			o.mu.Unlock()
			if active != 2 {
				t.Fatal("malformed list changed membership")
			}
			o.stopAll()
			for _, done := range []<-chan error{one, two} {
				select {
				case cause := <-done:
					if controlerror.IsAuthoritativeStopCause(cause) {
						t.Fatal("ordinary cleanup became withdrawal")
					}
				case <-time.After(time.Second):
					t.Fatal("cleanup")
				}
			}
		})
	}
}
