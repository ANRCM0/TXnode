package txboard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
)

func TestNativeContextRequestsReleaseBlockedHTTP(t *testing.T) {
	cases := []struct {
		name string
		call func(context.Context, *Client) error
	}{
		{"handshake", func(ctx context.Context, c *Client) error { _, err := c.HandshakeContext(ctx); return err }},
		{"config", func(ctx context.Context, c *Client) error { _, err := c.GetConfigContext(ctx); return err }},
		{"complete_config", func(ctx context.Context, c *Client) error { _, err := c.ConfigSnapshotContext(ctx); return err }},
		{"discovery", func(ctx context.Context, c *Client) error { _, err := c.GetMachineNodesContext(ctx); return err }},
		{"status", func(ctx context.Context, c *Client) error { return c.ReportMachineStatusContext(ctx, map[string]any{}) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entered, released, escape := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				select {
				case <-r.Context().Done():
					close(released)
				case <-escape:
				}
			}))
			defer server.Close()
			defer close(escape)
			client := NewClient(config.PanelConfig{URL: server.URL, Token: "synthetic-cancellation", MachineID: 9, NodeID: 42})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- tc.call(ctx, client) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("native request did not reach blocker")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("request cancellation was lost", err)
				}
				if _, authority := controlerror.AsAuthorityDenial(err); authority {
					t.Fatal("cancellation forged authority denial")
				}
			case <-time.After(time.Second):
				t.Fatal("native request outlived its parent")
			}
			select {
			case <-released:
			case <-time.After(time.Second):
				t.Fatal("Core request context was not cancelled")
			}
		})
	}
}

func TestNativeContextKeepsCompletedAuthorityDenial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(validDenial))
	}))
	defer server.Close()
	client := NewClient(config.PanelConfig{URL: server.URL, Token: "synthetic-cancellation", MachineID: 9})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := client.GetMachineNodesContext(ctx)
	denial, ok := controlerror.AsAuthorityDenial(err)
	if !ok || denial.Scope != controlerror.MachineScope || denial.MachineID != 9 || denial.HTTPStatus != http.StatusUnauthorized || denial.Code != "NODE_UNAUTHORIZED" {
		t.Fatal("completed native denial lost its bound type", err)
	}
}
