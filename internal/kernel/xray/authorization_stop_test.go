package xray

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
)

func TestAuthorizationStopBypassesOperationAndStateLocks(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			runtime, node, users, origin := applicationKernel(t, protocol)
			stream, err := applicationDial(protocol, node, applicationOldUUID, origin)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			body := []byte("xray-expiring-existing-stream")
			applicationRoundtrip(t, stream, body)
			runtime.operationMu.Lock()
			runtime.mu.Lock()
			locked := true
			defer func() {
				if locked {
					runtime.mu.Unlock()
					runtime.operationMu.Unlock()
				}
			}()
			done := make(chan struct{})
			go func() { runtime.StopAuthorization(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("authorization stop waited for kernel transaction locks")
			}
			if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", node.ServerPort), 100*time.Millisecond); err == nil {
				c.Close()
				t.Fatal("expired listener remained open")
			}
			stream.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			var b [1]byte
			n, err := stream.Read(b[:])
			if n != 0 || err == nil {
				t.Fatal("expired existing stream remained usable", n, err)
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("expired existing stream idle but not closed")
			}
			runtime.mu.Unlock()
			runtime.operationMu.Unlock()
			locked = false
			if runtime.IsRunning() {
				t.Fatal("expired runtime reported running")
			}
			if err := runtime.Start(node, users, kernel.TLSCert{}); err == nil || !strings.Contains(err.Error(), "AUTHORIZATION_EXPIRED") {
				t.Fatal("expired runtime revived", err)
			}
			runtime.Stop()
			traffic, _, _, err := runtime.GetUserTraffic(context.Background())
			if err != nil || traffic[1][0] != int64(len(body)) || traffic[1][1] != int64(len(body)) {
				t.Fatal("expired cumulative meter changed", traffic, err)
			}
		})
	}
}
