package singbox

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

func TestAuthorizationStopBypassesStructuralLockAndClosesRetiringGenerations(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			origin := newReloadOrigin(t, "O:")
			proxy := newReloadSocks(t, origin)
			runtime := New(config.KernelConfig{Type: "singbox", LogLevel: "error", ConfigDir: t.TempDir()})
			defer runtime.Stop()
			old := reloadSpec(protocol, reloadPort(t), proxy)
			users := []model.UserSpec{{ID: 7, UUID: reloadUUID}}
			if err := runtime.Start(old, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			oldStream := reloadDial(t, protocol, old.ServerPort, reloadUUID, origin.listener.Addr())
			defer oldStream.Close()
			reloadExchange(t, oldStream, "O:", "retiring-auth-stream")

			current := reloadSpec(protocol, reloadPort(t), proxy)
			if err := runtime.Start(current, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			currentStream := reloadDial(t, protocol, current.ServerPort, reloadUUID, origin.listener.Addr())
			defer currentStream.Close()
			reloadExchange(t, currentStream, "O:", "current-auth-stream")
			runtime.mu.Lock()
			locked := true
			defer func() {
				if locked {
					runtime.mu.Unlock()
				}
			}()
			done := make(chan struct{})
			go func() { runtime.StopAuthorization(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("authorization stop waited for structural kernel lock")
			}
			if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", current.ServerPort), 100*time.Millisecond); err == nil {
				c.Close()
				t.Fatal("current listener survived authorization stop")
			}
			for _, stream := range []net.Conn{oldStream, currentStream} {
				stream.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				var b [1]byte
				n, err := stream.Read(b[:])
				if n != 0 || err == nil {
					t.Fatal("expired live stream usable", n, err)
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("expired stream not closed")
				}
			}
			runtime.mu.Unlock()
			locked = false
			if runtime.IsRunning() {
				t.Fatal("expired runtime reported running")
			}
			if err := runtime.Start(current, users, kernel.TLSCert{}); err == nil || !strings.Contains(err.Error(), "AUTHORIZATION_EXPIRED") {
				t.Fatal("same expired runtime revived", err)
			}
			runtime.Stop()
			traffic, _, _, err := runtime.GetUserTraffic(context.Background())
			if err != nil || traffic[7][0] < int64(len("current-auth-stream")) {
				t.Fatal("expiry discarded current cumulative meter", traffic, err)
			}
		})
	}
}
