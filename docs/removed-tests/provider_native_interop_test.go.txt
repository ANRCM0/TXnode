//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	M "github.com/sagernet/sing/common/metadata"
)

// The explicit runner starts real Laravel routes and the separate Provider.
// Only Core's not-yet-open installation admission is substituted by the fixture.
func TestNativeProviderCoreMaterialAndRealVLESS(t *testing.T) {
	directory := os.Getenv("NATIVE_PROVIDER_NODE_DIR")
	if directory == "" {
		t.Skip("requires the private Core/Provider mTLS process runner")
	}
	var fixture struct {
		NodeID        int `json:"node_id"`
		UserID        int `json:"user_id"`
		Port          int `json:"port"`
		SecondaryPort int `json:"secondary_port"`
		OriginPort    int `json:"origin_port"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "fixture.json"))
	if err != nil || json.Unmarshal(raw, &fixture) != nil || fixture.NodeID != 1 {
		t.Fatal("invalid non-secret integration fixture")
	}
	cfg, err := config.Load(filepath.Join(directory, "node.json"))
	if err != nil {
		t.Fatal("native Provider configuration refused", err)
	}
	secondaryConfig, err := config.Load(filepath.Join(directory, "node-secondary.json"))
	if err != nil {
		t.Fatal("native Provider sibling configuration refused", err)
	}
	origin, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.OriginPort)))
	if err != nil {
		t.Fatal("origin unavailable", err)
	}
	defer origin.Close()
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	start := func(nodeConfig *config.Config, port int) (*Service, context.CancelFunc, <-chan error) {
		svc, err := NewChecked(nodeConfig)
		if err != nil {
			t.Fatal("native service configuration refused", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- svc.Run(ctx) }()
		t.Cleanup(cancel)
		liveProtocolWait(t, done, 15*time.Second, func() bool {
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 30*time.Millisecond)
			if err == nil {
				conn.Close()
			}
			return err == nil
		})
		return svc, cancel, done
	}
	connect := func(svc *Service, port int) (net.Conn, string) {
		svc.authorizationAdmissionMu.Lock()
		manager := svc.authorization
		svc.authorizationAdmissionMu.Unlock()
		snapshot := manager.Current()
		if snapshot == nil || len(snapshot.Users) != 1 || snapshot.Users[0].ID != fixture.UserID {
			t.Fatal("real Provider user did not reach authorization manager")
		}
		uuid := snapshot.Users[0].UUID
		if uuid == "22222222-2222-4222-8222-222222222222" || len(uuid) != 36 {
			t.Fatal("legacy or metadata credential reached the kernel")
		}
		raw, stream := liveProtocolDial(t, "vless",
			net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), uuid, M.ParseSocksaddr(origin.Addr().String()))
		t.Cleanup(func() { raw.Close() })
		t.Cleanup(func() { stream.Close() })
		stream.SetDeadline(time.Now().Add(10 * time.Second))
		body := []byte("actual-provider-uuid-through-native-core-and-vless")
		if _, err := stream.Write(body); err != nil {
			t.Fatal("real VLESS write refused", err)
		}
		echo := make([]byte, len(body))
		if _, err := io.ReadFull(stream, echo); err != nil || !bytes.Equal(body, echo) {
			t.Fatal("real VLESS echo failed")
		}
		stream.SetDeadline(time.Time{})
		return stream, uuid
	}
	waitClosed := func(stream net.Conn, port int, limit time.Duration) {
		stream.SetReadDeadline(time.Now().Add(limit))
		var one [1]byte
		_, err := stream.Read(one[:])
		if err == nil {
			t.Fatal("revoked or expired stream remained readable")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("stream was not closed before authorization deadline")
		}
		limitAt := time.Now().Add(2 * time.Second)
		for time.Now().Before(limitAt) {
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 30*time.Millisecond)
			if err != nil {
				return
			}
			conn.Close()
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("authorization closed the stream but left listener admission open")
	}
	stop := func(cancel context.CancelFunc, done <-chan error) {
		cancel()
		select {
		case <-done:
		case <-time.After(35 * time.Second):
			t.Fatal("native Provider service failed to stop")
		}
	}

	first, cancelFirst, doneFirst := start(cfg, fixture.Port)
	stream, uuid := connect(first, fixture.Port)
	second, cancelSecond, doneSecond := start(secondaryConfig, fixture.SecondaryPort)
	sibling, siblingUUID := connect(second, fixture.SecondaryPort)
	if siblingUUID != uuid {
		t.Fatal("authorized sibling did not receive the same Provider generation")
	}
	if err := os.WriteFile(filepath.Join(directory, "offline"), []byte("offline"), 0600); err != nil {
		t.Fatal(err)
	}
	waitClosed(stream, fixture.Port, 35*time.Second)
	stop(cancelFirst, doneFirst)
	if !first.reporter.HasTerminalTail() && !first.reporter.HasRecoveryBatch() {
		t.Fatal("offline expiry discarded the original unreported traffic")
	}
	sibling.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := sibling.Write([]byte("sibling")); err != nil {
		t.Fatal("unaffected sibling lost authorization")
	}
	echo := make([]byte, len("sibling"))
	if _, err := io.ReadFull(sibling, echo); err != nil || string(echo) != "sibling" {
		t.Fatal("unaffected sibling real VLESS stream failed")
	}
	sibling.SetDeadline(time.Time{})
	command := exec.Command("php", os.Getenv("NATIVE_PROVIDER_NODE_FIXTURE"), "revoke")
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		_ = output
		t.Fatal("real Core/Provider revocation failed")
	}
	waitClosed(sibling, fixture.SecondaryPort, 12*time.Second)
	stop(cancelSecond, doneSecond)
	err = filepath.WalkDir(cfg.Authorization.StateDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(uuid)) {
			t.Error("plaintext credential leaked into persistent authorization state")
		}
		return nil
	})
	if err != nil {
		t.Fatal("cannot inspect authorization state", err)
	}
	t.Log("Real Core entitlement, Provider mTLS material, VLESS, isolated offline expiry, retained tail and sibling revocation passed.")
}
