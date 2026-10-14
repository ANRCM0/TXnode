//go:build linux

package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/panel"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	M "github.com/sagernet/sing/common/metadata"
)

// This fixture exercises actual Service/kernel/spool boundaries. Only the
// transport is synthetic; its signed DTO is verified by the production manager.
type signedAuthorityPlane struct {
	*authorityTestPlane
	authMu    sync.Mutex
	manager   *authorization.Manager
	key       ed25519.PrivateKey
	trust     authorization.Trust
	revision  int
	lease     int64
	offline   bool
	refreshes int
	corrupt   bool
}

func signedAuthorityFixture(t *testing.T, kernelName string, lease int64) (*Service, *signedAuthorityPlane, int) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	port := authorityPort(t)
	p := &signedAuthorityPlane{authorityTestPlane: &authorityTestPlane{bootstrap: authorityBootstrap(port)}, key: key, lease: lease}
	p.trust = authorization.Trust{ProtocolVersion: 1, CoreInstanceID: "core-service-auth-test", KeyID: "service-auth-test", KeyEpoch: "1", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	s := authorityService(t, p.authorityTestPlane)
	s.cfg.Panel.URL = "https://127.0.0.1:1"
	s.cfg.Kernel.Type = kernelName
	s.cfg.Node.PullInterval = 3600
	s.cfg.Authorization = config.AuthorizationConfig{Enabled: true, StateDir: t.TempDir(), CoreInstanceID: p.trust.CoreInstanceID, KeyID: p.trust.KeyID, KeyEpoch: p.trust.KeyEpoch, PublicKey: p.trust.PublicKey, PolicyVersion: config.NativeAuthorizationPolicyVersion, RefreshInterval: 1, MaxClockSkew: 5}
	s = NewWithControlPlane(s.cfg, p)
	return s, p, port
}

func (p *signedAuthorityPlane) ConfigureAuthorization(m *authorization.Manager) error {
	p.authMu.Lock()
	defer p.authMu.Unlock()
	p.manager = m
	return m.SetTrust(p.trust)
}
func (p *signedAuthorityPlane) signedSnapshot() (controlplane.Snapshot, error) {
	p.authMu.Lock()
	defer p.authMu.Unlock()
	if p.offline {
		return controlplane.Snapshot{}, errors.New("synthetic network unavailable")
	}
	p.mu.Lock()
	b := p.bootstrap
	p.mu.Unlock()
	p.revision++
	users := make([]panel.User, len(b.Users))
	for i, u := range b.Users {
		users[i] = panel.User{ID: u.ID, UUID: u.UUID, SpeedLimit: u.SpeedLimit, DeviceLimit: u.DeviceLimit, TrafficPeriod: u.TrafficPeriod}
	}
	now := time.Now()
	payload := authorization.Payload{ProtocolVersion: 1, Audience: authorization.Audience, PolicyVersion: config.NativeAuthorizationPolicyVersion, CoreInstanceID: p.trust.CoreInstanceID, NodeID: 42, Revision: strconv.Itoa(p.revision), KeyID: p.trust.KeyID, KeyEpoch: p.trust.KeyEpoch, IssuedAt: now.Unix(), NotBefore: now.Unix() - 1, ExpiresAt: now.Unix() + p.lease, Complete: true, Users: users}
	raw, _ := json.Marshal(payload)
	sig := ed25519.Sign(p.key, raw)
	if p.corrupt {
		sig[0] ^= 1
	}
	env := authorization.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(sig)}
	auth, err := p.manager.Verify(env, users, now)
	return controlplane.Snapshot{Config: b.Config, Users: b.Users, Authorization: auth}, err
}
func (p *signedAuthorityPlane) Initial(context.Context, func() map[string]interface{}, chan<- controlplane.Event, chan<- controlplane.StatusChange) (controlplane.Bootstrap, error) {
	s, err := p.signedSnapshot()
	return controlplane.Bootstrap{Config: s.Config, Users: s.Users, Authorization: s.Authorization}, err
}
func (p *signedAuthorityPlane) Poll(context.Context) (controlplane.Snapshot, error) {
	return p.signedSnapshot()
}
func (p *signedAuthorityPlane) RefreshAuthorization(context.Context) (controlplane.Snapshot, error) {
	p.authMu.Lock()
	p.refreshes++
	p.authMu.Unlock()
	return p.signedSnapshot()
}

func TestSignedAuthorizationOfflineExpiryClosesStreamsAndReplaysOriginalTail(t *testing.T) {
	for _, kernelName := range []string{"singbox", "xray"} {
		t.Run(kernelName, func(t *testing.T) {
			s, p, port := signedAuthorityFixture(t, kernelName, 3)
			origin, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			go func() {
				conn, err := origin.Accept()
				if err == nil {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}
			}()
			s.cfg.Kernel.CustomRoute = []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{origin.Addr().(*net.TCPAddr).Port}, "outbound": "direct"}}
			if kernelName == "xray" {
				s.cfg.Kernel.CustomRoute = []map[string]any{{"type": "field", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": strconv.Itoa(origin.Addr().(*net.TCPAddr).Port), "outboundTag": "direct"}}
			}
			s = NewWithControlPlane(s.cfg, p)
			p.reportErr = errors.New("offline report")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx) }()
			authorityWaitListener(t, port)
			raw, client := liveProtocolDial(t, "vless", fmt.Sprintf("127.0.0.1:%d", port), liveProtocolUUID, M.ParseSocksaddr(origin.Addr().String()))
			defer raw.Close()
			defer client.Close()
			client.SetDeadline(time.Now().Add(8 * time.Second))
			body := []byte("signed-authority-existing-stream")
			if _, err := client.Write(body); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(body))
			if _, err := io.ReadFull(client, got); err != nil || string(got) != string(body) {
				t.Fatal("actual signed stream echo", err)
			}
			p.authMu.Lock()
			p.offline = true
			p.authMu.Unlock()
			// A long ordinary administrator poll interval does not disable renewal.
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "NODE_AUTHORIZATION_EXPIRED") {
					t.Fatal("expiry reason lost", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("finite lease did not stop Service")
			}
			p.authMu.Lock()
			refreshes := p.refreshes
			p.authMu.Unlock()
			if refreshes < 1 {
				t.Fatal("independent authorization refresh absent")
			}
			if s.kernel.IsRunning() {
				t.Fatal("expired kernel running")
			}
			if conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond); err == nil {
				conn.Close()
				t.Fatal("expired listener open")
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if n, err := client.Read(b[:]); n != 0 || err == nil {
				t.Fatal("expired existing stream remained usable")
			}
			tail, err := os.ReadFile(s.legacyPendingPath + ".terminal.json")
			if err != nil {
				t.Fatal(err)
			}
			var batch reporting.Batch
			if json.Unmarshal(tail, &batch) != nil || batch.Payload.BatchID == "" || batch.Payload.Traffic[7] != [2]int64{int64(len(body)), int64(len(body))} {
				t.Fatal("final meter/batch identity missing", batch.Payload)
			}
			fresh := NewWithControlPlane(s.cfg, p)
			if err := fresh.initialSetup(context.Background()); err == nil {
				fresh.kernel.Stop()
				fresh.closeAuthorization()
				t.Fatal("offline restart admitted stale credentials")
			}
			fresh.closeAuthorization()
			p.authMu.Lock()
			p.offline = false
			p.lease = 30
			p.authMu.Unlock()
			p.mu.Lock()
			p.reportErr = nil
			p.mu.Unlock()
			fresh = NewWithControlPlane(s.cfg, p)
			defer fresh.closeAuthorization()
			defer fresh.kernel.Stop()
			if err := fresh.initialSetup(context.Background()); err != nil {
				t.Fatal("fresh online signed recovery failed", err)
			}
			authorityWaitListener(t, port)
			p.mu.Lock()
			defer p.mu.Unlock()
			found := false
			for _, report := range p.reports {
				if report.BatchID == batch.Payload.BatchID {
					if report.Traffic[7] != batch.Payload.Traffic[7] {
						t.Fatal("tail body relabelled")
					}
					found = true
				}
			}
			if !found {
				t.Fatal("original expiry tail batch not replayed")
			}
		})
	}
}

func TestSignedAuthorizationUnsignedPushCannotChangeUsersAndSignedEmptyClosesListener(t *testing.T) {
	s, p, port := signedAuthorityFixture(t, "singbox", 30)
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.closeAuthorization()
	defer s.kernel.Stop()
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{{ID: 99, UUID: "unsigned-injected-user"}}})
	if len(s.users.Users()) != 1 || s.users.Users()[0].ID != 7 {
		t.Fatal("unsigned push mutated admission")
	}
	select {
	case result := <-s.authorizationResults:
		s.authorizationRefresh.Store(false)
		if err := s.applyAuthorizationResult(context.Background(), result); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("push failed to trigger signed reconciliation")
	}
	p.mu.Lock()
	p.bootstrap.Users = []model.UserSpec{}
	p.mu.Unlock()
	s.requestAuthorization(context.Background())
	select {
	case result := <-s.authorizationResults:
		s.authorizationRefresh.Store(false)
		if err := s.applyAuthorizationResult(context.Background(), result); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("empty signed snapshot absent")
	}
	if s.kernel.IsRunning() || len(s.users.Users()) != 0 {
		t.Fatal("empty complete authorization did not close listener")
	}
	if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("revoked listener open")
	}
}

func TestSignedAuthorizationForgedRenewalStopsAdmission(t *testing.T) {
	s, p, _ := signedAuthorityFixture(t, "singbox", 30)
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.closeAuthorization()
	defer s.kernel.Stop()
	p.authMu.Lock()
	p.corrupt = true
	p.authMu.Unlock()
	s.requestAuthorization(context.Background())
	select {
	case result := <-s.authorizationResults:
		s.authorizationRefresh.Store(false)
		err := s.applyAuthorizationResult(context.Background(), result)
		if err == nil {
			t.Fatal("forged renewal accepted")
		}
		s.stopForAuthorization(err)
	case <-time.After(time.Second):
		t.Fatal("renewal did not complete")
	}
	if s.kernel.IsRunning() {
		t.Fatal("forged renewal retained admission")
	}
}
