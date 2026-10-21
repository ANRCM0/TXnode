//go:build linux

package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel/txnode"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/panel"
	"github.com/ANRCM0/TX-Node/internal/txboard"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
	"github.com/gorilla/websocket"
)

type nativeConfigBlockedPlane struct {
	*nativeBillingPlane
	endpoint string
	polls    atomic.Int32
}

func (p *nativeConfigBlockedPlane) Poll(ctx context.Context) (controlplane.Snapshot, error) {
	p.polls.Add(1)
	for _, path := range []string{"/txapi/node/v1/config", "/txapi/node/v1/users"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+path, nil)
		response, err := http.DefaultClient.Do(req)
		if err == nil {
			response.Body.Close()
		}
	}
	return controlplane.Snapshot{}, errors.New("blocked config/users REST")
}

func nativeConfigService(t *testing.T, initial *model.NodeSpec, sourceURL string) (*Service, *nativeConfigBlockedPlane) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	base := &authorityTestPlane{bootstrap: controlplane.Bootstrap{Config: initial}}
	plane := &nativeBillingPlane{authorityTestPlane: base, key: key, period: "14"}
	plane.trust = authorization.Trust{ProtocolVersion: 1, CoreInstanceID: "1b32d316-8cb8-4b46-8d49-e281c28d5169", KeyID: "native-billing", KeyEpoch: "1",
		Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	original := authorityService(t, base)
	original.cfg.Panel.URL = "https://127.0.0.1:18443"
	root := t.TempDir()
	original.cfg.Authorization = config.AuthorizationConfig{Enabled: true, StateDir: filepath.Join(root, "authority"), CoreInstanceID: plane.trust.CoreInstanceID,
		KeyID: plane.trust.KeyID, KeyEpoch: "1", PublicKey: plane.trust.PublicKey, PolicyVersion: config.NativeProviderUsagePolicyVersion, RefreshInterval: 30, MaxClockSkew: 5,
		Provider: config.AuthorizationProviderConfig{Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1",
			CAFile: filepath.Join(root, "ca.pem"), ClientCert: filepath.Join(root, "node.pem"), ClientKey: filepath.Join(root, "node.key")}}
	original.cfg.UsageV2 = config.UsageV2Config{Enabled: true, Directory: filepath.Join(root, "usage")}
	blocked := &nativeConfigBlockedPlane{nativeBillingPlane: plane, endpoint: sourceURL}
	s := NewWithControlPlane(original.cfg, blocked)
	kernel := txnode.New(txnode.RuntimeConfig{})
	s.kernel, s.kernelLife = kernel, kernellifecycle.New(kernel)
	if err := s.preflightNativeUsage(); err != nil {
		t.Fatal(err)
	}
	if err := s.initAuthorization(); err != nil {
		t.Fatal(err)
	}
	snapshot := plane.snapshot(t)
	plane.transport = &modeTransport{session: *snapshot.Authorization.Payload.UsageV2, receipts: map[string]usagev2.Receipt{}}
	plane.bootstrap.Authorization, plane.bootstrap.Users = snapshot.Authorization, snapshot.Users
	plane.bootstrap.UsageV2Session, plane.bootstrap.UsageV2Transport, plane.bootstrap.UsageV2NativeHTTP = snapshot.Authorization.Payload.UsageV2, plane.transport, true
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.stopNativeUsageIO(); s.kernel.Stop(); s.closeNativeUsage(); s.closeAuthorization() })
	return s, blocked
}

func nativeConfigOrigin(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return listener
}
func nativeConfigPanel(t *testing.T, port int, origin net.Listener) (*panel.NodeConfig, *model.NodeSpec) {
	t.Helper()
	cfg := &panel.NodeConfig{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp",
		CustomRoutes: []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{origin.Addr().(*net.TCPAddr).Port}, "outbound": "direct"}}}
	spec, err := model.NodeSpecFromPanelValidated(cfg, config.KernelConfig{Type: "txnode", LogLevel: "error"})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, spec
}
func nativeConfigEcho(t *testing.T, c net.Conn, body string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(body))
	if _, err := io.ReadFull(c, response); err != nil || !bytes.Equal(response, []byte(body)) {
		t.Fatal("native config echo", err)
	}
}

// Real socket framing and real bounded VLESS kernel; only the signing fixture
// and unavailable REST server replace the remote Core/Provider processes.
func TestNativeConfigWSPortReloadKeepsSignedCollectorAndSibling(t *testing.T) {
	origin := nativeConfigOrigin(t)
	oldPort, newPort := authorityPort(t), authorityPort(t)
	wire, initial := nativeConfigPanel(t, oldPort, origin)
	var reads atomic.Int32
	frames := make(chan map[string]any, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			reads.Add(1)
			http.Error(w, "REST held", 503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer native-config-token" || r.Header.Get("X-TX-Node-ID") != "42" {
			http.Error(w, "unauthorized", 401)
			return
		}
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		if c.WriteJSON(map[string]any{"protocol_version": 1, "event": "session.ready", "data": map[string]any{"mode": "node", "node_id": 42}}) != nil {
			return
		}
		select {
		case frame := <-frames:
			c.WriteJSON(frame)
		case <-release:
			return
		}
		<-release
	}))
	t.Cleanup(func() { close(release); server.Close() })
	s, plane := nativeConfigService(t, initial, server.URL)
	siblingPanel, siblingInitial := nativeConfigPanel(t, authorityPort(t), origin)
	sibling, _ := nativeConfigService(t, siblingInitial, server.URL)
	_, siblingStream := nativeC2VLESSDial(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(siblingPanel.ServerPort)), plane.uuidOrDefault(), origin.Addr())
	defer siblingStream.Close()
	nativeConfigEcho(t, siblingStream, "sibling-before")
	before := s.authorization.Current()
	collector, meter, deadline, session := s.nativeUsage.collector.Load(), s.nativeUsage.active.Load(), s.authorizationDeadline, s.nativeUsage.session
	events := make(chan controlplane.Event, 1)
	socket := txboard.NewSocket("ws"+strings.TrimPrefix(server.URL, "http")+"/ws", "native-config-token", 42, 0, config.WSConfig{HandshakeTimeout: 2}, func(raw txboard.Event) {
		event, err := controlplane.TranslateTXBoardEvent(raw, s.cfg.Kernel)
		if err == nil {
			events <- event
		}
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socketDone := make(chan struct{})
	go func() { defer close(socketDone); socket.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-socketDone:
		case <-time.After(3 * time.Second):
			t.Error("socket failed to join")
		}
	})
	wire.ServerPort = newPort
	frames <- map[string]any{"protocol_version": 1, "event": "sync.config", "data": map[string]any{"node_id": 42, "config": wire}}
	select {
	case event := <-events:
		s.handleWSEvent(ctx, event)
	case <-time.After(3 * time.Second):
		t.Fatal("real WS config missing")
	}
	if s.authorizationFailure != nil || s.appliedConfigHash != computeConfigHash(s.lastConfig) || s.lastConfig.ServerPort != newPort || s.desiredDirty {
		t.Fatal("port update not applied", s.authorizationFailure)
	}
	if s.nativeUsage.collector.Load() != collector || s.nativeUsage.active.Load() != meter || s.authorization.Current().Digest != before.Digest || !s.authorizationDeadline.Equal(deadline) || !reflect.DeepEqual(session, s.nativeUsage.session) {
		t.Fatal("configuration invented authority or metering generation")
	}
	if reads.Load() != 0 || plane.polls.Load() != 0 || s.authorizationRefresh.Load() {
		t.Fatal("WS port reload fetched blocked REST")
	}
	if c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(oldPort)), 50*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("old listener remained")
	}
	_, fresh := nativeC2VLESSDial(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(newPort)), plane.uuidOrDefault(), origin.Addr())
	defer fresh.Close()
	nativeConfigEcho(t, fresh, "new-port-current-grant")
	nativeConfigEcho(t, siblingStream, "sibling-after")
	if !sibling.kernel.IsRunning() {
		t.Fatal("configuration reload stopped the sibling")
	}
	if collector.Unknown() {
		t.Fatal("port reload retired original collector")
	}
}
func (p *nativeConfigBlockedPlane) uuidOrDefault() string {
	if p.uuid != "" {
		return p.uuid
	}
	return "00112233-4455-4677-8899-aabbccddeeff"
}

func TestNativeConfigReloadFailureRetainsOriginalListenerAndPendingDesired(t *testing.T) {
	origin := nativeConfigOrigin(t)
	_, initial := nativeConfigPanel(t, authorityPort(t), origin)
	s, plane := nativeConfigService(t, initial, "http://127.0.0.1:1")
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	next := *initial
	next.ServerPort = occupied.Addr().(*net.TCPAddr).Port
	collector, meter, digest, applied := s.nativeUsage.collector.Load(), s.nativeUsage.active.Load(), s.authorization.Current().Digest, s.appliedConfigHash
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: &next})
	if !s.kernel.IsRunning() || s.appliedConfigHash != applied || s.lastConfig.ServerPort != next.ServerPort || !s.desiredDirty || s.applicationFailure != "KERNEL_RELOAD_FAILED" {
		t.Fatal("failed reload lost old applied runtime or desired retry")
	}
	if collector != s.nativeUsage.collector.Load() || meter != s.nativeUsage.active.Load() || digest != s.authorization.Current().Digest || collector.Unknown() || plane.polls.Load() != 0 {
		t.Fatal("failed port reload changed authority")
	}
	_, stream := nativeC2VLESSDial(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(initial.ServerPort)), plane.uuidOrDefault(), origin.Addr())
	defer stream.Close()
	nativeConfigEcho(t, stream, "old-runtime-survives-bind-failure")
}

func TestNativeConfigReloadExpiryAndMeterRevocationCannotAdmitPort(t *testing.T) {
	for _, reason := range []string{"expiry", "meter-revocation"} {
		t.Run(reason, func(t *testing.T) {
			origin := nativeConfigOrigin(t)
			_, initial := nativeConfigPanel(t, authorityPort(t), origin)
			s, _ := nativeConfigService(t, initial, "http://127.0.0.1:1")
			next := *initial
			next.ServerPort = authorityPort(t)
			before := s.authorization.Current().Digest
			if reason == "expiry" {
				s.authorizationAdmissionMu.Lock()
				s.authorizationDeadline = time.Now().Add(-time.Second)
				s.authorizationAdmissionMu.Unlock()
			} else {
				s.nativeUsage.active.Load().(interface{ StopBoundedUsageTraffic() }).StopBoundedUsageTraffic()
			}
			s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: &next})
			if s.authorizationFailure == nil || s.kernel.IsRunning() || s.authorization.Current().Digest != before {
				t.Fatal("expired/revoked grant survived config push")
			}
			if c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(next.ServerPort)), 50*time.Millisecond); err == nil {
				c.Close()
				t.Fatal("revoked config opened listener")
			}
		})
	}
}

func TestNativeConfigOlderFullPollCannotRollBackWSPort(t *testing.T) {
	origin := nativeConfigOrigin(t)
	_, initial := nativeConfigPanel(t, authorityPort(t), origin)
	s, plane := nativeConfigService(t, initial, "http://127.0.0.1:1")
	pending := plane.snapshot(t)
	pending.Config = initial
	generation := s.desiredGeneration
	next := *initial
	next.ServerPort = authorityPort(t)
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: &next})
	if err := s.applyAuthorizationResult(context.Background(), authorizationResult{snapshot: pending, configGeneration: generation, hasConfigGeneration: true}); err != nil {
		t.Fatal(err)
	}
	if s.lastConfig.ServerPort != next.ServerPort || s.authorization.Current().Digest != pending.Authorization.Digest {
		t.Fatal("stale config rolled back newer WS target or fresh signed authority was discarded")
	}
}
func TestNativeConfigNonPortDeltaRetainsFullSignedRESTPath(t *testing.T) {
	origin := nativeConfigOrigin(t)
	_, initial := nativeConfigPanel(t, authorityPort(t), origin)
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reads.Add(1); http.Error(w, "REST blocked", 503) }))
	defer server.Close()
	s, plane := nativeConfigService(t, initial, server.URL)
	candidate := *initial
	candidate.ServerPort = authorityPort(t)
	candidate.Protocol = "vmess"
	collector, meter, applied := s.nativeUsage.collector.Load(), s.nativeUsage.active.Load(), s.appliedConfigHash
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: &candidate})
	select {
	case result := <-s.authorizationResults:
		if result.err == nil {
			t.Fatal("unexpected full poll authority")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("non-port config bypassed existing signed refresh path")
	}
	if plane.polls.Load() != 1 || reads.Load() != 2 || s.appliedConfigHash != applied || s.nativeUsage.collector.Load() != collector || s.nativeUsage.active.Load() != meter {
		t.Fatal("unsupported config changed runtime without signed reconciliation")
	}
}
