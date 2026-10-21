//go:build linux

package service

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/panel"
	"github.com/ANRCM0/TX-Node/internal/txboard"
)

func TestNativeAuthorizationWorkerCancellationJoinsCoreAndProviderRequests(t *testing.T) {
	for _, blocked := range []string{"core", "provider"} {
		t.Run(blocked, func(t *testing.T) {
			root := t.TempDir()
			entered, cancelled, escape := make(chan struct{}), make(chan struct{}), make(chan struct{})
			block := func(r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				select {
				case <-r.Context().Done():
					close(cancelled)
				case <-escape:
				}
			}
			provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if blocked != "provider" {
					t.Error("Core cancellation reached Provider")
					return
				}
				block(r)
			}))
			defer provider.Close()
			certificate := provider.TLS.Certificates[0]
			private, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			providerCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
			providerConfig := config.AuthorizationProviderConfig{Endpoint: provider.URL, ProviderID: "primary-provider", ProviderInstanceEpoch: "1",
				CAFile: filepath.Join(root, "provider-ca.pem"), ClientCert: filepath.Join(root, "recipient.pem"), ClientKey: filepath.Join(root, "recipient.key")}
			for name, body := range map[string][]byte{providerConfig.CAFile: providerCA, providerConfig.ClientCert: providerCA,
				providerConfig.ClientKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})} {
				if err := os.WriteFile(name, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			coreID, machineID := "1b32d316-8cb8-4b46-8d49-e281c28d5169", 9
			recipient := sha256.Sum256(certificate.Certificate[0])
			commitment := sha256.Sum256([]byte("00112233-4455-4677-8899-aabbccddeeff"))
			now := time.Now().Unix()
			payload := credentialdelivery.Payload{ProtocolVersion: 1, Audience: credentialdelivery.Audience, PolicyVersion: credentialdelivery.PolicyVersion,
				CoreInstanceID: coreID, NodeID: 42, MachineID: &machineID, Revision: "1", KeyID: "cancel-key", KeyEpoch: "1", IssuedAt: now,
				NotBefore: now - 5, ExpiresAt: now + 60, Complete: true, Users: []panel.User{{ID: 7, UUID: "sha256:" + hex.EncodeToString(commitment[:])}},
				Provider: credentialdelivery.ProviderBinding{InstallationID: coreID, ProviderID: providerConfig.ProviderID, ProviderInstanceEpoch: "1",
					RecipientSHA256: hex.EncodeToString(recipient[:]), CredentialProfileID: "vless-uuid/v1",
					Subjects: []credentialdelivery.Subject{{UserID: 7, AccessSubjectID: "10", SubscriptionID: "11", TermsID: "12",
						ProviderSubjectRef: "subject_" + strings.Repeat("a", 32), CredentialRef: "credential_" + strings.Repeat("b", 32), CredentialGeneration: "1", CredentialExpiresAt: now + 3600}}}}
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			envelope := credentialdelivery.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
			core := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/txapi/node/v1/users" {
					t.Error("unexpected native refresh route")
					return
				}
				if blocked == "core" {
					block(r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"protocol_version": 1, "node_id": 42, "users": payload.Users, "authorization": envelope}, "request_id": "fixture"})
			}))
			defer core.Close()
			defer close(escape)
			coreCA := filepath.Join(root, "core-ca.pem")
			if err := os.WriteFile(coreCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: core.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			client := txboard.NewClient(config.PanelConfig{URL: core.URL, Token: "synthetic-worker-cancellation", NodeID: 42, MachineID: machineID})
			if err := client.PrepareNativeUsageTLS(coreCA); err != nil {
				t.Fatal(err)
			}
			manager, err := authorization.NewManager(config.AuthorizationConfig{Enabled: true, StateDir: filepath.Join(root, "authority"), CoreInstanceID: coreID,
				KeyID: "cancel-key", KeyEpoch: "1", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
				PolicyVersion: config.NativeProviderAuthorizationPolicyVersion, MaxClockSkew: 5, Provider: providerConfig}, authorization.Target{NodeID: 42, MachineID: &machineID})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			if err := manager.SetTrust(authorization.Trust{ProtocolVersion: 1, CoreInstanceID: coreID, KeyID: "cancel-key", KeyEpoch: "1", Algorithm: "Ed25519",
				PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}); err != nil {
				t.Fatal(err)
			}
			plane := controlplane.NewMachineTXBoardControlPlane(client, config.KernelConfig{}, nil, nil)
			if err := plane.ConfigureAuthorization(manager); err != nil {
				t.Fatal(err)
			}
			service := &Service{source: plane, authorization: manager, authorizationResults: make(chan authorizationResult, 1)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			service.requestAuthorizationSnapshot(ctx, false)
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("authorization worker did not reach real request blocker")
			}
			cancel()
			joined := make(chan struct{})
			go func() { service.closeAuthorization(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("cancelled authorization worker blocked Service join")
			}
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("cancelled native request remained at owner")
			}
			if manager.Current() != nil || !manager.Expiry().IsZero() {
				t.Fatal("cancelled retrieval renewed authorization")
			}
		})
	}
}

type selfTerminatingRefreshPlane struct {
	*signedAuthorityPlane
	native *txboard.Client
}

func (p *selfTerminatingRefreshPlane) RefreshAuthorization(ctx context.Context) (controlplane.Snapshot, error) {
	_, err := p.native.HandshakeContext(ctx)
	return controlplane.Snapshot{}, err
}

func TestServiceOwnLeaseExitCancelsAuthorizationWorkerBeforeJoin(t *testing.T) {
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
	initial, base, port := signedAuthorityFixture(t, "txnode", 5)
	plane := &selfTerminatingRefreshPlane{signedAuthorityPlane: base, native: txboard.NewClient(config.PanelConfig{URL: server.URL, Token: "synthetic-self-stop", NodeID: 42})}
	service := NewWithControlPlane(initial.cfg, plane)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- service.Run(parent) }()
	authorityWaitListener(t, port)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("lease fixture did not start blocked refresh")
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "NODE_AUTHORIZATION_EXPIRED") {
			t.Fatal("Service lost actual finite lease failure", err)
		}
		if _, denial := controlerror.AsAuthorityDenial(err); denial {
			t.Fatal("local lease expiry forged HTTP rejection")
		}
	case <-time.After(7 * time.Second):
		t.Fatal("local Service termination waited for live parent to cancel refresh")
	}
	if parent.Err() != nil {
		t.Fatal("test cancelled the parent instead of Service network scope")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("Service-owned request was not cancelled")
	}
	if service.kernel.IsRunning() {
		t.Fatal("expired Service kernel still running")
	}
}
