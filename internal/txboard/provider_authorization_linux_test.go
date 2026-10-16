//go:build linux

package txboard

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

func TestProviderUsersSnapshotAuthenticatesMetadataBeforeDeliveryAndEmptyCloses(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	core := "1b32d316-8cb8-4b46-8d49-e281c28d5169"
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	machine := 9
	for _, mode := range []string{"empty", "signature", "node", "machine", "metadata", "expired", "material_required"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			cfg := config.AuthorizationConfig{Enabled: true, StateDir: filepath.Join(root, "private-state"), CoreInstanceID: core, KeyID: "native-key", KeyEpoch: "1", PublicKey: public, PolicyVersion: config.NativeProviderAuthorizationPolicyVersion, MaxClockSkew: 5,
				Provider: config.AuthorizationProviderConfig{Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1", CAFile: filepath.Join(root, "missing-ca.pem"), ClientCert: filepath.Join(root, "missing-client.pem"), ClientKey: filepath.Join(root, "missing-client.key")}}
			manager, err := authorization.NewManager(cfg, authorization.Target{NodeID: 42, MachineID: &machine})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			if err := manager.SetTrust(authorization.Trust{ProtocolVersion: 1, CoreInstanceID: core, KeyID: cfg.KeyID, KeyEpoch: "1", Algorithm: "Ed25519", PublicKey: public}); err != nil {
				t.Fatal(err)
			}
			now := time.Now().Unix()
			hash := sha256.Sum256([]byte("00112233-4455-4677-8899-aabbccddeeff"))
			p := credentialdelivery.Payload{ProtocolVersion: 1, Audience: credentialdelivery.Audience, PolicyVersion: credentialdelivery.PolicyVersion, CoreInstanceID: core, NodeID: 42, MachineID: &machine, Revision: "1", KeyID: cfg.KeyID, KeyEpoch: "1", IssuedAt: now, NotBefore: now - 5, ExpiresAt: now + 60, Complete: true,
				Users:    []panel.User{{ID: 7, UUID: "sha256:" + hex.EncodeToString(hash[:])}},
				Provider: credentialdelivery.ProviderBinding{InstallationID: core, ProviderID: cfg.Provider.ProviderID, ProviderInstanceEpoch: "1", RecipientSHA256: strings.Repeat("a", 64), CredentialProfileID: "vless-uuid/v1", Subjects: []credentialdelivery.Subject{{UserID: 7, AccessSubjectID: "10", SubscriptionID: "11", TermsID: "12", ProviderSubjectRef: "subject_" + strings.Repeat("a", 32), CredentialRef: "credential_" + strings.Repeat("b", 32), CredentialGeneration: "1", CredentialExpiresAt: now + 3600}}}}
			switch mode {
			case "empty":
				p.Users = []panel.User{}
				p.Provider.Subjects = []credentialdelivery.Subject{}
			case "node":
				p.NodeID++
			case "machine":
				p.MachineID = nil
			case "expired":
				p.IssuedAt = now - 60
				p.NotBefore = now - 65
				p.ExpiresAt = now
			}
			raw, _ := json.Marshal(p)
			envelope := credentialdelivery.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
			if mode == "signature" {
				envelope.Signature = strings.Repeat("A", 86)
			}
			outer := append([]panel.User{}, p.Users...)
			if mode == "metadata" {
				outer[0].SpeedLimit++
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-TX-Node-ID") != "42" || r.Header.Get("X-TX-Machine-ID") != "9" || r.Header.Get("If-None-Match") != "" {
					t.Error("Machine child target or signed refresh changed")
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"protocol_version": 1, "node_id": 42, "users": outer, "authorization": envelope}, "request_id": "fixture"})
			}))
			defer server.Close()
			client := NewClient(config.PanelConfig{URL: server.URL, Token: "synthetic-machine", NodeID: 42, MachineID: machine})
			client.http = server.Client()
			got, snapshot, err := client.AuthorizedUsersSnapshot(manager)
			if mode == "empty" {
				if err != nil || got == nil || len(got) != 0 || snapshot == nil {
					t.Fatal("empty signed cohort required unavailable Provider material", err)
				}
				if _, err := manager.AcceptVerified(snapshot, time.Now()); err != nil {
					t.Fatal("empty cohort cannot close authorization", err)
				}
				return
			}
			if err == nil || got != nil || snapshot != nil {
				t.Fatal("metadata reached runtime before actual material")
			}
			if mode == "material_required" {
				if err.Error() != "NODE_CREDENTIAL_DELIVERY_TLS_CONFIGURATION_UNAVAILABLE" {
					t.Fatal("valid grant skipped material retrieval", err)
				}
			} else if !authorization.IsRefusal(err) {
				t.Fatal("Provider was accessed before Core validation", err)
			}
			if manager.Current() != nil || !manager.Expiry().IsZero() {
				t.Fatal("failed retrieval renewed authority")
			}
		})
	}
}
