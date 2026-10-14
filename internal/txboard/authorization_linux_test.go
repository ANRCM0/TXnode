//go:build linux

package txboard

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

func TestNativeAuthorizedSnapshotRequiresCompleteFreshSignedHTTPS(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	users := []panel.User{{ID: 7, UUID: "00112233-4455-6677-8899-aabbccddeeff"}}
	machine := 9
	for _, name := range []string{"valid", "empty", "wrong_machine", "outer_user_substitution", "invalid_signature", "duplicate_envelope", "304", "503", "unsigned"} {
		t.Run(name, func(t *testing.T) {
			cfg := config.AuthorizationConfig{Enabled: true, StateDir: filepath.Join(t.TempDir(), "private-state"), CoreInstanceID: "core-auth-fixture", KeyID: "native-key", KeyEpoch: "1", PublicKey: public, PolicyVersion: config.NativeAuthorizationPolicyVersion, MaxClockSkew: 5}
			m, err := authorization.NewManager(cfg, authorization.Target{NodeID: 42, MachineID: &machine})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			trust := authorization.Trust{ProtocolVersion: 1, CoreInstanceID: cfg.CoreInstanceID, KeyID: cfg.KeyID, KeyEpoch: cfg.KeyEpoch, Algorithm: "Ed25519", PublicKey: public}
			if err := m.SetTrust(trust); err != nil {
				t.Fatal(err)
			}
			candidateUsers := users
			if name == "empty" {
				candidateUsers = []panel.User{}
			}
			p := authorization.Payload{ProtocolVersion: 1, Audience: authorization.Audience, PolicyVersion: cfg.PolicyVersion, CoreInstanceID: cfg.CoreInstanceID, NodeID: 42, MachineID: &machine, Revision: "1", KeyID: cfg.KeyID, KeyEpoch: cfg.KeyEpoch, IssuedAt: time.Now().Unix(), NotBefore: time.Now().Unix() - 5, ExpiresAt: time.Now().Unix() + 60, Complete: true, Users: candidateUsers}
			if name == "wrong_machine" {
				v := machine + 1
				p.MachineID = &v
			}
			raw, _ := json.Marshal(p)
			env := authorization.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
			if name == "invalid_signature" {
				env.Signature = "bad"
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-None-Match") != "" || r.Header.Get("Authorization") != "Bearer synthetic-token" || r.Header.Get("X-TX-Node-ID") != "42" || r.Header.Get("X-TX-Machine-ID") != strconv.Itoa(machine) {
					t.Error("unsigned cache or invalid target headers")
				}
				if name == "304" {
					w.WriteHeader(304)
					return
				}
				if name == "503" {
					w.WriteHeader(503)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if name == "duplicate_envelope" {
					w.Write([]byte(`{"data":{},"data":{}}`))
					return
				}
				outer := candidateUsers
				if name == "outer_user_substitution" {
					outer = []panel.User{{ID: 7, UUID: "forged"}}
				}
				data := map[string]any{"protocol_version": 1, "node_id": 42, "users": outer}
				if name != "unsigned" {
					data["authorization"] = env
				}
				json.NewEncoder(w).Encode(map[string]any{"data": data, "request_id": "test-request"})
			}))
			defer server.Close()
			c := NewClient(config.PanelConfig{URL: server.URL, Token: "synthetic-token", NodeID: 42, MachineID: machine})
			c.http = server.Client()
			c.usersETag = "old-etag"
			got, snapshot, err := c.AuthorizedUsersSnapshot(m)
			if name == "valid" || name == "empty" {
				if err != nil || got == nil || snapshot == nil || len(got) != len(candidateUsers) {
					t.Fatal("valid signed transport rejected", err)
				}
				if m.Current() != nil || !m.Expiry().IsZero() {
					t.Fatal("HTTP background read applied authority before service")
				}
				return
			}
			if err == nil || got != nil || snapshot != nil {
				t.Fatal("unsafe signed response accepted")
			}
			if name == "503" {
				if authorization.IsRefusal(err) {
					t.Fatal("network/server fault inferred revocation")
				}
			} else if !authorization.IsRefusal(err) {
				t.Fatal("signed response refusal lost type", err)
			}
		})
	}
}
