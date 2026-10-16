//go:build linux

package authorization

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
)

func TestProviderGrantHighWaterPrecedesFetchAndStateContainsNoMaterial(t *testing.T) {
	p, trust, key, users, now := providerFixture(t)
	root := t.TempDir()
	cfg := config.AuthorizationConfig{Enabled: true, StateDir: filepath.Join(root, "state"), CoreInstanceID: trust.CoreInstanceID, KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch, PublicKey: trust.PublicKey, PolicyVersion: p.PolicyVersion, MaxClockSkew: 5,
		Provider: config.AuthorizationProviderConfig{Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1", CAFile: filepath.Join(root, "ca.pem"), ClientCert: filepath.Join(root, "client.pem"), ClientKey: filepath.Join(root, "client.key")}}
	target := Target{NodeID: p.NodeID, MachineID: p.MachineID}
	manager, err := NewManager(cfg, target)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.SetTrust(trust); err != nil {
		t.Fatal(err)
	}
	envelope := signProvider(t, p, key)
	grant, err := manager.VerifyProviderGrant(envelope, p.Users, now)
	if err != nil || grant == nil {
		t.Fatal("valid metadata rejected", err)
	}
	if manager.Current() != nil || !manager.Expiry().IsZero() {
		t.Fatal("metadata applied an authorization lease")
	}
	if _, err := manager.Accept(envelope, p.Users, now); !IsRefusal(err) {
		t.Fatal("metadata placeholder reached acceptance")
	}
	snapshot, err := manager.Accept(envelope, users, now)
	if err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(filepath.Join(cfg.StateDir, "state.json"))
	if err != nil || strings.Contains(string(state), users[0].UUID) || strings.Contains(string(state), p.Users[0].UUID) {
		t.Fatal("material or user rows persisted", err)
	}
	deadline := manager.Expiry()
	snapshot.Users[0].UUID = "10112233-4455-4677-8899-aabbccddeeff"
	if _, err := manager.AcceptVerified(snapshot, now.Add(time.Second)); !IsRefusal(err) {
		t.Fatal("candidate mutation bypassed the application boundary")
	}
	if !deadline.Equal(manager.Expiry()) {
		t.Fatal("failed acceptance renewed authority")
	}
	for _, name := range []string{"rollback", "conflict", "provider", "epoch", "outer_metadata"} {
		t.Run(name, func(t *testing.T) {
			next := p
			next.Users = cloneUsers(p.Users)
			metadata := cloneUsers(p.Users)
			switch name {
			case "rollback":
				next.Revision = "4"
			case "conflict":
				next.Provider.RecipientSHA256 = strings.Repeat("b", 64)
			case "provider":
				next.Revision = "6"
				next.Provider.ProviderID = "other-provider"
			case "epoch":
				next.Revision = "6"
				next.Provider.ProviderInstanceEpoch = "2"
			case "outer_metadata":
				metadata[0].DeviceLimit++
			}
			if _, err := manager.VerifyProviderGrant(signProvider(t, next, key), metadata, now); !IsRefusal(err) {
				t.Fatal("unsafe grant reached material retrieval", err)
			}
		})
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(cfg, target)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.SetTrust(trust); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.VerifyProviderGrant(envelope, p.Users, now); !IsRefusal(err) {
		t.Fatal("restarted process fetched replay material")
	}
	p.Revision = "6"
	if _, err := restarted.VerifyProviderGrant(signProvider(t, p, key), p.Users, now); err != nil {
		t.Fatal("fresh revision rejected after restart", err)
	}
}
