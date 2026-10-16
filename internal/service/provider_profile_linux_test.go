//go:build linux

package service

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nodesync"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

func providerProfileService(t *testing.T) (*Service, *fakeKernel, *authorityTestPlane, func(string, bool) *authorization.Snapshot) {
	t.Helper()
	plane := &authorityTestPlane{bootstrap: controlplane.Bootstrap{Config: &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: 12345}}}
	s := authorityService(t, plane)
	k := &fakeKernel{}
	s.kernel, s.kernelLife = k, kernellifecycle.New(k)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	core := "1b32d316-8cb8-4b46-8d49-e281c28d5169"
	root := t.TempDir()
	s.cfg.Authorization = config.AuthorizationConfig{
		Enabled: true, StateDir: filepath.Join(root, "state"), CoreInstanceID: core,
		KeyID: "profile-fixture", KeyEpoch: "1", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		PolicyVersion: config.NativeProviderAuthorizationPolicyVersion, MaxClockSkew: 5, RefreshInterval: 30,
		Provider: config.AuthorizationProviderConfig{Endpoint: "https://provider.example.test", ProviderID: "primary-provider", ProviderInstanceEpoch: "1", CAFile: filepath.Join(root, "ca.pem"), ClientCert: filepath.Join(root, "client.pem"), ClientKey: filepath.Join(root, "client.key")},
	}
	manager, err := authorization.NewManager(s.cfg.Authorization, authorization.Target{NodeID: 42})
	if err != nil {
		t.Fatal(err)
	}
	trust := authorization.Trust{ProtocolVersion: 1, CoreInstanceID: core, KeyID: s.cfg.Authorization.KeyID, KeyEpoch: "1", PublicKey: s.cfg.Authorization.PublicKey, Algorithm: "Ed25519"}
	if err := manager.SetTrust(trust); err != nil {
		manager.Close()
		t.Fatal(err)
	}
	s.authorization = manager
	t.Cleanup(func() { s.kernel.Stop(); s.closeAuthorization() })
	revision := 0
	sign := func(profile string, empty bool) *authorization.Snapshot {
		t.Helper()
		revision++
		now := time.Now()
		users := []panel.User{{ID: 7, UUID: "00112233-4455-4677-8899-aabbccddeeff"}}
		hash := sha256.Sum256([]byte(users[0].UUID))
		commitments := []panel.User{{ID: 7, UUID: "sha256:" + hex.EncodeToString(hash[:])}}
		subjects := []credentialdelivery.Subject{{UserID: 7, AccessSubjectID: "10", SubscriptionID: "11", TermsID: "12", ProviderSubjectRef: "subject_" + strings.Repeat("a", 32), CredentialRef: "credential_" + strings.Repeat("b", 32), CredentialGeneration: "1", CredentialExpiresAt: now.Unix() + 3600}}
		if empty {
			users, commitments, subjects = []panel.User{}, []panel.User{}, []credentialdelivery.Subject{}
		}
		p := credentialdelivery.Payload{ProtocolVersion: 1, Audience: credentialdelivery.Audience, PolicyVersion: credentialdelivery.PolicyVersion, CoreInstanceID: core, NodeID: 42, Revision: strconv.Itoa(revision), KeyID: trust.KeyID, KeyEpoch: "1", IssuedAt: now.Unix(), NotBefore: now.Unix() - 5, ExpiresAt: now.Unix() + 60, Complete: true, Users: commitments,
			Provider: credentialdelivery.ProviderBinding{InstallationID: core, ProviderID: "primary-provider", ProviderInstanceEpoch: "1", RecipientSHA256: strings.Repeat("a", 64), CredentialProfileID: profile, Subjects: subjects}}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		envelope := authorization.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
		snapshot, err := manager.Verify(envelope, users, now)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	return s, k, plane, sign
}

func TestProviderProfileMismatchCannotOpenInitialKernel(t *testing.T) {
	for _, mode := range []string{"vless_config_vmess_grant", "vmess_config_vless_grant", "missing_config", "unsupported_config", "forged_exported_profile"} {
		t.Run(mode, func(t *testing.T) {
			s, k, plane, sign := providerProfileService(t)
			profile := "vmess-uuid/v1"
			switch mode {
			case "vmess_config_vless_grant":
				plane.bootstrap.Config.Protocol = "vmess"
				profile = "vless-uuid/v1"
			case "missing_config":
				plane.bootstrap.Config = nil
			case "unsupported_config":
				plane.bootstrap.Config.Protocol = "trojan"
			}
			snapshot := sign(profile, false)
			if mode == "forged_exported_profile" {
				snapshot.Payload.Provider.CredentialProfileID = "vless-uuid/v1"
			}
			plane.bootstrap.Authorization = snapshot
			plane.bootstrap.Users = model.UserSpecsFromPanel(snapshot.Users)
			if err := s.initialSetup(context.Background()); err == nil || !strings.Contains(err.Error(), "NODE_AUTHORIZATION_PROVIDER_PROFILE_MISMATCH") {
				t.Fatal("mismatched initial protocol accepted", err)
			}
			if k.running || k.startCalls != 0 || s.authorization.Current() != nil || !s.authorization.Expiry().IsZero() {
				t.Fatal("mismatch opened kernel or persisted renewed authority")
			}
		})
	}
}

func TestProviderProfileMismatchStopsExistingKernelOnFullAndUsersOnlyRefresh(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(strconv.FormatBool(full), func(t *testing.T) {
			s, k, plane, sign := providerProfileService(t)
			initial := sign("vless-uuid/v1", false)
			users := model.UserSpecsFromPanel(initial.Users)
			s.lastConfig = plane.bootstrap.Config
			s.lastConfigHash = computeConfigHash(s.lastConfig)
			if err := s.acceptAuthorization(initial, users, s.lastConfig); err != nil {
				t.Fatal(err)
			}
			s.updateUserState(users, srcBootstrap)
			k.running = true
			deadline := s.authorization.Expiry()
			changed := sign("vmess-uuid/v1", false)
			result := nodesync.Result{Users: model.UserSpecsFromPanel(changed.Users), Authorization: changed}
			result.UserHash = computeUserHash(result.Users)
			if full {
				result.Config = plane.bootstrap.Config
			}
			s.applySyncResult(context.Background(), result)
			if s.authorizationFailure == nil || !strings.Contains(s.authorizationFailure.Error(), "NODE_AUTHORIZATION_PROVIDER_PROFILE_MISMATCH") || k.running {
				t.Fatal("profile mismatch reused current kernel", s.authorizationFailure)
			}
			if k.startCalls != 0 || k.reloadCalls != 0 || k.updateCalls != 0 || !deadline.Equal(s.authorization.Expiry()) {
				t.Fatal("mismatch applied credentials or extended the lease")
			}
			if s.startKernel(s.lastConfig, users) || k.running {
				t.Fatal("terminal profile refusal allowed kernel reuse")
			}
		})
	}
}

func TestProviderEmptySnapshotRevokesAcrossProtocolEdit(t *testing.T) {
	s, k, plane, sign := providerProfileService(t)
	initial := sign("vless-uuid/v1", false)
	users := model.UserSpecsFromPanel(initial.Users)
	s.lastConfig = plane.bootstrap.Config
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	if err := s.acceptAuthorization(initial, users, s.lastConfig); err != nil {
		t.Fatal(err)
	}
	s.updateUserState(users, srcBootstrap)
	k.running = true
	empty := sign("vmess-uuid/v1", true)
	result := nodesync.Result{Users: []model.UserSpec{}, Authorization: empty}
	result.UserHash = computeUserHash(result.Users)
	s.applySyncResult(context.Background(), result)
	if s.authorizationFailure != nil || k.running || s.users.Count() != 0 || s.authorization.Current() == nil || len(s.authorization.Current().Users) != 0 {
		t.Fatal("empty revocation blocked by prior protocol", s.authorizationFailure)
	}
}

func TestProviderRejectedReplacementConfigCannotReuseOldProtocol(t *testing.T) {
	s, k, plane, sign := providerProfileService(t)
	initial := sign("vless-uuid/v1", false)
	users := model.UserSpecsFromPanel(initial.Users)
	s.lastConfig = plane.bootstrap.Config
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	if err := s.acceptAuthorization(initial, users, s.lastConfig); err != nil {
		t.Fatal(err)
	}
	s.updateUserState(users, srcBootstrap)
	k.running = true
	// This kernel only supports VLESS. Even with unchanged UUIDs, accepting a
	// VMess grant must close its old listener before config validation fails.
	next := sign("vmess-uuid/v1", false)
	replacement := &model.NodeSpec{Protocol: "vmess", ServerPort: 12345}
	result := nodesync.Result{Config: replacement, Users: model.UserSpecsFromPanel(next.Users), Authorization: next}
	result.UserHash = computeUserHash(result.Users)
	s.applySyncResult(context.Background(), result)
	if k.running || k.startCalls != 0 || k.reloadCalls != 0 || k.updateCalls != 0 {
		t.Fatal("rejected config reused old protocol with new grant")
	}
	if s.signedUsersAllowed(users) || s.startKernel(s.lastConfig, users) {
		t.Fatal("old protocol passed the final admission check")
	}
}
