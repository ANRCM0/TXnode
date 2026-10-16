package authorization

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

var materialUUIDRE = regexp.MustCompile(`\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z`)

// ValidateProtocol checks an already verified snapshot. Empty cohorts remove
// all credentials and must remain applicable across a concurrent protocol edit.
func ValidateProtocol(snapshot *Snapshot, protocol string) error {
	if snapshot == nil {
		return refuse("SNAPSHOT_REQUIRED")
	}
	if snapshot.Payload.PolicyVersion != config.NativeProviderAuthorizationPolicyVersion {
		return nil
	}
	if snapshot.Payload.Provider == nil {
		return refuse("PROVIDER_PROFILE_MISMATCH")
	}
	if len(snapshot.Users) == 0 {
		return nil
	}
	expected := ""
	switch snapshot.Payload.Provider.CredentialProfileID {
	case "vless-uuid/v1":
		expected = "vless"
	case "vmess-uuid/v1":
		expected = "vmess"
	}
	if expected == "" || protocol != expected {
		return refuse("PROVIDER_PROFILE_MISMATCH")
	}
	return nil
}

// VerifyProviderGrant checks metadata without creating an applicable Snapshot.
// In particular, a stale revision cannot cause material retrieval before the
// durable high-water and the Machine child target have been checked.
func (m *Manager) VerifyProviderGrant(env Envelope, users []panel.User, now time.Time) (*credentialdelivery.Grant, error) {
	if m.cfg.PolicyVersion != config.NativeProviderAuthorizationPolicyVersion {
		return nil, refuse("PROVIDER_POLICY_REQUIRED")
	}
	m.mu.Lock()
	trust := m.trust
	m.mu.Unlock()
	grant, err := verifyProviderGrant(env, trust, m.target, now, m.cfg.MaxClockSkew)
	if err != nil {
		return nil, err
	}
	if !sameUsers(grant.Payload.Users, users) {
		return nil, refuse("USERS_MISMATCH")
	}
	if err := m.checkProviderBinding(&grant.Payload.Provider); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkHighWater(&Snapshot{Payload: providerPayload(grant.Payload), Digest: grant.Digest}, now, false); err != nil {
		return nil, err
	}
	return grant, nil
}

func (m *Manager) checkProviderBinding(binding *credentialdelivery.ProviderBinding) error {
	if m.cfg.PolicyVersion != config.NativeProviderAuthorizationPolicyVersion {
		if binding != nil {
			return refuse("PROVIDER_POLICY_REQUIRED")
		}
		return nil
	}
	if binding == nil || binding.ProviderID != m.cfg.Provider.ProviderID || binding.ProviderInstanceEpoch != m.cfg.Provider.ProviderInstanceEpoch {
		return refuse("PROVIDER_BINDING_MISMATCH")
	}
	return nil
}

func verifyProviderGrant(env Envelope, trust Trust, target Target, now time.Time, skew int) (*credentialdelivery.Grant, error) {
	grant, err := credentialdelivery.VerifyGrant(credentialdelivery.Envelope{Payload: env.Payload, Signature: env.Signature}, credentialdelivery.Trust{
		ProtocolVersion: trust.ProtocolVersion, CoreInstanceID: trust.CoreInstanceID, KeyID: trust.KeyID,
		KeyEpoch: trust.KeyEpoch, Algorithm: trust.Algorithm, PublicKey: trust.PublicKey,
	}, now, skew)
	if err != nil {
		return nil, refuse("PROVIDER_GRANT_INVALID")
	}
	if target.NodeID <= 0 || grant.Payload.NodeID != target.NodeID || !sameMachine(grant.Payload.MachineID, target.MachineID) {
		return nil, refuse("TARGET_MISMATCH")
	}
	return grant, nil
}

func verifyProviderSnapshot(env Envelope, users []panel.User, trust Trust, target Target, now time.Time, skew int) (*Snapshot, error) {
	grant, err := verifyProviderGrant(env, trust, target, now, skew)
	if err != nil {
		return nil, err
	}
	if users == nil || len(users) != len(grant.Payload.Users) {
		return nil, refuse("USERS_MISMATCH")
	}
	committed := cloneUsers(users)
	for i := range committed {
		if !materialUUIDRE.MatchString(committed[i].UUID) {
			return nil, refuse("PROVIDER_MATERIAL_INVALID")
		}
		hash := sha256.Sum256([]byte(committed[i].UUID))
		committed[i].UUID = "sha256:" + hex.EncodeToString(hash[:])
	}
	if !sameUsers(grant.Payload.Users, committed) {
		return nil, refuse("USERS_MISMATCH")
	}
	return &Snapshot{Payload: providerPayload(grant.Payload), Users: cloneUsers(users), PayloadBytes: append([]byte(nil), grant.PayloadBytes...), Digest: grant.Digest, envelope: env}, nil
}

func sameUsers(a, b []panel.User) bool {
	if a == nil || b == nil {
		return false
	}
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

func providerPayload(p credentialdelivery.Payload) Payload {
	provider := p.Provider
	provider.Subjects = append([]credentialdelivery.Subject{}, provider.Subjects...)
	return Payload{
		ProtocolVersion: p.ProtocolVersion, Audience: p.Audience, PolicyVersion: p.PolicyVersion,
		CoreInstanceID: p.CoreInstanceID, NodeID: p.NodeID, MachineID: cloneInt(p.MachineID),
		Revision: p.Revision, KeyID: p.KeyID, KeyEpoch: p.KeyEpoch, IssuedAt: p.IssuedAt,
		NotBefore: p.NotBefore, ExpiresAt: p.ExpiresAt, Complete: p.Complete,
		Users: cloneUsers(p.Users), Provider: &provider,
	}
}
