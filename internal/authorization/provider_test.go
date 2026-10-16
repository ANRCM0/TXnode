package authorization

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

func providerFixture(t *testing.T) (credentialdelivery.Payload, Trust, ed25519.PrivateKey, []panel.User, time.Time) {
	t.Helper()
	now := time.Unix(1800000000, 500000000)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	trust := Trust{ProtocolVersion: 1, CoreInstanceID: "1b32d316-8cb8-4b46-8d49-e281c28d5169", KeyID: "native-key", KeyEpoch: "1", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	users := []panel.User{{ID: 7, UUID: "00112233-4455-4677-8899-aabbccddeeff", SpeedLimit: 23, DeviceLimit: 2, TrafficPeriod: "period-7"}}
	hash := sha256.Sum256([]byte(users[0].UUID))
	commitments := cloneUsers(users)
	commitments[0].UUID = "sha256:" + hex.EncodeToString(hash[:])
	machine := 9
	p := credentialdelivery.Payload{
		ProtocolVersion: 1, Audience: Audience, PolicyVersion: config.NativeProviderAuthorizationPolicyVersion,
		CoreInstanceID: trust.CoreInstanceID, NodeID: 42, MachineID: &machine, Revision: "5",
		KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch, IssuedAt: now.Unix(), NotBefore: now.Unix() - 5, ExpiresAt: now.Unix() + 120, Complete: true, Users: commitments,
		Provider: credentialdelivery.ProviderBinding{
			InstallationID: trust.CoreInstanceID, ProviderID: "primary-provider", ProviderInstanceEpoch: "1",
			RecipientSHA256: strings.Repeat("a", 64), CredentialProfileID: "vless-uuid/v1",
			Subjects: []credentialdelivery.Subject{{UserID: 7, AccessSubjectID: "10", SubscriptionID: "11", TermsID: "12", ProviderSubjectRef: "subject_" + strings.Repeat("a", 32), CredentialRef: "credential_" + strings.Repeat("b", 32), CredentialGeneration: "1", CredentialExpiresAt: now.Unix() + 3600}},
		},
	}
	return p, trust, key, users, now
}

func signProvider(t *testing.T, p credentialdelivery.Payload, key ed25519.PrivateKey) Envelope {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(raw, key)
}

func TestProviderSnapshotRequiresMaterialCommitmentAndPreservesSignedPolicy(t *testing.T) {
	p, trust, key, users, now := providerFixture(t)
	env := signProvider(t, p, key)
	target := Target{NodeID: p.NodeID, MachineID: p.MachineID}
	snapshot, err := Verify(env, users, trust, target, p.PolicyVersion, now, 5)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Users[0].UUID != users[0].UUID || snapshot.Payload.Users[0].UUID != p.Users[0].UUID || strings.Contains(string(snapshot.PayloadBytes), users[0].UUID) || snapshot.Payload.Provider == nil {
		t.Fatal("secret material entered signed metadata or policy disappeared")
	}
	for _, name := range []string{"placeholder", "uuid", "non_v4", "speed", "device", "period", "owner", "missing"} {
		t.Run(name, func(t *testing.T) {
			outer := cloneUsers(users)
			switch name {
			case "placeholder":
				outer = cloneUsers(p.Users)
			case "uuid":
				outer[0].UUID = "10112233-4455-4677-8899-aabbccddeeff"
			case "non_v4":
				outer[0].UUID = "00112233-4455-6677-8899-aabbccddeeff"
			case "speed":
				outer[0].SpeedLimit++
			case "device":
				outer[0].DeviceLimit++
			case "period":
				outer[0].TrafficPeriod = "other"
			case "owner":
				outer[0].ID++
			case "missing":
				outer = nil
			}
			if _, err := Verify(env, outer, trust, target, p.PolicyVersion, now, 5); !IsRefusal(err) {
				t.Fatal("uncommitted runtime policy accepted", err)
			}
		})
	}
	if _, err := Verify(env, users, trust, target, config.NativeAuthorizationPolicyVersion, now, 5); !IsRefusal(err) {
		t.Fatal("Provider grant crossed policy boundary")
	}
	for _, target := range []Target{{NodeID: 43, MachineID: p.MachineID}, {NodeID: 42}, {NodeID: 42, MachineID: new(int)}} {
		if _, err := Verify(env, users, trust, target, p.PolicyVersion, now, 5); !IsRefusal(err) {
			t.Fatal("Provider grant transferred to a different Machine child")
		}
	}
	p.Users = []panel.User{}
	p.Provider.Subjects = []credentialdelivery.Subject{}
	if _, err := Verify(signProvider(t, p, key), []panel.User{}, trust, Target{NodeID: p.NodeID, MachineID: p.MachineID}, p.PolicyVersion, now, 5); err != nil {
		t.Fatal("complete empty snapshot rejected", err)
	}
}
