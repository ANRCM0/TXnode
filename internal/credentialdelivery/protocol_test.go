package credentialdelivery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/panel"
)

func grantFixture(t *testing.T) (Payload, Trust, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	instance := "11111111-1111-4111-8111-111111111111"
	trust := Trust{1, instance, "core-signing", "1", "Ed25519", base64.RawURLEncoding.EncodeToString(public)}
	p := Payload{
		ProtocolVersion: 1, Audience: Audience, PolicyVersion: PolicyVersion,
		CoreInstanceID: instance, NodeID: 7, Revision: "3", KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch,
		IssuedAt: now, NotBefore: now, ExpiresAt: now + 60, Complete: true,
		Users: []panel.User{{ID: 20, UUID: "sha256:" + strings.Repeat("a", 64), SpeedLimit: 1}},
		Provider: ProviderBinding{
			InstallationID: instance, ProviderID: "provider-a", ProviderInstanceEpoch: "1",
			RecipientSHA256: strings.Repeat("b", 64), CredentialProfileID: "vless-uuid/v1",
			Subjects: []Subject{{
				UserID: 20, AccessSubjectID: "11", SubscriptionID: "12", TermsID: "13",
				ProviderSubjectRef:   "subject_" + strings.Repeat("1", 32),
				CredentialRef:        "credential_" + strings.Repeat("2", 32),
				CredentialGeneration: "1", CredentialExpiresAt: now + 3600,
			}},
		},
	}
	return p, trust, private
}

func signRaw(raw []byte, private ed25519.PrivateKey) Envelope {
	return Envelope{
		Payload:   base64.RawURLEncoding.EncodeToString(raw),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, raw)),
	}
}

func TestVerifyGrantBindsExactSignedBytesAndEmptySnapshot(t *testing.T) {
	p, trust, key := grantFixture(t)
	raw, _ := json.Marshal(p)
	envelope := signRaw(raw, key)
	grant, err := VerifyGrant(envelope, trust, time.Now(), 0)
	hash := sha256.Sum256(raw)
	if err != nil || grant.Digest != hex.EncodeToString(hash[:]) || !bytes.Equal(raw, grant.PayloadBytes) {
		t.Fatalf("valid grant rejected: %v", err)
	}
	p.Users, p.Provider.Subjects = []panel.User{}, []Subject{}
	raw, _ = json.Marshal(p)
	if grant, err = VerifyGrant(signRaw(raw, key), trust, time.Now(), 0); err != nil || len(grant.Payload.Users) != 0 {
		t.Fatal("complete empty snapshot rejected")
	}
}

func TestVerifyGrantRejectsMalformedOrUnboundAuthorization(t *testing.T) {
	for name, change := range map[string]func(*Payload){
		"legacy policy":                 func(p *Payload) { p.PolicyVersion = "native-node-authorization/v1" },
		"other audience":                func(p *Payload) { p.Audience = "other" },
		"other core":                    func(p *Payload) { p.CoreInstanceID = "22222222-2222-4222-8222-222222222222" },
		"other key":                     func(p *Payload) { p.KeyID = "other" },
		"key epoch":                     func(p *Payload) { p.KeyEpoch = "2" },
		"leading zero revision":         func(p *Payload) { p.Revision = "03" },
		"revision overflow":             func(p *Payload) { p.Revision = "9223372036854775808" },
		"zero target":                   func(p *Payload) { p.NodeID = 0 },
		"invalid machine":               func(p *Payload) { n := 0; p.MachineID = &n },
		"incomplete":                    func(p *Payload) { p.Complete = false },
		"null users":                    func(p *Payload) { p.Users = nil },
		"null subjects":                 func(p *Payload) { p.Provider.Subjects = nil },
		"missing correspondence":        func(p *Payload) { p.Provider.Subjects = []Subject{} },
		"expired":                       func(p *Payload) { p.ExpiresAt = p.IssuedAt },
		"long lease":                    func(p *Payload) { p.ExpiresAt = p.IssuedAt + 121 },
		"future issue":                  func(p *Payload) { p.IssuedAt += 40; p.NotBefore += 40; p.ExpiresAt += 40 },
		"old not before":                func(p *Payload) { p.NotBefore-- },
		"wrong installation":            func(p *Payload) { p.Provider.InstallationID = "22222222-2222-4222-8222-222222222222" },
		"provider epoch":                func(p *Payload) { p.Provider.ProviderInstanceEpoch = "01" },
		"bad recipient":                 func(p *Payload) { p.Provider.RecipientSHA256 = strings.Repeat("A", 64) },
		"unsupported profile":           func(p *Payload) { p.Provider.CredentialProfileID = "password/v1" },
		"raw uuid":                      func(p *Payload) { p.Users[0].UUID = "11111111-1111-4111-8111-111111111111" },
		"negative limit":                func(p *Payload) { p.Users[0].SpeedLimit = -1 },
		"subject user mismatch":         func(p *Payload) { p.Provider.Subjects[0].UserID++ },
		"invalid subject id":            func(p *Payload) { p.Provider.Subjects[0].AccessSubjectID = "011" },
		"credential shorter than grant": func(p *Payload) { p.Provider.Subjects[0].CredentialExpiresAt = p.ExpiresAt - 1 },
		"duplicate subject": func(p *Payload) {
			p.Users = append(p.Users, panel.User{ID: 21, UUID: "sha256:" + strings.Repeat("c", 64)})
			p.Provider.Subjects = append(p.Provider.Subjects, p.Provider.Subjects[0])
			p.Provider.Subjects[1].UserID = 21
		},
		"duplicate commitment": func(p *Payload) {
			p.Users = append(p.Users, panel.User{ID: 21, UUID: p.Users[0].UUID})
			s := p.Provider.Subjects[0]
			s.UserID, s.AccessSubjectID = 21, "14"
			s.ProviderSubjectRef, s.CredentialRef = "subject_"+strings.Repeat("3", 32), "credential_"+strings.Repeat("4", 32)
			p.Provider.Subjects = append(p.Provider.Subjects, s)
		},
		"too many subjects": func(p *Payload) { p.Users = make([]panel.User, MaxSubjects+1) },
	} {
		t.Run(name, func(t *testing.T) {
			p, trust, key := grantFixture(t)
			change(&p)
			raw, _ := json.Marshal(p)
			if _, err := VerifyGrant(signRaw(raw, key), trust, time.Now(), 0); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
	p, trust, key := grantFixture(t)
	valid, _ := json.Marshal(p)
	for name, raw := range map[string][]byte{
		"duplicate":          bytes.Replace(valid, []byte(`"node_id":7`), []byte(`"node_id":7,"node_id":7`), 1),
		"escaped duplicate":  bytes.Replace(valid, []byte(`"node_id":7`), []byte(`"node_id":7,"node_\u0069d":7`), 1),
		"case alias":         bytes.Replace(valid, []byte(`"node_id"`), []byte(`"Node_ID"`), 1),
		"missing user limit": bytes.Replace(valid, []byte(`,"device_limit":0`), nil, 1),
		"unknown user field": bytes.Replace(valid, []byte(`"device_limit":0`), []byte(`"device_limit":0,"secret":"x"`), 1),
		"number exponent":    bytes.Replace(valid, []byte(`"node_id":7`), []byte(`"node_id":7e0`), 1),
		"negative zero":      bytes.Replace(valid, []byte(`"device_limit":0`), []byte(`"device_limit":-0`), 1),
		"trailing object":    append(append([]byte{}, valid...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyGrant(signRaw(raw, key), trust, time.Now(), 0); err == nil {
				t.Fatal("invalid closed JSON accepted")
			}
		})
	}
	envelope := signRaw(valid, key)
	envelope.Signature = strings.Repeat("A", 86)
	if _, err := VerifyGrant(envelope, trust, time.Now(), 0); err == nil {
		t.Fatal("invalid signature accepted")
	}
	envelope = signRaw(valid, key)
	envelope.Payload += "="
	if _, err := VerifyGrant(envelope, trust, time.Now(), 0); err == nil {
		t.Fatal("noncanonical base64 accepted")
	}
}

func TestStrictMaterialDTOAndTrust(t *testing.T) {
	for _, raw := range []string{
		`{"contract_version":"credential-delivery/1","request_id":"a"}`,
		`{"contract_version":"credential-delivery/1","request_id":"a","authorization":null}`,
		`{"contract_version":"credential-delivery/1","request_id":"a","authorization":{"payload":"a","signature":"b","secret":"x"}}`,
	} {
		var req MaterialRequest
		if DecodeStrict([]byte(raw), &req) == nil {
			t.Fatal("missing or extra authorization fields accepted")
		}
	}
	_, trust, _ := grantFixture(t)
	for _, invalid := range []Trust{
		{1, trust.CoreInstanceID, trust.KeyID, "0", "Ed25519", trust.PublicKey},
		{1, trust.CoreInstanceID, trust.KeyID, "1", "RSA", trust.PublicKey},
		{1, trust.CoreInstanceID, trust.KeyID, "1", "Ed25519", "bad"},
	} {
		if ValidateTrust(invalid) == nil {
			t.Fatal("invalid trust accepted")
		}
	}
}
