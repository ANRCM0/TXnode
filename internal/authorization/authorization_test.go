package authorization

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

func signedFixture(t *testing.T) (Payload, Trust, ed25519.PrivateKey, time.Time) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	now := time.Unix(1800000000, 500000000)
	trust := Trust{ProtocolVersion: 1, CoreInstanceID: "core-fixture-authorization", KeyID: "native-key-1", KeyEpoch: "1", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	p := Payload{ProtocolVersion: 1, Audience: Audience, PolicyVersion: config.NativeAuthorizationPolicyVersion, CoreInstanceID: trust.CoreInstanceID, NodeID: 42, Revision: "5", KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch, IssuedAt: now.Unix(), NotBefore: now.Unix() - 5, ExpiresAt: now.Unix() + 120, Complete: true, Users: []panel.User{{ID: 7, UUID: "00112233-4455-6677-8899-aabbccddeeff", TrafficPeriod: "opaque-period-7"}, {ID: 8, UUID: "10112233-4455-6677-8899-aabbccddeeff"}}}
	return p, trust, key, now
}
func signPayload(t *testing.T, p Payload, key ed25519.PrivateKey) Envelope {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(raw, key)
}
func signRaw(raw []byte, key ed25519.PrivateKey) Envelope {
	return Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
}
func TestVerifySignedCompleteTargetAndEmptySnapshot(t *testing.T) {
	p, trust, key, now := signedFixture(t)
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprint(empty), func(t *testing.T) {
			candidate := p
			if empty {
				candidate.Users = []panel.User{}
			}
			snap, err := Verify(signPayload(t, candidate, key), candidate.Users, trust, Target{NodeID: 42}, p.PolicyVersion, now, 5)
			if err != nil {
				t.Fatal(err)
			}
			if snap.Users == nil || len(snap.Users) != len(candidate.Users) || snap.Digest == "" {
				t.Fatal("complete snapshot missing")
			}
		})
	}
	machine := 9
	p.MachineID = &machine
	if _, err := Verify(signPayload(t, p, key), p.Users, trust, Target{NodeID: 42, MachineID: &machine}, p.PolicyVersion, now, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signPayload(t, p, key), p.Users, trust, Target{NodeID: 42}, p.PolicyVersion, now, 5); !IsRefusal(err) {
		t.Fatal("machine grant transferred to standalone")
	}
	sibling := 43
	if _, err := Verify(signPayload(t, p, key), p.Users, trust, Target{NodeID: sibling, MachineID: &machine}, p.PolicyVersion, now, 5); !IsRefusal(err) {
		t.Fatal("machine grant transferred to sibling")
	}
}
func TestVerifyRefusesMalformedInvalidBoundariesAndUsers(t *testing.T) {
	cases := map[string]func(*Payload){
		"audience": func(p *Payload) { p.Audience = "wrong" }, "policy": func(p *Payload) { p.PolicyVersion = "wrong" }, "core": func(p *Payload) { p.CoreInstanceID = "other-core" }, "node": func(p *Payload) { p.NodeID++ }, "key": func(p *Payload) { p.KeyID = "other-key" }, "epoch": func(p *Payload) { p.KeyEpoch = "0" }, "revision": func(p *Payload) { p.Revision = "05" }, "overflow": func(p *Payload) { p.Revision = "9999999999999999999" }, "incomplete": func(p *Payload) { p.Complete = false }, "missing_users": func(p *Payload) { p.Users = nil }, "past": func(p *Payload) { p.ExpiresAt = p.IssuedAt }, "long": func(p *Payload) { p.ExpiresAt = p.IssuedAt + 121 }, "future": func(p *Payload) { p.IssuedAt += 6; p.NotBefore += 6; p.ExpiresAt += 6 }, "not_before": func(p *Payload) { p.NotBefore = p.IssuedAt + 1 }, "wide_skew": func(p *Payload) { p.NotBefore = p.IssuedAt - 6 }, "negative_time": func(p *Payload) { p.NotBefore = -1 }, "duplicate_id": func(p *Payload) { p.Users[1].ID = p.Users[0].ID }, "unordered": func(p *Payload) { p.Users[0], p.Users[1] = p.Users[1], p.Users[0] }, "duplicate_uuid": func(p *Payload) { p.Users[1].UUID = p.Users[0].UUID }, "empty_uuid": func(p *Payload) { p.Users[0].UUID = "" }, "uuid_limit": func(p *Payload) { p.Users[0].UUID = strings.Repeat("x", 256) }, "negative_limit": func(p *Payload) { p.Users[0].DeviceLimit = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, trust, key, now := signedFixture(t)
			mutate(&p)
			_, err := Verify(signPayload(t, p, key), p.Users, trust, Target{NodeID: 42}, config.NativeAuthorizationPolicyVersion, now, 5)
			if !IsRefusal(err) {
				t.Fatal("invalid signed snapshot accepted", err)
			}
		})
	}
}
func TestVerifyStrictSignedJSONAndSignature(t *testing.T) {
	p, trust, key, now := signedFixture(t)
	raw, _ := json.Marshal(p)
	cases := map[string]Envelope{
		"tampered":     signPayload(t, p, key),
		"duplicate":    signRaw([]byte(strings.Replace(string(raw), `"node_id":42`, `"node_id":42,"node_id":42`, 1)), key),
		"unknown":      signRaw([]byte(strings.TrimSuffix(string(raw), "}")+`,"unexpected":1}`), key),
		"unknown_user": signRaw([]byte(strings.Replace(string(raw), `"id":7`, `"id":7,"secret_extra":1`, 1)), key),
		"extra_value":  signRaw(append(raw, []byte(` {}`)...), key),
		"invalid_utf8": signRaw(append(raw, 0xff), key),
		"padded":       {Payload: base64.URLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))},
	}
	env := cases["tampered"]
	env.Signature = strings.Repeat("A", 86)
	cases["tampered"] = env
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(env, p.Users, trust, Target{NodeID: 42}, p.PolicyVersion, now, 5); !IsRefusal(err) {
				t.Fatal("malformed envelope accepted", err)
			}
		})
	}
	changed := cloneUsers(p.Users)
	changed[0].TrafficPeriod = "different-period"
	if _, err := Verify(signPayload(t, p, key), changed, trust, Target{NodeID: 42}, p.PolicyVersion, now, 5); !IsRefusal(err) {
		t.Fatal("unsigned outer users substituted")
	}
}
