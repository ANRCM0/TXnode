package providerproof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"sync"
	"testing"
)

var testKey *rsa.PrivateKey
var testTrust TrustedKey

func TestMain(m *testing.M) {
	var err error
	testKey, err = rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		panic("fixture key generation failed")
	}
	der, err := x509.MarshalPKIXPublicKey(&testKey.PublicKey)
	if err != nil {
		panic("fixture public key failed")
	}
	h := sha256.Sum256(der)
	testTrust = TrustedKey{ID: "fixture-go-key", Epoch: "1", PublicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		SPKISHA256: hex.EncodeToString(h[:]), NotBefore: 1, NotAfter: 200}
	os.Exit(m.Run())
}

// The nested objects are deliberately opaque diagnostic inputs. Only the real
// Core interoperability test below claims a fully validated business profile.
func testPayload() map[string]any {
	return map[string]any{"v": "credential-provider/local-authorization/1", "mode": "local_synthetic_authorization_snapshot",
		"iss": "txboard:local-synthetic-authority", "aud": "txboard:offline-fixture-verifier", "snapshot_ref": "asf_" + strings.Repeat("a", 32),
		"provider_id": "local_fixture", "access_subject_id": "9007199254740993", "actor_ref": "local-fixture-operator", "authorization_ref": "local-fixture-grant/v1",
		"candidate_id": "1", "candidate_ref": "lc_" + strings.Repeat("b", 32), "candidate_evidence_hash": strings.Repeat("c", 64),
		"candidate_request": map[string]any{}, "candidate_evidence": map[string]any{}, "binding_commit": map[string]any{}, "source": map[string]any{}, "policy": map[string]any{},
		"issued_at": 100, "lease_expires_at": 150, "key_epoch": "1", "key_spki_sha256": testTrust.SPKISHA256,
		"key_not_before": 1, "key_not_after": 200, "admission_granted": false, "delivery_status": "not_implemented", "node_convergence": "not_implemented"}
}

func testHeader() map[string]any {
	return map[string]any{"alg": "RS256", "typ": "txboard-fixture-authorization+jws", "kid": testTrust.ID}
}

func signRaw(t *testing.T, header, payload []byte) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, testKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal("fixture signature failed")
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func sign(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(t, h, p)
}

func verifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := New([]TrustedKey{testTrust})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSignatureEvidenceNeverGrantsAdmission(t *testing.T) {
	token := sign(t, testHeader(), testPayload())
	proof, err := verifier(t).VerifySignature(token)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.SignatureVerified || proof.AdmissionGranted || proof.BusinessEvidenceValidation != "not_evaluated" ||
		proof.LiveCoreEligibility != "not_evaluated" || proof.WindowValidation != "not_evaluated" || proof.KeyRevoked {
		t.Fatal("invalid diagnostic scope")
	}
	if proof.IssuedAt != 100 || proof.LeaseExpiresAt != 150 || proof.KeyID != testTrust.ID || proof.KeyEpoch != "1" {
		t.Fatal("metadata changed")
	}
	h := sha256.Sum256([]byte(token))
	if proof.SignedStatementSHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("signed bytes changed")
	}
	raw, _ := json.Marshal(proof)
	for _, forbidden := range []string{"candidate_evidence", "provider_subject_ref", "credential_ref", "public_pem", "PRIVATE KEY", token} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("diagnostic exposed material")
		}
	}
}

func TestHistoricalRevokedKeySignatureIsExplicitlyNonAuthorizing(t *testing.T) {
	meta := testTrust
	meta.Revoked = true
	v, err := New([]TrustedKey{meta})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := v.VerifySignature(sign(t, testHeader(), testPayload()))
	if err != nil || !proof.KeyRevoked || proof.AdmissionGranted || proof.WindowValidation != "not_evaluated" {
		t.Fatal("history was treated as admission")
	}
}

func TestClosedProfileAndDomainConfusion(t *testing.T) {
	cases := map[string]func(map[string]any, map[string]any){
		"algorithm-none":    func(h, p map[string]any) { h["alg"] = "none" },
		"algorithm-hmac":    func(h, p map[string]any) { h["alg"] = "HS256" },
		"wrong-type":        func(h, p map[string]any) { h["typ"] = "JWT" },
		"unknown-key":       func(h, p map[string]any) { h["kid"] = "unknown" },
		"header-jwk":        func(h, p map[string]any) { h["jwk"] = map[string]any{} },
		"header-url":        func(h, p map[string]any) { h["jku"] = "https://example.test/key" },
		"issuer":            func(h, p map[string]any) { p["iss"] = "other" },
		"audience":          func(h, p map[string]any) { p["aud"] = "txboard:node" },
		"profile":           func(h, p map[string]any) { p["v"] = "credential-provider/production/1" },
		"admission":         func(h, p map[string]any) { p["admission_granted"] = true },
		"delivery":          func(h, p map[string]any) { p["delivery_status"] = "complete" },
		"convergence":       func(h, p map[string]any) { p["node_convergence"] = "applied" },
		"extra-claim":       func(h, p map[string]any) { p["exp"] = 150 },
		"missing-claim":     func(h, p map[string]any) { delete(p, "source") },
		"float-id":          func(h, p map[string]any) { p["access_subject_id"] = 1 },
		"leading-zero-id":   func(h, p map[string]any) { p["candidate_id"] = "01" },
		"overflow-id":       func(h, p map[string]any) { p["candidate_id"] = "9223372036854775808" },
		"unknown-actor":     func(h, p map[string]any) { p["actor_ref"] = "remote-operator" },
		"bad-evidence-hash": func(h, p map[string]any) { p["candidate_evidence_hash"] = nil },
		"null-evidence":     func(h, p map[string]any) { p["candidate_evidence"] = nil },
		"array-evidence":    func(h, p map[string]any) { p["source"] = []any{} },
		"epoch":             func(h, p map[string]any) { p["key_epoch"] = "2" },
		"spki":              func(h, p map[string]any) { p["key_spki_sha256"] = strings.Repeat("0", 64) },
		"key-before":        func(h, p map[string]any) { p["key_not_before"] = 2 },
		"key-after":         func(h, p map[string]any) { p["key_not_after"] = 201 },
		"time-string":       func(h, p map[string]any) { p["issued_at"] = "100" },
		"time-fraction":     func(h, p map[string]any) { p["issued_at"] = 100.1 },
		"time-negative":     func(h, p map[string]any) { p["issued_at"] = -1 },
		"empty-window":      func(h, p map[string]any) { p["lease_expires_at"] = 100 },
		"long-window":       func(h, p map[string]any) { p["lease_expires_at"] = 161 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			h, p := testHeader(), testPayload()
			change(h, p)
			if proof, err := verifier(t).VerifySignature(sign(t, h, p)); err != ErrInvalidProof || proof.SignatureVerified {
				t.Fatal("accepted invalid profile")
			}
		})
	}
}

func TestTamperingAndNoncanonicalCompactEncoding(t *testing.T) {
	token := sign(t, testHeader(), testPayload())
	parts := strings.Split(token, ".")
	payload, _ := json.Marshal(testPayload())
	changed := strings.Replace(string(payload), `"issued_at":100`, `"issued_at":101`, 1)
	badSignature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	badSignature[0] ^= 1
	cases := []string{"", token + "=", strings.Repeat("a", maxBytes+1), strings.Join(parts[:2], "."), token + ".x",
		parts[0] + "=." + parts[1] + "." + parts[2], parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(changed)) + "." + parts[2],
		parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(badSignature), parts[0] + "." + parts[1] + ".AA"}
	for i, token := range cases {
		if _, err := verifier(t).VerifySignature(token); err != ErrInvalidProof {
			t.Fatalf("accepted malformed compact case %d", i)
		}
	}
}

func TestDuplicateKeysInvalidUnicodeAndDepthAreRefusedBeforeSignatureSuccess(t *testing.T) {
	header, _ := json.Marshal(testHeader())
	payload, _ := json.Marshal(testPayload())
	cases := [][]byte{
		[]byte(strings.Replace(string(payload), `"source":{}`, `"source":{"x":1,"x":2}`, 1)),
		[]byte(strings.Replace(string(payload), `"source":{}`, `"source":{"x":1,"\u0078":2}`, 1)),
		[]byte(strings.Replace(string(payload), `"source":{}`, `"source":{"x":"\ud800"}`, 1)),
		[]byte(strings.Replace(string(payload), `"source":{}`, `"source":{"x":`+strings.Repeat("[", 34)+"0"+strings.Repeat("]", 34)+"}", 1)),
		append(append([]byte{}, payload...), []byte(` {}`)...),
	}
	for i, raw := range cases {
		if _, err := verifier(t).VerifySignature(signRaw(t, header, raw)); err != ErrInvalidProof {
			t.Fatalf("accepted malformed JSON %d", i)
		}
	}
	duplicateHeader := []byte(`{"alg":"RS256","alg":"RS256","typ":"txboard-fixture-authorization+jws","kid":"fixture-go-key"}`)
	if _, err := verifier(t).VerifySignature(signRaw(t, duplicateHeader, payload)); err != ErrInvalidProof {
		t.Fatal("accepted duplicate header")
	}
	if _, err := object([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}); err != ErrInvalidProof {
		t.Fatal("accepted invalid UTF8")
	}
}

func TestTrustBoundsTypesDigestsAndDuplicateIDs(t *testing.T) {
	if _, err := New(nil); err != ErrInvalidProof {
		t.Fatal("empty trust")
	}
	if _, err := New([]TrustedKey{testTrust, testTrust}); err != ErrInvalidProof {
		t.Fatal("duplicate key")
	}
	if _, err := New([]TrustedKey{testTrust, testTrust, testTrust}); err != ErrInvalidProof {
		t.Fatal("unbounded trust")
	}
	for _, change := range []func(*TrustedKey){
		func(k *TrustedKey) { k.Epoch = "01" }, func(k *TrustedKey) { k.ID = "../key" },
		func(k *TrustedKey) { k.SPKISHA256 = strings.Repeat("0", 64) }, func(k *TrustedKey) { k.NotAfter = k.NotBefore },
		func(k *TrustedKey) { k.PublicPEM += "extra" }, func(k *TrustedKey) { k.PublicPEM = strings.Repeat("x", 8193) },
	} {
		k := testTrust
		change(&k)
		if _, err := New([]TrustedKey{k}); err != ErrInvalidProof {
			t.Fatal("accepted invalid trust")
		}
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	hash := sha256.Sum256(der)
	k := testTrust
	k.PublicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	k.SPKISHA256 = hex.EncodeToString(hash[:])
	if _, err := New([]TrustedKey{k}); err != ErrInvalidProof {
		t.Fatal("accepted alternate key type")
	}
	short, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ = x509.MarshalPKIXPublicKey(&short.PublicKey)
	hash = sha256.Sum256(der)
	k.PublicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	k.SPKISHA256 = hex.EncodeToString(hash[:])
	if _, err := New([]TrustedKey{k}); err != ErrInvalidProof {
		t.Fatal("accepted alternate RSA size")
	}
}

func TestConcurrentImmutableTrustAndPredecessorVerification(t *testing.T) {
	predecessor := testTrust
	predecessor.ID = "old-fixture-key"
	predecessor.Epoch = "2"
	keys := []TrustedKey{testTrust, predecessor}
	v, err := New(keys)
	if err != nil {
		t.Fatal(err)
	}
	keys[0].Revoked = true
	keys[0].PublicPEM = "changed after construction"
	token := sign(t, testHeader(), testPayload())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				p, err := v.VerifySignature(token)
				if err != nil || p.KeyRevoked || p.AdmissionGranted {
					t.Error("mutable verifier trust")
				}
			}
		}()
	}
	wg.Wait()
	h, p := testHeader(), testPayload()
	h["kid"] = predecessor.ID
	p["key_epoch"] = predecessor.Epoch
	if proof, err := v.VerifySignature(sign(t, h, p)); err != nil || proof.KeyID != predecessor.ID {
		t.Fatal("predecessor failed")
	}
}

func TestCoreFixtureInterop(t *testing.T) {
	path := os.Getenv("TXBOARD_PROVIDER_PROOF_FIXTURE")
	if path == "" {
		t.Skip("Requires opt-in actual Core public-only fixture")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 32768 {
		t.Fatal("fixture unavailable")
	}
	var fixture struct {
		Version  string       `json:"version"`
		Keys     []TrustedKey `json:"trusted_keys"`
		Token    string       `json:"token"`
		Expected struct {
			SnapshotRef   string `json:"snapshot_ref"`
			PayloadSHA256 string `json:"payload_sha256"`
			SignedSHA256  string `json:"signed_statement_sha256"`
			IssuedAt      int64  `json:"issued_at"`
			ExpiresAt     int64  `json:"lease_expires_at"`
		} `json:"expected"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&fixture) != nil || fixture.Version != "node-offline-signature-fixture/1" {
		t.Fatal("invalid public fixture")
	}
	v, err := New(fixture.Keys)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := v.VerifySignature(fixture.Token)
	if err != nil || !proof.SignatureVerified || proof.AdmissionGranted || proof.SnapshotRef != fixture.Expected.SnapshotRef ||
		proof.PayloadSHA256 != fixture.Expected.PayloadSHA256 || proof.SignedStatementSHA256 != fixture.Expected.SignedSHA256 ||
		proof.IssuedAt != fixture.Expected.IssuedAt || proof.LeaseExpiresAt != fixture.Expected.ExpiresAt ||
		proof.BusinessEvidenceValidation != "not_evaluated" || proof.LiveCoreEligibility != "not_evaluated" || proof.WindowValidation != "not_evaluated" {
		t.Fatal("actual Core signed proof did not match independent Go diagnostic")
	}
}
