package credentialprovider

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	bolt "github.com/sagernet/bbolt"
)

// This fixture exercises protocol/store behavior on Windows without bypassing
// the production OpenStore Unix permission checks in application code.
func templateTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "template.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{metadataBucket, operationsBucket, keysBucket, subjectsBucket, subjectIDsBucket, issueEvidenceBucket, generationEvidenceBucket} {
			if _, e := tx.CreateBucketIfNotExists(name); e != nil {
				return e
			}
		}
		return tx.Bucket(metadataBucket).Put([]byte("credential_evidence_version"), []byte("1"))
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Store{db: db, providerID: "provider-a", epoch: "1"}
}

func TestClientTemplateRealMTLSValidationAndPublicSignedRender(t *testing.T) {
	fixture := makeTLSFixture(t)
	store := templateTestStore(t)
	trust, core := deliveryKey(t)
	config, err := LoadTLSConfig(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	// A distinct node certificate is TLS-admitted but is not Core-authorized.
	config.VerifyConnection = nil
	control := httptest.NewUnstartedServer(withCapabilities(http.NotFoundHandler(), store, fixture.config.ClientFingerprints, false, true))
	control.TLS = config
	control.StartTLS()
	defer control.Close()
	publicHandler, err := NewRenderHandler(store, trust)
	if err != nil {
		t.Fatal(err)
	}
	public := httptest.NewUnstartedServer(publicHandler)
	public.TLS = &tls.Config{Certificates: config.Certificates, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	public.StartTLS()
	defer public.Close()
	post := func(client *http.Client, url string, input any, status int) []byte {
		t.Helper()
		raw, _ := json.Marshal(input)
		resp, err := client.Post(url, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != status || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("status=%d wanted=%d body=%s", resp.StatusCode, status, body)
		}
		return body
	}
	source := `{"outbounds":{{json .Connections}},"custom":true}`
	digest := sha256.Sum256([]byte(source))
	hash := hex.EncodeToString(digest[:])
	input := templateValidationRequest{credentialdelivery.ClientTemplateEngine, "validate-1", "provider-a", "1", credentialdelivery.RenderSingBox, source, hash}
	body := post(fixture.client, control.URL+"/template-validate", input, 200)
	var validated struct {
		Valid    bool   `json:"valid"`
		SHA256   string `json:"sha256"`
		FormatID string `json:"format_id"`
	}
	_ = json.Unmarshal(body, &validated)
	if !validated.Valid || validated.SHA256 != hash || validated.FormatID != input.FormatID {
		t.Fatal("validation response lost source/client binding")
	}
	post(fixture.wrong, control.URL+"/template-validate", input, 403)
	if _, err := fixture.noCert.Post(control.URL+"/template-validate", "application/json", strings.NewReader("{}")); err == nil {
		t.Fatal("control endpoint accepted no client certificate")
	}
	post(fixture.noCert, public.URL+"/template-validate", input, 404)
	wrong := input
	wrong.ProviderID = "provider-b"
	post(fixture.client, control.URL+"/template-validate", wrong, 400)
	wrong = input
	wrong.Source = "malformed"
	wrong.SHA256 = hash
	post(fixture.client, control.URL+"/template-validate", wrong, 422)
	wrong = input
	wrong.Source = "{"
	badHash := sha256.Sum256([]byte(wrong.Source))
	wrong.SHA256 = hex.EncodeToString(badHash[:])
	body = post(fixture.client, control.URL+"/template-validate", wrong, 200)
	_ = json.Unmarshal(body, &validated)
	if validated.Valid {
		t.Fatal("malformed JSON template passed real node validation")
	}
	issued := execute(t, store, makeRequest(t, "issue", 1, issueInput()))
	var receipt IssueResult
	if issued.Status != "succeeded" || json.Unmarshal(issued.Result, &receipt) != nil {
		t.Fatalf("issue failed: %#v", issued)
	}
	secret := privateFor(t, store).Credential
	secretHash := sha256.Sum256([]byte(secret))
	recipient, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Unix()
	payload := credentialdelivery.RenderPayload{ProtocolVersion: 1, PolicyVersion: credentialdelivery.RenderPolicyVersion, Audience: credentialdelivery.RenderAudience, CoreInstanceID: trust.CoreInstanceID, KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch, IssuedAt: now, NotBefore: now - 1, ExpiresAt: now + 30, GrantID: "render_" + strings.Repeat("1", 32), ProviderID: "provider-a", ProviderInstanceEpoch: "1", RecipientPublicKey: base64.RawURLEncoding.EncodeToString(recipient), FormatID: credentialdelivery.RenderSingBox, ClientVersion: "1.12.0", UserID: "9", Subject: metadataRequest(receipt).Subjects[0], CredentialSHA256: hex.EncodeToString(secretHash[:]), CredentialExpiresAt: receipt.CredentialExpiresAt, Nodes: []credentialdelivery.ConnectionNode{{NodeID: "5", Name: "sample", Host: "127.0.0.1", Port: 443, Protocol: "vless", Transport: "tcp"}}, ClientTemplate: &credentialdelivery.ClientTemplate{Engine: credentialdelivery.ClientTemplateEngine, FormatID: credentialdelivery.RenderSingBox, Version: strings.Repeat("a", 64), SHA256: hash, Source: source}}
	raw, _ := json.Marshal(payload)
	grantHash := sha256.Sum256(raw)
	request := credentialdelivery.RenderRequest{ContractVersion: credentialdelivery.RenderContractVersion, RequestID: "template-render-1", Authorization: credentialdelivery.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(core, raw))}, Proof: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, credentialdelivery.RenderProofMessage("template-render-1", hex.EncodeToString(grantHash[:]))))}
	body = post(fixture.noCert, public.URL+"/subscription-render", request, 200)
	if !bytes.Contains(body, []byte(`"custom":true`)) || !bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte("credential_ref")) {
		t.Fatal("custom source was not rendered from admitted inert values")
	}
	noProof := request
	noProof.Proof = ""
	post(fixture.noCert, public.URL+"/subscription-render", noProof, 403)
	execute(t, store, makeRequest(t, "revoke", 2, revokeInput()))
	body = post(fixture.noCert, public.URL+"/subscription-render", request, 409)
	if bytes.Contains(body, []byte(secret)) {
		t.Fatal("revoked credential leaked through template")
	}
}
