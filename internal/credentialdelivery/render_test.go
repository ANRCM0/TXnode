package credentialdelivery

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func renderFixture(t *testing.T) (RenderPayload, Trust, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	node, trust, core := grantFixture(t)
	public, client, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := RenderPayload{ProtocolVersion: 1, PolicyVersion: RenderPolicyVersion, Audience: RenderAudience,
		CoreInstanceID: trust.CoreInstanceID, KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch,
		IssuedAt: node.IssuedAt, NotBefore: node.IssuedAt - 5, ExpiresAt: node.IssuedAt + 30,
		GrantID: "render_" + strings.Repeat("a", 32), ProviderID: "provider-a", ProviderInstanceEpoch: "1",
		RecipientPublicKey: base64.RawURLEncoding.EncodeToString(public), FormatID: RenderFormat, UserID: "20",
		Subject: MetadataSubject{trust.CoreInstanceID, "11", "12", "13", "subject_" + strings.Repeat("1", 32),
			"credential_" + strings.Repeat("2", 32), "1", "vless-uuid/v1"},
		CredentialSHA256: strings.Repeat("a", 64), CredentialExpiresAt: node.IssuedAt + 3600,
		Nodes: []ConnectionNode{{NodeID: "7", Name: "test node", Protocol: "vless", Host: "127.0.0.1", Port: 443, Transport: "tcp"}}}
	return p, trust, core, client
}

func signedRenderRequest(p RenderPayload, core, client ed25519.PrivateKey) RenderRequest {
	raw, _ := json.Marshal(p)
	hash := sha256.Sum256(raw)
	request := RenderRequest{ContractVersion: RenderContractVersion, RequestID: "render-1", Authorization: signRaw(raw, core)}
	request.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(client, RenderProofMessage(request.RequestID, hex.EncodeToString(hash[:]))))
	return request
}

func TestRenderRequiresSeparateRecipientPrivateKeyAndBoundRequest(t *testing.T) {
	p, trust, core, client := renderFixture(t)
	request := signedRenderRequest(p, core, client)
	if _, err := VerifyRenderRequest(request, trust, time.Now()); err != nil {
		t.Fatal(err)
	}
	wrong := request
	wrong.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(core, []byte("core cannot act as recipient")))
	if _, err := VerifyRenderRequest(wrong, trust, time.Now()); err == nil {
		t.Fatal("Core key became a subscriber key")
	}
	wrong = request
	wrong.RequestID = "different-request"
	if _, err := VerifyRenderRequest(wrong, trust, time.Now()); err == nil {
		t.Fatal("request identity was not bound to proof")
	}
	for name, change := range map[string]func(*RenderPayload){
		"expired":                func(p *RenderPayload) { p.ExpiresAt = p.IssuedAt },
		"long grant":             func(p *RenderPayload) { p.ExpiresAt = p.IssuedAt + 31 },
		"node policy":            func(p *RenderPayload) { p.PolicyVersion = PolicyVersion },
		"wrong audience":         func(p *RenderPayload) { p.Audience = Audience },
		"node protocol mismatch": func(p *RenderPayload) { p.Nodes[0].Protocol = "vmess" },
		"unsupported transport":  func(p *RenderPayload) { p.Nodes[0].Transport = "ws" },
		"arbitrary URL":          func(p *RenderPayload) { p.Nodes[0].Host = "https://example.test/path" },
		"nul name":               func(p *RenderPayload) { p.Nodes[0].Name = "a\x00b" },
		"missing targets":        func(p *RenderPayload) { p.Nodes = nil },
		"credential lifetime":    func(p *RenderPayload) { p.CredentialExpiresAt = p.ExpiresAt - 1 },
		"tls alpn": func(p *RenderPayload) {
			p.Nodes[0].TLS = &ConnectionTLS{ServerName: "example.test", ALPN: []string{"unsupported"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, trust, core, client := renderFixture(t)
			change(&p)
			if _, err := VerifyRenderRequest(signedRenderRequest(p, core, client), trust, time.Now()); err == nil {
				t.Fatal("invalid render grant accepted")
			}
		})
	}
	p.Nodes[0].TLS = &ConnectionTLS{ServerName: "example.test", ALPN: []string{"h2", "http/1.1"}}
	if _, err := VerifyRenderRequest(signedRenderRequest(p, core, client), trust, time.Now()); err != nil {
		t.Fatal("closed TLS DTO rejected")
	}
}
