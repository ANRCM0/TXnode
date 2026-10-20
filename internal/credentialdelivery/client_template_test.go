package credentialdelivery

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignedClientTemplateBindsSourceHashVersionEngineAndFormat(t *testing.T) {
	for name, change := range map[string]func(*RenderPayload){
		"valid":         func(*RenderPayload) {},
		"source":        func(p *RenderPayload) { p.ClientTemplate.Source = "tampered" },
		"hash":          func(p *RenderPayload) { p.ClientTemplate.SHA256 = strings.Repeat("0", 64) },
		"version":       func(p *RenderPayload) { p.ClientTemplate.Version = "new" },
		"engine":        func(p *RenderPayload) { p.ClientTemplate.Engine = "unknown/v1" },
		"client":        func(p *RenderPayload) { p.ClientTemplate.FormatID = RenderSingBox },
		"native bundle": func(p *RenderPayload) { p.FormatID = RenderFormat },
		"oversized":     func(p *RenderPayload) { p.ClientTemplate.Source = strings.Repeat("x", MaxTemplateBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			p, trust, core, client := renderFixture(t)
			p.FormatID = RenderClashMeta
			p.ClientVersion = "1.18.0"
			digest := sha256.Sum256([]byte("{{ .Default }}"))
			p.ClientTemplate = &ClientTemplate{ClientTemplateEngine, RenderClashMeta, strings.Repeat("a", 64), hex.EncodeToString(digest[:]), "{{ .Default }}"}
			change(&p)
			_, err := VerifyRenderRequest(signedRenderRequest(p, core, client), trust, time.Now())
			if (err == nil) != (name == "valid") {
				t.Fatalf("unexpected verification result: %v", err)
			}
		})
	}
	p, trust, core, client := renderFixture(t)
	p.FormatID = RenderClashMeta
	p.ClientVersion = "1.18.0"
	hash := sha256.Sum256([]byte("{{ .Default }}"))
	p.ClientTemplate = &ClientTemplate{ClientTemplateEngine, RenderClashMeta, strings.Repeat("a", 64), hex.EncodeToString(hash[:]), "{{ .Default }}"}
	request := signedRenderRequest(p, core, client)
	raw, _ := base64.RawURLEncoding.DecodeString(request.Authorization.Payload)
	var modified RenderPayload
	_ = json.Unmarshal(raw, &modified)
	modified.ClientTemplate.Version = strings.Repeat("b", 64)
	raw, _ = json.Marshal(modified)
	request.Authorization.Payload = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := VerifyRenderRequest(request, trust, time.Now()); err == nil {
		t.Fatal("changed template version retained a valid Core signature")
	}
}
