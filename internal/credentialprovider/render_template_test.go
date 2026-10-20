package credentialprovider

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
)

func templateConnections() []credentialdelivery.RenderConnection {
	return []credentialdelivery.RenderConnection{{UUID: "11111111-1111-4111-8111-111111111111", Node: credentialdelivery.ConnectionNode{NodeID: "1", Name: "sample", Host: "example.invalid", Port: 443, Protocol: "vmess", Transport: "tcp"}}}
}

func TestClientTemplateFullDocumentsPreserveEightNativeFormats(t *testing.T) {
	for _, format := range []string{credentialdelivery.RenderClash, credentialdelivery.RenderClashMeta, credentialdelivery.RenderStash, credentialdelivery.RenderSingBox, credentialdelivery.RenderSurfboard, credentialdelivery.RenderSurgeIOS, credentialdelivery.RenderSurgeMac, credentialdelivery.RenderShadowrocket} {
		t.Run(format, func(t *testing.T) {
			builtin, err := renderClientDocument(format, templateConnections())
			if err != nil {
				t.Fatal(err)
			}
			rendered, err := renderTemplateDocument(format, "{{ if .Connections }}{{ .Default }}{{ else }}missing{{ end }}", templateConnections())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(builtin.body, rendered.body) || builtin.contentType != rendered.contentType || builtin.filename != rendered.filename {
				t.Fatal("default delegation changed native output")
			}
		})
	}
	source := `{"format":{{ quote .Format }},"outbounds":[{{ range .Connections }}{"tag":{{ quote .Name }},"uuid":{{ quote .UUID }},"host":{{ quote .Node.Host }}}{{ end }}]}`
	rendered, err := renderTemplateDocument(credentialdelivery.RenderSingBox, source, templateConnections())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rendered.body, []byte(`"host":"example.invalid"`)) || bytes.Contains(rendered.body, []byte("credential_ref")) {
		t.Fatal("inert connection projection failed")
	}
}

func TestClientTemplateRejectsRecursionUnboundedExpansionAndMalformedDocuments(t *testing.T) {
	for name, source := range map[string]string{
		"recursion": `{{template "client" .}}`, "definitions": `{{define "other"}}x{{end}}{{template "other" .}}`,
		"nested ranges":   `{{range .Connections}}{{range $.Connections}}{{.UUID}}{{end}}{{end}}`,
		"arbitrary range": `{{range 1000000000}}x{{end}}`, "unsafe builtin": `{{printf "%s" .Default}}`,
		"helper expansion": "{{ .Default" + strings.Repeat(" | base64", 80) + " }}",
		"malformed json":   `{"bad":`, "nil map": `null`, "missing variable": `{{ .Unknown }}`,
		"ast budget": strings.Repeat("{{ if true }}x{{end}}", 500),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderTemplateDocument(credentialdelivery.RenderSingBox, source, templateConnections()); err == nil {
				t.Fatal("unsafe or malformed source accepted")
			}
		})
	}
	for _, format := range []string{credentialdelivery.RenderClashMeta, credentialdelivery.RenderStash, credentialdelivery.RenderSingBox, credentialdelivery.RenderSurgeIOS, credentialdelivery.RenderSurfboard, credentialdelivery.RenderShadowrocket} {
		if _, err := renderTemplateDocument(format, "not a client document", templateConnections()); err == nil {
			t.Fatalf("malformed %s document accepted", format)
		}
	}
	large := templateConnections()
	large[0].Node.Name = strings.Repeat("x", 100000)
	large = append(large, large[0], large[0])
	if _, err := renderTemplateDocument(credentialdelivery.RenderClashMeta, `{{range .Connections}}{{$.Default}}{{end}}`, large); err == nil {
		t.Fatal("output byte budget exceeded without rejection")
	}
}
