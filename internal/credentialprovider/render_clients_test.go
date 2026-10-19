package credentialprovider

import (
	"strings"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"gopkg.in/yaml.v3"
)

func clientConnection() credentialdelivery.RenderConnection {
	return credentialdelivery.RenderConnection{UUID: "11111111-1111-4111-8111-111111111111",
		Node: credentialdelivery.ConnectionNode{NodeID: "9007199254740993", Name: "Node, = [Rule] # comment",
			Protocol: "vmess", Host: "2001:db8::1", Port: 443, Transport: "tcp"}}
}

func TestClassicClashUsesVmessYamlAndKeepsItsOwnDocumentIdentity(t *testing.T) {
	connection := clientConnection()
	document, err := renderClientDocument(credentialdelivery.RenderClash, []credentialdelivery.RenderConnection{connection})
	if err != nil || document.filename != "txboard-clash-classic.yaml" || document.contentType != "application/yaml" {
		t.Fatal("classic Clash document identity invalid", err)
	}
	var config struct {
		Proxies []map[string]any `yaml:"proxies"`
		Rules   []string         `yaml:"rules"`
	}
	if yaml.Unmarshal(document.body, &config) != nil || len(config.Proxies) != 1 || len(config.Rules) != 1 || config.Rules[0] != "MATCH,TXBoard" {
		t.Fatal("classic Clash YAML structure invalid")
	}
	proxy := config.Proxies[0]
	if proxy["type"] != "vmess" || proxy["uuid"] != connection.UUID || proxy["server"] != connection.Node.Host {
		t.Fatal("VMess identity or IPv6 host changed")
	}
	connection.Node.TLS = &credentialdelivery.ConnectionTLS{ServerName: "example.test", ALPN: []string{"h2"}}
	if _, err := renderClientDocument(credentialdelivery.RenderClash, []credentialdelivery.RenderConnection{connection}); err == nil {
		t.Fatal("classic Clash silently discarded signed ALPN")
	}
	if _, err := renderClientDocument(credentialdelivery.RenderClashMeta, []credentialdelivery.RenderConnection{connection}); err != nil {
		t.Fatal("Meta lost explicit ALPN compatibility", err)
	}
	connection.Node.Protocol = "vless"
	if _, err := renderClientDocument(credentialdelivery.RenderClash, []credentialdelivery.RenderConnection{connection}); err == nil {
		t.Fatal("classic Clash emitted unsupported VLESS")
	}
}

func TestSurgeIniCannotInjectPolicyOrGroupSyntaxAndPreservesTlsAlpn(t *testing.T) {
	connection := clientConnection()
	connection.Node.TLS = &credentialdelivery.ConnectionTLS{ServerName: "example.test", ALPN: []string{"h2", "http/1.1"}}
	for _, format := range []struct{ name, filename string }{{credentialdelivery.RenderSurgeIOS, "txboard-surge-ios.conf"}, {credentialdelivery.RenderSurgeMac, "txboard-surge-mac.conf"}} {
		document, err := renderClientDocument(format.name, []credentialdelivery.RenderConnection{connection})
		if err != nil || document.filename != format.filename || document.contentType != "text/plain; charset=utf-8" {
			t.Fatal("Surge document identity invalid", err)
		}
		body := string(document.body)
		if strings.Count(body, "[Rule]") != 1 || strings.Count(body, "[Proxy]") != 1 || strings.Count(body, "[Proxy Group]") != 1 ||
			strings.Contains(body, "# comment") || !strings.Contains(body, "alpn=\"h2,http/1.1\"") ||
			!strings.Contains(body, "skip-cert-verify=false") || !strings.Contains(body, "sni=example.test") ||
			!strings.Contains(body, "username="+connection.UUID) || !strings.Contains(body, "2001:db8::1, 443") ||
			strings.Contains(body, "credential_ref") || strings.Contains(body, "#!MANAGED-CONFIG") {
			t.Fatal("Surge output widened signed fields or injected configuration")
		}
		proxyName := "TX-9007199254740993 Node Rule comment"
		if !strings.Contains(body, proxyName+" = vmess,") || !strings.Contains(body, "TXBoard = select, "+proxyName) {
			t.Fatal("safe proxy label and group member diverged")
		}
		repeated, err := renderClientDocument(format.name, []credentialdelivery.RenderConnection{connection})
		if err != nil || string(repeated.body) != body {
			t.Fatal("Surge output is not deterministic")
		}
	}
}

func TestSurgeRejectsIncompatibleOrUnsafeInputInsteadOfSerializingPartialMaterial(t *testing.T) {
	for _, change := range []func(*credentialdelivery.RenderConnection){
		func(c *credentialdelivery.RenderConnection) { c.Node.Protocol = "vless" },
		func(c *credentialdelivery.RenderConnection) { c.Node.Transport = "ws" },
		func(c *credentialdelivery.RenderConnection) { c.Node.Host = "example.test, tls=false" },
		func(c *credentialdelivery.RenderConnection) { c.Node.Name = "one\n[Rule]" },
		func(c *credentialdelivery.RenderConnection) { c.UUID += ", tls=false" },
		func(c *credentialdelivery.RenderConnection) {
			c.Node.TLS = &credentialdelivery.ConnectionTLS{ServerName: "example.test, insecure=true", ALPN: []string{}}
		},
	} {
		connection := clientConnection()
		change(&connection)
		document, err := renderClientDocument(credentialdelivery.RenderSurgeIOS, []credentialdelivery.RenderConnection{connection})
		if err == nil || len(document.body) != 0 {
			t.Fatal("unsafe input emitted credential material")
		}
	}
}
