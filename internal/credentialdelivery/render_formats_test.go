package credentialdelivery

import (
	"testing"
	"time"
)

func TestExplicitClientVersionAndCredentialProfileBoundaries(t *testing.T) {
	for _, c := range []struct{ format, lower, upper, below string }{
		{RenderClash, "1.18.0", "2.0.0", "1.17.9"},
		{RenderClashMeta, "1.18.0", "2.0.0", "1.17.9"},
		{RenderSingBox, "1.10.0", "1.13.0", "1.9.9"},
		{RenderShadowrocket, "2.2.0", "3.0.0", "2.1.9"},
		{RenderSurgeIOS, "5.20.0", "6.0.0", "5.19.9"},
		{RenderSurgeMac, "6.7.0", "7.0.0", "6.6.9"},
	} {
		t.Run(c.format, func(t *testing.T) {
			if !ValidRenderFormat(c.format, c.lower) || !ValidRenderProfile(c.format, "vmess-uuid/v1") {
				t.Fatal("explicit supported boundary rejected")
			}
			for _, version := range []string{c.upper, c.below, "", "01.18.0", c.lower + "\n"} {
				if ValidRenderFormat(c.format, version) {
					t.Fatal("invalid client version accepted")
				}
			}
		})
	}
	for _, format := range []string{RenderClash, RenderSurgeIOS, RenderSurgeMac} {
		if ValidRenderProfile(format, "vless-uuid/v1") {
			t.Fatal("unsupported VLESS client admitted")
		}
	}
}

func TestSignedLegacyClientGrantRequiresCompatibleVmessTargets(t *testing.T) {
	for _, format := range []struct{ name, version string }{{RenderClash, "1.18.0"}, {RenderSurgeIOS, "5.20.0"}, {RenderSurgeMac, "6.7.0"}} {
		p, trust, core, client := renderFixture(t)
		p.FormatID, p.ClientVersion = format.name, format.version
		if _, err := VerifyRenderRequest(signedRenderRequest(p, core, client), trust, time.Now()); err == nil {
			t.Fatal("signed but incompatible VLESS policy accepted")
		}
		p.Subject.CredentialProfileID, p.Nodes[0].Protocol = "vmess-uuid/v1", "vmess"
		if _, err := VerifyRenderRequest(signedRenderRequest(p, core, client), trust, time.Now()); err != nil {
			t.Fatal("compatible VMess policy rejected", err)
		}
		p.Nodes[0].TLS = &ConnectionTLS{ServerName: "example.test", ALPN: []string{"h2", "http/1.1"}}
		_, err := VerifyRenderRequest(signedRenderRequest(p, core, client), trust, time.Now())
		if (format.name == RenderClash) != (err != nil) {
			t.Fatal("signed ALPN compatibility rule changed")
		}
	}
}
