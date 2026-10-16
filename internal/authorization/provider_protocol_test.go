package authorization

import (
	"testing"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

func TestProviderProfileMatchesRuntimeProtocolAndEmptyRevocationIsIndependent(t *testing.T) {
	p, trust, key, users, now := providerFixture(t)
	for _, profile := range []string{"vless-uuid/v1", "vmess-uuid/v1"} {
		p.Provider.CredentialProfileID = profile
		snapshot, err := Verify(signProvider(t, p, key), users, trust, Target{NodeID: p.NodeID, MachineID: p.MachineID}, p.PolicyVersion, now, 5)
		if err != nil {
			t.Fatal(err)
		}
		for _, protocol := range []string{"vless", "vmess", "trojan", ""} {
			err := ValidateProtocol(snapshot, protocol)
			matches := profile == protocol+"-uuid/v1"
			if matches && err != nil || !matches && !IsRefusal(err) {
				t.Fatalf("profile=%s protocol=%s err=%v", profile, protocol, err)
			}
		}
	}
	p.Users, p.Provider.Subjects = []panel.User{}, []credentialdelivery.Subject{}
	empty, err := Verify(signProvider(t, p, key), []panel.User{}, trust, Target{NodeID: p.NodeID, MachineID: p.MachineID}, p.PolicyVersion, now, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProtocol(empty, "vless"); err != nil {
		t.Fatal("empty VMess grant could not remove prior VLESS cohort", err)
	}
	legacy, legacyTrust, legacyKey, legacyNow := signedFixture(t)
	snapshot, err := Verify(signPayload(t, legacy, legacyKey), legacy.Users, legacyTrust, Target{NodeID: legacy.NodeID}, config.NativeAuthorizationPolicyVersion, legacyNow, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProtocol(snapshot, "trojan"); err != nil {
		t.Fatal("legacy policy acquired a Provider-only restriction", err)
	}
}
