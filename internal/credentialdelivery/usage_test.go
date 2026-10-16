package credentialdelivery

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

func TestUsageV2PolicyRequiresExactCompleteSignedGrantMapping(t *testing.T) {
	p, trust, key := grantFixture(t)
	p.PolicyVersion = PolicyVersionV2
	p.UsageV2 = &usagev2.Session{ProtocolVersion: 2, CoreInstanceID: p.CoreInstanceID, NodeID: "7", SourceEpoch: "1",
		ReceiptGeneration: "1", RetentionSeconds: 3600, MaxLateReportSeconds: 600, ReceiptRetentionSeconds: 7200, IssuedAt: p.IssuedAt,
		Grants: []usagev2.Grant{{UserID: "20", AccessSubjectID: "11", AuthSnapshotID: "1", TariffRevisionID: "2",
			TermsID: "13", UsagePeriodID: "4", IssuedAt: p.IssuedAt, LeaseExpiresAt: p.ExpiresAt, RevocationVersion: "0"}}}
	raw, _ := json.Marshal(p)
	if _, err := VerifyGrant(signRaw(raw, key), trust, time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Payload){
		"missing session":            func(p *Payload) { p.UsageV2 = nil },
		"legacy policy with session": func(p *Payload) { p.PolicyVersion = PolicyVersion },
		"wrong node":                 func(p *Payload) { p.UsageV2.NodeID = "8" },
		"wrong user":                 func(p *Payload) { p.UsageV2.Grants[0].UserID = "21" },
		"wrong subject":              func(p *Payload) { p.UsageV2.Grants[0].AccessSubjectID = "12" },
		"wrong terms":                func(p *Payload) { p.UsageV2.Grants[0].TermsID = "14" },
		"longer usage lease":         func(p *Payload) { p.UsageV2.Grants[0].LeaseExpiresAt++ },
		"shorter usage lease":        func(p *Payload) { p.UsageV2.Grants[0].LeaseExpiresAt-- },
		"different issued time":      func(p *Payload) { p.UsageV2.IssuedAt-- },
		"missing usage rows":         func(p *Payload) { p.UsageV2.Grants = []usagev2.Grant{} },
	} {
		t.Run(name, func(t *testing.T) {
			var copy Payload
			json.Unmarshal(raw, &copy)
			change(&copy)
			invalid, _ := json.Marshal(copy)
			if _, err := VerifyGrant(signRaw(invalid, key), trust, time.Now(), 0); err == nil {
				t.Fatal("invalid usage mapping accepted")
			}
		})
	}
	p.PolicyVersion, p.UsageV2 = PolicyVersion, nil
	raw, _ = json.Marshal(p)
	raw = bytes.Replace(raw, []byte(`"provider":`), []byte(`"usage_v2":null,"provider":`), 1)
	if _, err := VerifyGrant(signRaw(raw, key), trust, time.Now(), 0); err == nil {
		t.Fatal("legacy policy accepted explicit usage null")
	}
}
