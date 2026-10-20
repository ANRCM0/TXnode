package tuic

import (
	"crypto/tls"
	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"testing"
)

func TestCredentialUpdateInvalidatesExistingConnection(t *testing.T) {
	const uuid = "00112233-4455-4677-8899-aabbccddeeff"
	s, err := NewServer(Options{TLSConfig: &tls.Config{}, Users: []core.User{{ID: 1, UUID: uuid + ":old"}}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := parseUUID(uuid)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{srv: s, authed: true, userID: 1, userValid: s.credentialValidity[id]}
	if !c.authValid() {
		t.Fatal("fresh authentication invalid")
	}
	s.SetUsers([]core.User{{ID: 1, UUID: uuid + ":old"}})
	if !c.authValid() {
		t.Fatal("stable credentials revoked")
	}
	s.SetUsers([]core.User{{ID: 1, UUID: uuid + ":new"}})
	if c.authValid() {
		t.Fatal("password rotation can open more streams")
	}
	s.SetUsers([]core.User{{ID: 1, UUID: uuid + ":old"}})
	if c.authValid() {
		t.Fatal("readding password revived revoked connection")
	}
}
