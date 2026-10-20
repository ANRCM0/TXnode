package hysteria

import (
	"crypto/tls"
	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"testing"
)

func TestCredentialUpdateInvalidatesExistingConnection(t *testing.T) {
	s, err := NewServer(Options{TLSConfig: &tls.Config{}, Users: []core.User{{ID: 1, UUID: "old"}}})
	if err != nil {
		t.Fatal(err)
	}
	st := &connState{srv: s, authed: true, user: s.users["old"], userValid: s.credentialValidity["old"]}
	if !st.authValid() {
		t.Fatal("fresh authentication invalid")
	}
	s.SetUsers([]core.User{{ID: 1, UUID: "old"}, {ID: 2, UUID: "other"}})
	if !st.authValid() {
		t.Fatal("unrelated user update revoked stable credentials")
	}
	s.SetUsers([]core.User{{ID: 1, UUID: "new"}})
	if st.authValid() {
		t.Fatal("rotated credential can open more streams")
	}
	s.SetUsers([]core.User{{ID: 1, UUID: "old"}})
	if st.authValid() {
		t.Fatal("readding credential revived revoked connection")
	}
}
