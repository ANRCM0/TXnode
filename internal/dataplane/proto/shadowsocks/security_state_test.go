package shadowsocks

import (
	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"testing"
)

func TestUserReplacementKeepsSaltHistory(t *testing.T) {
	old, err := New(Options{Cipher: "aes-128-gcm", Users: []core.User{{ID: 1, UUID: "first"}}})
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("recorded-salt-123")
	if !old.salts.add(salt) {
		t.Fatal("fresh salt refused")
	}
	next, err := New(Options{Cipher: "aes-128-gcm", Users: []core.User{{ID: 1, UUID: "rotated"}}})
	if err != nil {
		t.Fatal(err)
	}
	next.InheritSecurityState(old)
	if next.salts.add(salt) {
		t.Fatal("replayed salt accepted after user update")
	}
	if !next.salts.add([]byte("another-salt-1234")) {
		t.Fatal("new salt refused")
	}
	if old.salts.add([]byte("another-salt-1234")) {
		t.Fatal("old generation missed new salt")
	}
}
