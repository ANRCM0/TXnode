package vmess

import (
	"errors"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

func TestUserReplacementKeepsReplayHistory(t *testing.T) {
	users := []core.User{{ID: 1, UUID: "00112233-4455-4677-8899-aabbccddeeff"}}
	old, err := NewHandler(Options{Users: users})
	if err != nil {
		t.Fatal(err)
	}
	auth := []byte("same-auth-id-1234")
	if err := old.fresh(auth); err != nil {
		t.Fatal(err)
	}
	next, err := NewHandler(Options{Users: append(users, core.User{ID: 2, UUID: "11112233-4455-4677-8899-aabbccddeeff"})})
	if err != nil {
		t.Fatal(err)
	}
	next.InheritSecurityState(old)
	if err := next.fresh(auth); !errors.Is(err, ErrReplayed) {
		t.Fatalf("old request accepted after update: %v", err)
	}
	newAuth := []byte("new-auth-id--1234")
	if err := next.fresh(newAuth); err != nil {
		t.Fatal(err)
	}
	if err := old.fresh(newAuth); !errors.Is(err, ErrReplayed) {
		t.Fatalf("old generation missed new request: %v", err)
	}
}
