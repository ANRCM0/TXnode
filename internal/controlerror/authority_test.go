package controlerror

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAuthorityDenialSurvivesWrappingWithoutLeakingUntrustedCode(t *testing.T) {
	denial := &AuthorityDenial{Scope: MachineScope, NodeID: 42, MachineID: 7, Code: "NODE_UNAUTHORIZED", HTTPStatus: 401}
	got, ok := AsAuthorityDenial(fmt.Errorf("poll failed: %w", denial))
	if !ok || got != denial {
		t.Fatal("wrapped denial lost")
	}
	if got.Error() != "native authority denial: scope=machine node_id=42 machine_id=7 status=401 code=NODE_UNAUTHORIZED" {
		t.Fatalf("unexpected diagnostic %q", got.Error())
	}
	hostile := &AuthorityDenial{Scope: 99, Code: "secret-token https://untrusted.test/", HTTPStatus: 401}
	if strings.Contains(hostile.Error(), "secret-token") || strings.Contains(hostile.Error(), "untrusted") {
		t.Fatal("untrusted code leaked")
	}
}

func TestAsAuthorityDenialRejectsOrdinaryAndNilErrors(t *testing.T) {
	var typedNil *AuthorityDenial
	for _, err := range []error{nil, errors.New("HTTP 401"), typedNil, fmt.Errorf("wrapped: %w", typedNil)} {
		if _, ok := AsAuthorityDenial(err); ok {
			t.Fatal("ordinary or nil error classified as authority denial")
		}
	}
}
