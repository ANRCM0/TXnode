package controlerror

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestMembershipWithdrawalRetainsDistinctTypeAndFixedDiagnostic(t *testing.T) {
	cause := &NodeMembershipWithdrawal{NodeID: 42, MachineID: 7}
	wrapped := fmt.Errorf("stop: %w", cause)
	if got, ok := AsMembershipWithdrawal(wrapped); !ok || got != cause || got.Error() != "NATIVE_NODE_MEMBERSHIP_WITHDRAWN" {
		t.Fatal("membership cause lost")
	}
	if _, ok := AsAuthorityDenial(wrapped); ok {
		t.Fatal("successful list withdrawal fabricated HTTP denial")
	}
	if !IsAuthoritativeStopCause(wrapped) {
		t.Fatal("valid membership not terminal")
	}
}
func TestAuthoritativeStopCauseRejectsMalformedMembershipAndOrdinaryFailures(t *testing.T) {
	var typedNil *NodeMembershipWithdrawal
	for _, cause := range []error{nil, context.Canceled, errors.New("HTTP 404"), typedNil, fmt.Errorf("wrapped: %w", typedNil), &NodeMembershipWithdrawal{}, &NodeMembershipWithdrawal{NodeID: 42}, &NodeMembershipWithdrawal{MachineID: 7}, &NodeMembershipWithdrawal{NodeID: -1, MachineID: 7}, &AuthorityDenial{Scope: MachineScope, MachineID: 7, HTTPStatus: 500, Code: "NODE_UNAUTHORIZED"}, &AuthorityDenial{Scope: MachineScope, MachineID: 7, HTTPStatus: 404, Code: "NODE_NOT_FOUND"}, &AuthorityDenial{Scope: NodeScope, NodeID: 42, HTTPStatus: 401, Code: "other"}} {
		if IsAuthoritativeStopCause(cause) {
			t.Fatal("ordinary/malformed error authorized stop", cause)
		}
	}
	for _, cause := range []error{&AuthorityDenial{Scope: MachineScope, MachineID: 7, HTTPStatus: 401, Code: "NODE_UNAUTHORIZED"}, &AuthorityDenial{Scope: NodeScope, NodeID: 42, HTTPStatus: 401, Code: "NODE_UNAUTHORIZED"}, &AuthorityDenial{Scope: NodeScope, NodeID: 42, MachineID: 7, HTTPStatus: 404, Code: "NODE_NOT_FOUND"}} {
		if !IsAuthoritativeStopCause(errors.Join(errors.New("durability"), cause)) {
			t.Fatal("valid native denial lost")
		}
	}
}
