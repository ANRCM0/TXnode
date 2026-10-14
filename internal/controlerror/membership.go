package controlerror

import "errors"

// NodeMembershipWithdrawal is a successful authenticated native Machine
// snapshot's withdrawal of a previously managed Node. It is not an HTTP denial.
// IDs are taken from the configured request identity and existing child handle.
type NodeMembershipWithdrawal struct {
	NodeID    int
	MachineID int
}

func (e *NodeMembershipWithdrawal) Error() string { return "NATIVE_NODE_MEMBERSHIP_WITHDRAWN" }
func AsMembershipWithdrawal(err error) (*NodeMembershipWithdrawal, bool) {
	var withdrawal *NodeMembershipWithdrawal
	if !errors.As(err, &withdrawal) || withdrawal == nil || withdrawal.NodeID <= 0 || withdrawal.MachineID <= 0 {
		return nil, false
	}
	return withdrawal, true
}

// IsAuthoritativeStopCause deliberately rejects generic cancellation/network
// failures and malformed typed causes. Only native authenticated boundaries
// create these closed-domain stop causes; caller response text is never parsed.
func IsAuthoritativeStopCause(err error) bool {
	if _, ok := AsMembershipWithdrawal(err); ok {
		return true
	}
	denial, ok := AsAuthorityDenial(err)
	if !ok {
		return false
	}
	if denial.Code == "NODE_UNAUTHORIZED" && denial.HTTPStatus == 401 {
		return denial.Scope == NodeScope && denial.NodeID > 0 && denial.MachineID == 0 || denial.Scope == MachineScope && denial.MachineID > 0 && denial.NodeID >= 0
	}
	return denial.Code == "NODE_NOT_FOUND" && denial.HTTPStatus == 404 && denial.Scope == NodeScope && denial.NodeID > 0 && denial.MachineID >= 0
}
