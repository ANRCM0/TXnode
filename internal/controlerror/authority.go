// Package controlerror contains provider-neutral control errors without transport dependencies.
package controlerror

import (
	"errors"
	"fmt"
)

type Scope uint8

const (
	NodeScope Scope = iota + 1
	MachineScope
)

// AuthorityDenial is a completed native rejection of the request's configured identity.
// It intentionally excludes response text, credentials and endpoint addresses.
type AuthorityDenial struct {
	Scope      Scope
	NodeID     int
	MachineID  int
	Code       string
	HTTPStatus int
}

func (e *AuthorityDenial) Error() string {
	if e == nil {
		return "native authority denial"
	}
	scope := "unknown"
	if e.Scope == NodeScope {
		scope = "node"
	} else if e.Scope == MachineScope {
		scope = "machine"
	}
	code := "unknown"
	if e.Code == "NODE_UNAUTHORIZED" || e.Code == "NODE_NOT_FOUND" {
		code = e.Code
	}
	return fmt.Sprintf("native authority denial: scope=%s node_id=%d machine_id=%d status=%d code=%s", scope, e.NodeID, e.MachineID, e.HTTPStatus, code)
}

func AsAuthorityDenial(err error) (*AuthorityDenial, bool) {
	var denial *AuthorityDenial
	if !errors.As(err, &denial) || denial == nil {
		return nil, false
	}
	return denial, true
}
