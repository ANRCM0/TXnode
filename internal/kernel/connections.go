package kernel

import (
	"context"
	"errors"
)

var (
	ErrInvalidConnectionID = errors.New("invalid native connection ID")
	ErrConnectionNotFound  = errors.New("native connection not found")
)

type Connection struct {
	ID        string `json:"id"`
	UserID    int    `json:"user_id"`
	Transport string `json:"transport"`
}

type ConnectionPage struct {
	Connections []Connection `json:"connections"`
	Total       int          `json:"total"`
	Next        string       `json:"next,omitempty"`
}

// ConnectionInspector is optional. Native control-plane requests delegate here.
// IDs are opaque, process scoped and never valid on another Node instance.
type ConnectionInspector interface {
	Connections(context.Context, string, int) (ConnectionPage, error)
}

type RuntimeDiagnosticProvider interface {
	RuntimeDiagnostics() map[string]any
}
