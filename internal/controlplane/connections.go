package controlplane

import (
	"errors"
	"regexp"
	"time"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/kernel"
)

const EventConnections EventType = "ops.node.connections.request"

var connectionRequestID = regexp.MustCompile(`^nco_[a-f0-9]{32}$`)
var connectionReference = regexp.MustCompile(`^[a-f0-9]{32}:[1-9][0-9]{0,19}$`)

// ConnectionCommand is a bounded request for the existing kernel owner.
type ConnectionCommand struct {
	NodeID       int    `json:"node_id"`
	RequestID    string `json:"request_id"`
	Action       string `json:"action"`
	Deadline     int64  `json:"deadline"`
	After        string `json:"after,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
}

type ConnectionResult struct {
	NodeID    int                    `json:"node_id"`
	RequestID string                 `json:"request_id"`
	Action    string                 `json:"action"`
	Status    string                 `json:"status"`
	Page      *kernel.ConnectionPage `json:"page,omitempty"`
}

type ConnectionResultSender interface {
	SendConnectionResult(ConnectionResult)
}

func ParseConnectionCommand(raw []byte, nodeID int, now time.Time) (*ConnectionCommand, error) {
	var command ConnectionCommand
	if len(raw) > 1024 || authorization.ValidateJSON(raw, &command) != nil ||
		!connectionRequestID.MatchString(command.RequestID) || nodeID <= 0 || command.NodeID != nodeID ||
		command.Deadline <= now.Unix() || command.Deadline > now.Unix()+30 {
		return nil, errors.New("invalid native connection request")
	}
	switch command.Action {
	case "list":
		if command.ConnectionID != "" || command.Limit < 1 || command.Limit > 100 ||
			command.After != "" && !connectionReference.MatchString(command.After) {
			return nil, errors.New("invalid native connection list")
		}
	case "close":
		if command.After != "" || command.Limit != 0 || !connectionReference.MatchString(command.ConnectionID) {
			return nil, errors.New("invalid native connection close")
		}
	default:
		return nil, errors.New("unsupported native connection action")
	}
	return &command, nil
}
