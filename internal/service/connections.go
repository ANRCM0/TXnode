package service

import (
	"context"
	"errors"
	"time"

	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel"
)

type connectionReceipt struct {
	command controlplane.ConnectionCommand
	result  controlplane.ConnectionResult
}

// Runs on the Service loop, including commands drained from its Machine mailbox.
func (s *Service) handleConnectionCommand(ctx context.Context, command *controlplane.ConnectionCommand) {
	if command == nil || s.cfg == nil || command.NodeID != s.cfg.Panel.NodeID {
		return
	}
	sender, ok := s.push.Client().(controlplane.ConnectionResultSender)
	if !ok {
		return
	}
	result := controlplane.ConnectionResult{NodeID: command.NodeID, RequestID: command.RequestID, Action: command.Action, Status: "unavailable"}
	now := time.Now()
	if command.Deadline <= now.Unix() || command.Deadline > now.Unix()+30 {
		result.Status = "expired"
		sender.SendConnectionResult(result)
		return
	}
	for id, receipt := range s.connectionReceipts {
		if receipt.command.Deadline <= now.Unix() {
			delete(s.connectionReceipts, id)
		}
	}
	if receipt, exists := s.connectionReceipts[command.RequestID]; exists {
		if receipt.command == *command {
			sender.SendConnectionResult(receipt.result)
		}
		return
	}
	if len(s.connectionReceipts) >= 32 || ctx.Err() != nil || s.authorityTerminal(ctx) || s.kernel == nil || !s.kernel.IsRunning() {
		sender.SendConnectionResult(result)
		return
	}
	operationCtx, cancel := context.WithDeadline(ctx, time.Unix(command.Deadline, 0))
	defer cancel()
	var err error
	switch command.Action {
	case "list":
		if inspector, available := s.kernel.(kernel.ConnectionInspector); available {
			page, queryErr := inspector.Connections(operationCtx, command.After, command.Limit)
			err = queryErr
			if err == nil {
				result.Page, result.Status = &page, "complete"
			}
		}
	case "close":
		err = s.kernel.CloseConnection(operationCtx, command.ConnectionID)
		if err == nil {
			result.Status = "closed"
		}
	}
	switch {
	case errors.Is(err, kernel.ErrConnectionNotFound):
		result.Status = "not_found"
	case errors.Is(err, kernel.ErrInvalidConnectionID):
		result.Status = "invalid"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		result.Status = "expired"
	}
	if s.connectionReceipts == nil {
		s.connectionReceipts = make(map[string]connectionReceipt)
	}
	s.connectionReceipts[command.RequestID] = connectionReceipt{command: *command, result: result}
	sender.SendConnectionResult(result)
}
