package usagev2

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

var machineTransportObservations atomic.Int32

type machineTransportScopeKey struct{}

func WithMachineTransportStartupScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, machineTransportScopeKey{}, true)
}

// This isolated diagnostic clone records only bounded failure categories.
func machineTransportCause(ctx context.Context, failure error, path, phase string, elapsed time.Duration) {
	sequence := machineTransportObservations.Add(1)
	if sequence > 16 {
		return
	}
	endpoint := "query"
	if path == "/submit" {
		endpoint = "submit"
	}
	kind := "other"
	var certificate *tls.CertificateVerificationError
	var network net.Error
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		kind = "context_deadline"
	case errors.Is(ctx.Err(), context.Canceled):
		kind = "context_canceled"
	case errors.As(failure, &certificate):
		kind = "tls_verification"
	case errors.Is(failure, syscall.ECONNREFUSED):
		kind = "connection_refused"
	case errors.Is(failure, syscall.ECONNRESET):
		kind = "connection_reset"
	case errors.Is(failure, io.EOF), errors.Is(failure, io.ErrUnexpectedEOF):
		kind = "eof"
	case errors.As(failure, &network) && network.Timeout():
		kind = "network_timeout"
	}
	deadline, bounded := ctx.Deadline()
	remaining := int64(0)
	if bounded {
		remaining = min(int64(60*time.Second), max(int64(-60*time.Second), int64(time.Until(deadline))))
	}
	scope := "worker"
	if startup, _ := ctx.Value(machineTransportScopeKey{}).(bool); startup {
		scope = "startup"
	}
	event := map[string]any{
		"schema": "txnode-machine-transport-cause/v1", "sequence": sequence,
		"phase": phase, "endpoint": endpoint, "cause": kind,
		"context_canceled":  errors.Is(ctx.Err(), context.Canceled),
		"context_deadline":  errors.Is(ctx.Err(), context.DeadlineExceeded),
		"error_is_deadline": errors.Is(failure, context.DeadlineExceeded),
		"error_is_canceled": errors.Is(failure, context.Canceled),
		"has_deadline":      bounded, "deadline_remaining_nanos": remaining,
		"observed_unix_nanos": time.Now().UnixNano(),
		"scope":               scope, "request_elapsed_nanos": min(int64(60*time.Second), max(int64(0), int64(elapsed))),
	}
	encoded, err := json.Marshal(event)
	if err == nil {
		fmt.Printf("NATIVE_MACHINE_TRANSPORT_CAUSE %s\n", encoded)
	}
}
