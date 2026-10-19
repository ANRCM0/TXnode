// Package udperr classifies UDP socket errors the way the relay needs them
// (github.com/ANRCM0/TX-Node/internal/dataplane/udperr has two functions in the sample): a closed socket ends
// the session, an unreachable destination is logged and the session continues.
package udperr

import (
	"errors"
	"net"
	"os"
	"syscall"
)

// IsClosed reports whether err means the socket is gone.
func IsClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded)
}

// IsUnreachable reports ICMP-derived destination errors.
func IsUnreachable(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}
