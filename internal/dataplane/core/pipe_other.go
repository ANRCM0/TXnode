//go:build !linux

package core

import (
	"context"
	"net"
)

// splicePipe is unavailable outside Linux; Pipe falls back to io.Copy.
func splicePipe(ctx context.Context, a, b net.Conn, up, down func(int64)) (bool, error) {
	return false, nil
}

// Splice falls back to Pipe on platforms without splice(2).
func Splice(a, b net.Conn) (bool, error) {
	return false, Pipe(context.Background(), a, b, nil, nil)
}
