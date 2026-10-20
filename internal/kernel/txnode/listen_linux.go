//go:build linux

package txnode

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenReusePort opens a TCP listener with SO_REUSEPORT so Reload can bind the
// new generation on the same port before the old one is closed. The kernel
// load-balances fresh connections between both sockets during the overlap; live
// sessions stay on the old server until it drains.
func listenReusePort(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var err error
			if cerr := c.Control(func(fd uintptr) {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); cerr != nil {
				return cerr
			}
			return err
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}
