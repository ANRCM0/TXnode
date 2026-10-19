//go:build !linux

package txnode

import "net"

// listenReusePort falls back to a plain listen on platforms without
// SO_REUSEPORT, so Reload closes the old listener before binding the new one.
func listenReusePort(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
