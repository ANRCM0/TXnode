package outbound

import (
	"context"
	"crypto/rand"
	"net"
)

// ShadowTLSDial is installed by node wiring (ctransport.DialShadowTLS). The
// SIP003 shadow-tls plugin needs a borrowed TLS handshake, so it cannot use the
// plain transport dialer.
var ShadowTLSDial func(ctx context.Context, network, addr, host, password string) (net.Conn, error)

// randRead is a test seam: the VMess/VLESS headers and the Shadowsocks salts
// read from it, so tests can pin them. Production never replaces it.
var randRead = rand.Read
