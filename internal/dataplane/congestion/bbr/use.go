package bbr

import (
	"os"
	"strings"

	"github.com/apernet/quic-go/congestion"
)

// Setter is the subset of *quic.Conn that Use needs. *quic.Conn satisfies it:
//
//	func (c *Conn) SetCongestionControl(cc congestion.CongestionControl)
//	func (c *Conn) InitialPacketSize() congestion.ByteCount
//
// InitialPacketSize matters: quic-go documents that a controller installed with
// SetCongestionControl must be seeded with the connection's own initial packet
// size, not the package default, or path-MTU discovery looks like a cwnd
// decrease. Use therefore seeds the sender from the connection.
type Setter interface {
	SetCongestionControl(congestion.CongestionControl)
	InitialPacketSize() congestion.ByteCount
}

// Use installs BBRv1 on a QUIC connection. It is the Go form of
// congestion_bbr.Use @0xa97c00 (notes/rev-proto-udp.md §1.3: hysteria's ServeHTTP
// calls it for every authenticated connection that is not running brutal).
func Use(conn Setter) *Sender {
	return UseProfile(conn, "")
}

// UseProfile installs BBRv1 with a named profile (applyProfile @0xa95aa0).
func UseProfile(conn Setter, profileName string) *Sender {
	s := New(profileName)
	if size := conn.InitialPacketSize(); size > 0 {
		s.SetMaxDatagramSize(size)
	}
	conn.SetCongestionControl(s)
	return s
}

// BrutalAvailable reports whether the kernel advertises TCP Brutal.
//
// Evidence: mux.BrutalAvailable @0x773aa0 reads
// "/proc/sys/net/ipv4/tcp_available_congestion_control" @0xf8eb5d
// (notes/rev-transport.md §4.4). The contract places the helper in this package
// because brutal itself is a congestion controller; the binary's copy lives in
// mux, which is a different owner's package here.
func BrutalAvailable() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(data)) {
		if f == "brutal" {
			return true
		}
	}
	return false
}
