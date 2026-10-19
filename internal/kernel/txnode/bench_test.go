package txnode

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
)

// benchKernel starts a SOCKS5 node with one panel user, relays to a sink origin
// and returns a connected client stream plus a cleanup function.
func benchKernel(b *testing.B, meter *usagebucket.Meter) (net.Conn, func()) {
	b.Helper()
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}()
		}
	}()

	port := freePortTB(b)
	k := New(RuntimeConfig{TrustedProxies: "private", MaxFresh: 128, HandshakeTimeout: 5 * time.Second})
	if meter != nil {
		k.meter = &nativeMeter{}
		k.meter.setEventMeter(meter)
	}
	ns := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}
	if err := k.Start(ns, []model.UserSpec{{ID: 1, UUID: "secret-pass"}}, kernel.TLSCert{}); err != nil {
		b.Fatal(err)
	}
	conn := socksConnectTB(b, port, "secret-pass", origin.Addr().String())
	return conn, func() {
		_ = conn.Close()
		k.Stop()
		_ = origin.Close()
	}
}

func BenchmarkSocksRelayUpload(b *testing.B) {
	conn, cleanup := benchKernel(b, nil)
	defer cleanup()
	buf := make([]byte, 32*1024)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSocksRelayUploadMetered(b *testing.B) {
	meter, err := usagebucket.New(usagebucket.Options{Enabled: true, Window: time.Second, MaxEvents: 128, MaxSealed: 8})
	if err != nil {
		b.Fatal(err)
	}
	conn, cleanup := benchKernel(b, meter)
	defer cleanup()
	buf := make([]byte, 32*1024)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
}
