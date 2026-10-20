//go:build linux

package txnode

import (
	"testing"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// Use the public lifecycle to catch preparing a new UDP socket before closing
// the old generation, which helper-only tests cannot detect.
func TestKernelReloadShadowsocksSameUDPPort(t *testing.T) {
	k := New(RuntimeConfig{})
	port := freePortTB(t)
	node := &model.NodeSpec{Protocol: "shadowsocks", ListenIP: "127.0.0.1", ServerPort: port, Cipher: "aes-128-gcm"}
	users := []model.UserSpec{{ID: 1, UUID: "udp-reload-user"}}
	if err := k.Start(node, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer k.Stop()
	old := k.bind
	if old.pc == nil {
		t.Fatal("Start did not activate UDP")
	}
	addr := old.pc.LocalAddr().String()
	if err := k.Reload(node, users, kernel.TLSCert{}); err != nil {
		t.Fatalf("same-port UDP reload: %v", err)
	}
	if k.bind == old || k.bind.pc == nil || old.pc != nil {
		t.Fatal("Reload did not transfer UDP ownership")
	}
	if k.bind.pc.LocalAddr().String() != addr {
		t.Fatal("Reload changed the UDP bind address")
	}
}
