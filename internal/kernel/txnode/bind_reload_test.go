package txnode

import (
	"errors"
	"net"
	"testing"
)

func TestSwitchDatagramsReusesReleasedPort(t *testing.T) {
	oldPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := oldPC.LocalAddr().String()
	old := &bindResult{pc: oldPC}
	next := &bindResult{}
	defer old.closeAll()
	defer next.closeAll()
	next.startDatagrams = func() error { var err error; next.pc, err = net.ListenPacket("udp", addr); return err }
	if err := switchDatagrams(old, next); err != nil {
		t.Fatal(err)
	}
	if old.pc != nil || next.pc == nil {
		t.Fatal("socket ownership was not transferred")
	}
	if next.pc.LocalAddr().String() != addr {
		t.Fatal("reload changed the UDP address")
	}
}

func TestSwitchDatagramsRestoresPreviousListener(t *testing.T) {
	oldPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := oldPC.LocalAddr().String()
	old := &bindResult{pc: oldPC}
	defer old.closeAll()
	restored := 0
	old.startDatagrams = func() error { restored++; var err error; old.pc, err = net.ListenPacket("udp", addr); return err }
	rejected := errors.New("invalid replacement UDP configuration")
	next := &bindResult{startDatagrams: func() error { return rejected }}
	if err := switchDatagrams(old, next); !errors.Is(err, rejected) {
		t.Fatalf("reload error = %v", err)
	}
	if restored != 1 || old.pc == nil {
		t.Fatal("previous listener was not restored")
	}
	if old.pc.LocalAddr().String() != addr {
		t.Fatal("rollback changed the UDP address")
	}
}

func TestSwitchDatagramsReportsRestoreFailure(t *testing.T) {
	rejected := errors.New("replacement rejected")
	restore := errors.New("restore rejected")
	old := &bindResult{startDatagrams: func() error { return restore }}
	next := &bindResult{startDatagrams: func() error { return rejected }}
	err := switchDatagrams(old, next)
	if !errors.Is(err, rejected) || !errors.Is(err, restore) {
		t.Fatalf("rollback errors lost: %v", err)
	}
}
