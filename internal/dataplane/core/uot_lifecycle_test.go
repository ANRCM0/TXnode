package core

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

func TestUoTRejectsTruncatedIPAddress(t *testing.T) {
	for _, tc := range []struct {
		atyp byte
		size int
	}{{uotAtypIPv4, 7}, {uotAtypIPv6, 19}} {
		for n := 1; n < tc.size; n++ {
			frame := make([]byte, n)
			frame[0] = tc.atyp
			if _, _, err := uotReadAddr(frame); !errors.Is(err, errUoTBadAddress) {
				t.Fatalf("atyp=%d len=%d err=%v", tc.atyp, n, err)
			}
		}
	}
}

func TestUoTWriteRejectsShortFrame(t *testing.T) {
	conn := accountingConn{write: func(p []byte) (int, error) { return len(p) - 1, nil }}
	stream := NewUoT(conn, 1)
	if err := stream.WritePacket([]byte("payload"), socks.Addr{Host: "127.0.0.1", Port: 53}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short frame accepted: %v", err)
	}
}

func TestUoTCloseInterruptsBlockedWrite(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	stream := NewUoT(a, 1)
	done := make(chan error, 1)
	go func() { done <- stream.WritePacket([]byte("payload"), socks.Addr{Host: "127.0.0.1", Port: 53}) }()
	closed := make(chan struct{})
	go func() { _ = stream.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind WritePacket")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("write remained blocked after Close")
	}
}
