package core

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

type lifecyclePackets struct {
	reading   chan struct{}
	closed    chan struct{}
	readOnce  sync.Once
	closeOnce sync.Once
}

func newLifecyclePackets() *lifecyclePackets {
	return &lifecyclePackets{reading: make(chan struct{}), closed: make(chan struct{})}
}

func (p *lifecyclePackets) ReadPacket([]byte) (int, socks.Addr, error) {
	p.readOnce.Do(func() { close(p.reading) })
	<-p.closed
	return 0, socks.Addr{}, io.EOF
}

func (p *lifecyclePackets) WritePacket([]byte, socks.Addr) error { return nil }
func (p *lifecyclePackets) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func TestPacketSessionSourceAndRevocation(t *testing.T) {
	tracker := NewTracker()
	tracker.SetUsers([]User{{ID: 1, UUID: "one"}, {ID: 2, UUID: "two"}})
	srv := NewServer(ServerOptions{Tracker: tracker})
	defer srv.Close()
	packets := newLifecyclePackets()
	sess := &Session{UserID: 1, Packets: packets, SourceIP: netip.MustParseAddr("198.51.100.7")}
	done := make(chan error, 1)
	go func() { done <- srv.ServeSession(context.Background(), sess) }()
	select {
	case <-packets.reading:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not start")
	}
	if alive := tracker.Alive()[1]; len(alive) != 1 || alive[0] != sess.SourceIP.String() {
		t.Fatalf("packet session source lost: %v", alive)
	}
	tracker.SetUsers([]User{{ID: 2, UUID: "two"}})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoked packet session survived")
	}
	if tracker.TotalUsers() != 1 {
		t.Fatal("unrelated user removed")
	}
}

func TestPacketSessionCloseAndCancellation(t *testing.T) {
	var previousID uint64
	for _, mode := range []string{"server", "admission", "context"} {
		t.Run(mode, func(t *testing.T) {
			var admitted atomic.Bool
			admitted.Store(true)
			srv := NewServer(ServerOptions{Admission: admitted.Load})
			defer srv.Close()
			packets := newLifecyclePackets()
			sess := &Session{Packets: packets}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- srv.ServeSession(ctx, sess) }()
			select {
			case <-packets.reading:
			case <-time.After(2 * time.Second):
				t.Fatal("session did not start")
			}
			if sess.ConnID == 0 || sess.ConnID == previousID {
				t.Fatal("session ID reused across server generations")
			}
			previousID = sess.ConnID
			switch mode {
			case "server":
				_ = srv.Close()
			case "admission":
				admitted.Store(false)
				srv.CloseAllSessions()
			case "context":
				cancel()
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("packet read not interrupted")
			}
			wait, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := srv.WaitSessions(wait); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestObsoletePacketHandshakeClosesTransport(t *testing.T) {
	tracker := NewTracker()
	tracker.SetUsers([]User{{ID: 1, UUID: "one"}})
	srv := NewServer(ServerOptions{Tracker: tracker})
	defer srv.Close()
	packets := newLifecyclePackets()
	err := srv.ServeSession(context.Background(), &Session{UserID: 1, Packets: packets, AuthValid: func() bool { return false }})
	if !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("obsolete credentials admitted: %v", err)
	}
	select {
	case <-packets.closed:
	default:
		t.Fatal("refused packet transport leaked")
	}
	if tracker.TotalSessions() != 0 {
		t.Fatal("obsolete handshake acquired tracker quota")
	}
}
