package core

import (
	"context"
	"testing"
	"time"
)

func TestConnectionPageBoundsAndCursor(t *testing.T) {
	srv := NewServer(ServerOptions{})
	defer srv.Close()
	for i := uint64(1); i <= 300; i++ {
		if !srv.registerSession(&Session{ConnID: i, UserID: 7}) {
			t.Fatal("register")
		}
	}
	p := srv.ConnectionPage(0, 10000)
	if p.Total != 300 || len(p.Connections) != MaxConnectionPage || !p.More {
		t.Fatalf("unbounded or incomplete page: %+v", p)
	}
	for i, c := range p.Connections {
		if c.ID != uint64(i+1) || c.Transport != "tcp" || c.UserID != 7 {
			t.Fatal("unordered or incorrect management identity", c)
		}
	}
	p = srv.ConnectionPage(298, 2)
	if p.Total != 300 || len(p.Connections) != 2 || p.More || p.Connections[0].ID != 299 || p.Connections[1].ID != 300 {
		t.Fatalf("cursor changed identity: %+v", p)
	}
}

func TestCloseSessionCancelsOnlyOwnedPacketSession(t *testing.T) {
	srv, other := NewServer(ServerOptions{}), NewServer(ServerOptions{})
	defer srv.Close()
	defer other.Close()
	packets := newLifecyclePackets()
	done := make(chan error, 1)
	go func() { done <- srv.ServeSession(context.Background(), &Session{Packets: packets}) }()
	select {
	case <-packets.reading:
	case <-time.After(2 * time.Second):
		t.Fatal("packet session did not start")
	}
	p := srv.ConnectionPage(0, 1)
	if len(p.Connections) != 1 || p.Connections[0].Transport != "udp" {
		t.Fatal("packet missing from management page", p)
	}
	id := p.Connections[0].ID
	if other.CloseSession(id) {
		t.Fatal("foreign server closed a packet session")
	}
	if !srv.CloseSession(id) {
		t.Fatal("owned session not closed")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not cancel packet relay")
	}
	if srv.CloseSession(id) || srv.ConnectionPage(0, 1).Total != 0 {
		t.Fatal("exited session remained registered")
	}
}
