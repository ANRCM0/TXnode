package vless

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type snapshotIdentity struct {
	UUID, Name string
	Index      int
}
type snapshotHandler struct{ users chan snapshotIdentity }

func (h *snapshotHandler) NewConnectionEx(ctx context.Context, c net.Conn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	if u, ok := auth.UserFromContext[snapshotIdentity](ctx); ok {
		h.users <- u
	}
	c.Close()
	if onClose != nil {
		onClose(nil)
	}
}
func (h *snapshotHandler) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	if u, ok := auth.UserFromContext[snapshotIdentity](ctx); ok {
		h.users <- u
	}
	c.Close()
	if onClose != nil {
		onClose(nil)
	}
}

type snapshotConn struct {
	bytes.Reader
	written bytes.Buffer
	enter   chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *snapshotConn) Read(p []byte) (int, error) {
	if c.enter != nil {
		c.once.Do(func() { close(c.enter); <-c.release })
	}
	return c.Reader.Read(p)
}
func (c *snapshotConn) Write(p []byte) (int, error)      { return c.written.Write(p) }
func (c *snapshotConn) Close() error                     { return nil }
func (c *snapshotConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *snapshotConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *snapshotConn) SetDeadline(time.Time) error      { return nil }
func (c *snapshotConn) SetReadDeadline(time.Time) error  { return nil }
func (c *snapshotConn) SetWriteDeadline(time.Time) error { return nil }
func snapshotRequest(t *testing.T, uuid string) []byte {
	t.Helper()
	client, err := NewClient(uuid, "", logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	wire := &snapshotConn{}
	conn, err := client.DialConn(wire, M.ParseSocksaddr("127.0.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), wire.written.Bytes()...)
}

func TestSnapshotUserIdentityIsBoundAcrossConcurrentReorderAndSlowAuth(t *testing.T) {
	old := snapshotIdentity{UUID: "550e8400-e29b-41d4-a716-446655440000", Name: "old-name", Index: 1}
	sibling := snapshotIdentity{UUID: "550e8400-e29b-41d4-a716-446655440001", Name: "sibling", Index: 0}
	handler := &snapshotHandler{users: make(chan snapshotIdentity, 8)}
	service := NewService[snapshotIdentity](logger.NOP(), handler)
	service.UpdateUsers([]snapshotIdentity{sibling, old}, []string{sibling.UUID, old.UUID}, []string{"", ""})
	enter, release := make(chan struct{}), make(chan struct{})
	conn := &snapshotConn{Reader: *bytes.NewReader(snapshotRequest(t, old.UUID)), enter: enter, release: release}
	done := make(chan error, 1)
	go func() { done <- service.NewConnection(context.Background(), conn, M.Socksaddr{}, nil) }()
	select {
	case <-enter:
	case <-time.After(2 * time.Second):
		t.Fatal("auth did not enter")
	}
	updated := make(chan struct{})
	go func() {
		service.UpdateUsers([]snapshotIdentity{sibling}, []string{sibling.UUID}, []string{""})
		close(updated)
	}()
	select {
	case <-updated:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("slow auth blocked update")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("auth did not finish")
	}
	if got := <-handler.users; got != old {
		t.Fatalf("old auth misattributed %+v", got)
	}
	newConn := &snapshotConn{Reader: *bytes.NewReader(snapshotRequest(t, old.UUID))}
	if err := service.NewConnection(context.Background(), newConn, M.Socksaddr{}, nil); err == nil {
		t.Fatal("retired UUID accepted")
	}
	replacement := old
	replacement.Name = "new-name"
	replacement.Index = 0
	service.UpdateUsers([]snapshotIdentity{replacement, sibling}, []string{replacement.UUID, sibling.UUID}, []string{"", ""})
	if err := service.NewConnection(context.Background(), &snapshotConn{Reader: *bytes.NewReader(snapshotRequest(t, old.UUID))}, M.Socksaddr{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := <-handler.users; got != replacement {
		t.Fatalf("new auth stale identity %+v", got)
	}
}
