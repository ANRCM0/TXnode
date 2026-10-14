package vmess

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type snapshotIdentity struct {
	UUID, Name string
	Index      int
}
type snapshotAuthHandler struct{ users chan snapshotIdentity }

func (h *snapshotAuthHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, ok := auth.UserFromContext[snapshotIdentity](ctx)
	if ok {
		h.users <- user
	}
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}
func (h *snapshotAuthHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, ok := auth.UserFromContext[snapshotIdentity](ctx)
	if ok {
		h.users <- user
	}
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

type snapshotWireConn struct {
	bytes.Reader
	written bytes.Buffer
}

func newSnapshotWireConn(body []byte) *snapshotWireConn {
	return &snapshotWireConn{Reader: *bytes.NewReader(body)}
}
func (c *snapshotWireConn) Write(p []byte) (int, error)      { return c.written.Write(p) }
func (c *snapshotWireConn) Close() error                     { return nil }
func (c *snapshotWireConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *snapshotWireConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *snapshotWireConn) SetDeadline(time.Time) error      { return nil }
func (c *snapshotWireConn) SetReadDeadline(time.Time) error  { return nil }
func (c *snapshotWireConn) SetWriteDeadline(time.Time) error { return nil }

func snapshotRequest(t *testing.T, uuid string, alterID int) []byte {
	t.Helper()
	client, err := NewClient(uuid, "aes-128-gcm", alterID)
	if err != nil {
		t.Fatal(err)
	}
	wire := newSnapshotWireConn(nil)
	if _, err = client.DialConn(wire, M.ParseSocksaddr("127.0.0.1:80")); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), wire.written.Bytes()...)
}

func TestAuthenticationSnapshotRetainsAEADReplayAcrossUserUpdate(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	old := snapshotIdentity{UUID: uuid, Name: "old-name", Index: 0}
	retained := snapshotIdentity{UUID: uuid, Name: "new-name", Index: 1}
	added := snapshotIdentity{UUID: "550e8400-e29b-41d4-a716-446655440001", Name: "added", Index: 0}
	handler := &snapshotAuthHandler{users: make(chan snapshotIdentity, 4)}
	service := NewService[snapshotIdentity](handler)
	if err := service.UpdateUsers([]snapshotIdentity{old}, []string{uuid}, []int{0}); err != nil {
		t.Fatal(err)
	}
	request := snapshotRequest(t, uuid, 0)
	if err := service.NewConnection(context.Background(), newSnapshotWireConn(request), M.Socksaddr{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := <-handler.users; got != old {
		t.Fatalf("initial identity %+v", got)
	}
	filter := service.replayFilter
	if err := service.UpdateUsers([]snapshotIdentity{added, retained}, []string{added.UUID, uuid}, []int{0, 0}); err != nil {
		t.Fatal(err)
	}
	if filter != service.replayFilter {
		t.Fatal("replay filter replaced during update")
	}
	if err := service.NewConnection(context.Background(), newSnapshotWireConn(request), M.Socksaddr{}, nil); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed AEAD auth after update accepted: %v", err)
	}
	fresh := snapshotRequest(t, uuid, 0)
	if err := service.NewConnection(context.Background(), newSnapshotWireConn(fresh), M.Socksaddr{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := <-handler.users; got != retained {
		t.Fatalf("reordered current identity %+v", got)
	}
}

type snapshotBlockedConn struct {
	*snapshotWireConn
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *snapshotBlockedConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.snapshotWireConn.Read(p)
}
func TestSlowAuthenticationDoesNotBlockUpdateOrMisattributeOldIndex(t *testing.T) {
	old := snapshotIdentity{UUID: "550e8400-e29b-41d4-a716-446655440000", Name: "old-name", Index: 1}
	sibling := snapshotIdentity{UUID: "550e8400-e29b-41d4-a716-446655440001", Name: "sibling", Index: 0}
	handler := &snapshotAuthHandler{users: make(chan snapshotIdentity, 4)}
	service := NewService[snapshotIdentity](handler)
	if err := service.UpdateUsers([]snapshotIdentity{sibling, old}, []string{sibling.UUID, old.UUID}, []int{0, 0}); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	entered := make(chan struct{})
	conn := &snapshotBlockedConn{snapshotWireConn: newSnapshotWireConn(snapshotRequest(t, old.UUID, 0)), entered: entered, release: release}
	done := make(chan error, 1)
	go func() { done <- service.NewConnection(context.Background(), conn, M.Socksaddr{}, nil) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("authentication did not start")
	}
	updated := make(chan error, 1)
	go func() { updated <- service.UpdateUsers([]snapshotIdentity{sibling}, []string{sibling.UUID}, []int{0}) }()
	select {
	case err := <-updated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("slow auth blocked user update")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("old auth did not finish")
	}
	if got := <-handler.users; got != old {
		t.Fatalf("old snapshot index resolved against new users: %+v", got)
	}
	if err := service.NewConnection(context.Background(), newSnapshotWireConn(snapshotRequest(t, old.UUID, 0)), M.Socksaddr{}, nil); err == nil {
		t.Fatal("retired UUID accepted by current snapshot")
	}
}

func TestLegacyRefreshUserPublicationAndIdempotentClose(t *testing.T) {
	user := snapshotIdentity{UUID: "550e8400-e29b-41d4-a716-446655440000", Name: "legacy", Index: 0}
	handler := &snapshotAuthHandler{users: make(chan snapshotIdentity, 100)}
	service := NewService[snapshotIdentity](handler)
	if err := service.UpdateUsers([]snapshotIdentity{user}, []string{user.UUID}, []int{0}); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	if service.alterIdWorkerDone != nil {
		t.Fatal("unexpected legacy worker for AEAD-only users")
	}
	if err := service.UpdateUsers([]snapshotIdentity{user}, []string{user.UUID}, []int{1}); err != nil {
		t.Fatal(err)
	}
	service.lifecycleMu.Lock()
	worker := service.alterIdWorkerDone
	service.alterIdUpdateTask.Reset(time.Millisecond)
	service.lifecycleMu.Unlock()
	if worker == nil {
		t.Fatal("adding legacy user after Start did not start worker")
	}
	var wg sync.WaitGroup
	var failures atomic.Int32
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			if err := service.UpdateUsers([]snapshotIdentity{user}, []string{user.UUID}, []int{1}); err != nil {
				failures.Add(1)
			}
		}
	}()
	requests := make([][]byte, 40)
	for i := range requests {
		requests[i] = snapshotRequest(t, user.UUID, 1)
	}
	go func() {
		defer wg.Done()
		for _, request := range requests {
			if err := service.NewConnection(context.Background(), newSnapshotWireConn(request), M.Socksaddr{}, nil); err != nil {
				failures.Add(1)
			}
		}
	}()
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("legacy concurrent auth/update failures=%d", failures.Load())
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-worker:
	default:
		t.Fatal("Close did not wait for legacy worker")
	}
	snapshot := service.users.Load()
	service.refreshLegacyKeys()
	if service.users.Load() != snapshot {
		t.Fatal("closed service published another snapshot")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start after Close=%v", err)
	}
	if err := service.UpdateUsers([]snapshotIdentity{user}, []string{user.UUID}, []int{0}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Update after Close=%v", err)
	}
}

func TestInvalidUserListDoesNotPublishPartialAuthentication(t *testing.T) {
	service := NewService[snapshotIdentity](&snapshotAuthHandler{users: make(chan snapshotIdentity, 1)})
	prior := service.users.Load()
	if err := service.UpdateUsers([]snapshotIdentity{{}}, nil, []int{0}); err == nil {
		t.Fatal("mismatched parallel lists accepted")
	}
	if service.users.Load() != prior {
		t.Fatal("invalid update replaced snapshot")
	}
}

var _ io.Reader = (*snapshotBlockedConn)(nil)
