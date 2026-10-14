package xray

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	metadata "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common/protocol"
	xrayProxy "github.com/xtls/xray-core/proxy"
)

const applicationOldUUID = "00112233-4455-6677-8899-aabbccddeeff"
const applicationKeptUUID = "10112233-4455-6677-8899-aabbccddeeff"
const applicationNewUUID = "20112233-4455-6677-8899-aabbccddeeff"
const applicationFourthUUID = "30112233-4455-6677-8899-aabbccddeeff"

type applicationEcho struct {
	listener    net.Listener
	mu          sync.Mutex
	connections []net.Conn
	wg          sync.WaitGroup
}

func newApplicationEcho(t *testing.T) *applicationEcho {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	origin := &applicationEcho{listener: l}
	origin.wg.Add(1)
	go func() {
		defer origin.wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			origin.mu.Lock()
			origin.connections = append(origin.connections, c)
			origin.wg.Add(1)
			origin.mu.Unlock()
			go func() { defer origin.wg.Done(); defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		origin.mu.Lock()
		for _, c := range origin.connections {
			c.Close()
		}
		origin.mu.Unlock()
		origin.wg.Wait()
	})
	return origin
}
func applicationPort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func applicationKernel(t *testing.T, kind string) (*Xray, *model.NodeSpec, []model.UserSpec, *applicationEcho) {
	t.Helper()
	echo := newApplicationEcho(t)
	cfg := config.KernelConfig{Type: "xray", LogLevel: "error", ConfigDir: t.TempDir(), CustomRoute: []map[string]any{{"type": "field", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprint(echo.listener.Addr().(*net.TCPAddr).Port), "outboundTag": "direct"}}}
	x := New(cfg)
	t.Cleanup(x.Stop)
	nc := &model.NodeSpec{Protocol: kind, ListenIP: "127.0.0.1", ServerPort: applicationPort(t)}
	users := []model.UserSpec{{ID: 1, UUID: applicationOldUUID}, {ID: 2, UUID: applicationKeptUUID}}
	if e := x.Start(nc, users, kernel.TLSCert{}); e != nil {
		t.Fatal("actual Xray startup", e)
	}
	return x, nc, users, echo
}
func applicationDial(kind string, nc *model.NodeSpec, id string, origin *applicationEcho) (net.Conn, error) {
	raw, e := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(nc.ServerPort)), time.Second)
	if e != nil {
		return nil, e
	}
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	destination := metadata.ParseSocksaddr(origin.listener.Addr().String())
	var wrapped net.Conn
	if kind == "vless" {
		c, e := vless.NewClient(id, "", logger.NOP())
		if e != nil {
			raw.Close()
			return nil, e
		}
		wrapped, e = c.DialConn(raw, destination)
		if e != nil {
			raw.Close()
			return nil, e
		}
	} else {
		c, e := vmess.NewClient(id, "aes-128-gcm", 0)
		if e != nil {
			raw.Close()
			return nil, e
		}
		wrapped, e = c.DialConn(raw, destination)
		if e != nil {
			raw.Close()
			return nil, e
		}
	}
	return wrapped, nil
}
func applicationRoundtrip(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if n, e := c.Write(payload); e != nil || n != len(payload) {
		t.Fatal("actual protocol write", e)
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatal("actual origin echo mismatch", e)
	}
}
func applicationEchoUser(t *testing.T, kind string, nc *model.NodeSpec, id string, origin *applicationEcho) {
	t.Helper()
	c, e := applicationDial(kind, nc, id, origin)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	applicationRoundtrip(t, c, []byte("current-xray-authority"))
}
func applicationReject(t *testing.T, kind string, nc *model.NodeSpec, id string, origin *applicationEcho) {
	t.Helper()
	c, e := applicationDial(kind, nc, id, origin)
	if e != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte("revoked"))
	var b [7]byte
	if n, e := io.ReadFull(c, b[:]); e == nil && n == len(b) {
		t.Fatal("revoked credential reached actual echo")
	}
}
func applicationClosed(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	n, e := c.Read(b[:])
	if n != 0 || e == nil {
		t.Fatal("established revoked stream still open")
	}
	var ne net.Error
	if errors.As(e, &ne) && ne.Timeout() {
		t.Fatal("old stream remained open until read timeout")
	}
}

func TestXrayActualRemovalAndRebindRequireRebuildCloseStreamsAndRetainMeters(t *testing.T) {
	for _, kind := range []string{"vless", "vmess"} {
		for _, rebind := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rebind=%v", kind, rebind), func(t *testing.T) {
				x, nc, users, origin := applicationKernel(t, kind)
				if x.Capabilities().ForceCloseUser || x.Capabilities().ForceCloseConnection {
					t.Fatal("Xray falsely advertises per-user strong close")
				}
				stream, e := applicationDial(kind, nc, applicationOldUUID, origin)
				if e != nil {
					t.Fatal(e)
				}
				defer stream.Close()
				payload := []byte("actual-old-xray-meter")
				applicationRoundtrip(t, stream, payload)
				before, e := func() (map[int][2]int64, error) { v, _, _, e := x.GetUserTraffic(context.Background()); return v, e }()
				if e != nil || before[1][0] < int64(len(payload)) || before[1][1] < int64(len(payload)) {
					t.Fatal("actual Xray cumulative meter missing", before, e)
				}
				desired := []model.UserSpec{users[1]}
				if rebind {
					desired = append(desired, model.UserSpec{ID: 1, UUID: applicationNewUUID})
					a, r, e := x.UpdateUsers(desired)
					if a != 0 || r != 0 || !errors.Is(e, ErrUserReconstructionRequired) {
						t.Fatal("rebinding falsely applied", a, r, e)
					}
				} else {
					r, e := x.RemoveUsers([]model.UserSpec{users[0]})
					if r != 0 || !errors.Is(e, ErrUserReconstructionRequired) {
						t.Fatal("removal falsely applied", r, e)
					}
				}
				x.mu.Lock()
				stillOld := len(x.users) == 2 && x.users[0].UUID == applicationOldUUID
				x.mu.Unlock()
				if !stillOld {
					t.Fatal("rejected operation changed local bookkeeping")
				}
				// Service responds to this unconfirmed operation by stopping and rebuilding.
				x.Stop()
				applicationClosed(t, stream)
				tail, _, _, e := x.GetUserTraffic(context.Background())
				if e != nil || tail[1] != before[1] {
					t.Fatal("Stop discarded final native cumulative meter", tail, e)
				}
				repeat, _, _, _ := x.GetUserTraffic(context.Background())
				if repeat[1] != tail[1] {
					t.Fatal("repeated stopped sampling duplicated bytes")
				}
				if e := x.Start(nc, desired, kernel.TLSCert{}); e != nil {
					t.Fatal("same-port desired reconstruction", e)
				}
				applicationReject(t, kind, nc, applicationOldUUID, origin)
				applicationEchoUser(t, kind, nc, applicationKeptUUID, origin)
				if rebind {
					applicationEchoUser(t, kind, nc, applicationNewUUID, origin)
				}
				after, _, _, e := x.GetUserTraffic(context.Background())
				if e != nil || after[1][0] < tail[1][0] || after[1][1] < tail[1][1] {
					t.Fatal("restart reset cumulative history", after, e)
				}
			})
		}
	}
}

type failingApplicationManager struct {
	xrayProxy.UserManager
	failAt      int
	calls       int
	removeCalls int
}

func (m *failingApplicationManager) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	m.calls++
	if m.calls == m.failAt {
		return errors.New("synthetic-user-manager-failure")
	}
	return m.UserManager.AddUser(ctx, u)
}
func (m *failingApplicationManager) RemoveUser(ctx context.Context, email string) error {
	m.removeCalls++
	return errors.New("synthetic-remove-must-not-be-called")
}
func TestXrayCandidateConversionBeforeActualAddAndPartialErrorLeavesBookkeepingUnconfirmed(t *testing.T) {
	for _, kind := range []string{"vless", "vmess"} {
		t.Run(kind, func(t *testing.T) {
			x, nc, users, origin := applicationKernel(t, kind)
			x.mu.Lock()
			manager, e := x.getUserManager()
			x.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			fault := &failingApplicationManager{UserManager: manager, failAt: 2}
			x.userManagerOverride = func() (xrayProxy.UserManager, error) { return fault, nil }
			valid := model.UserSpec{ID: 3, UUID: applicationNewUUID}
			invalid := model.UserSpec{ID: 4, UUID: "invalid-secret-input-must-not-leak"}
			a, e := x.AddUsers([]model.UserSpec{valid, invalid})
			if a != 0 || !errors.Is(e, ErrUserConversion) || fault.calls != 0 {
				t.Fatal("validation mutated manager", a, e, fault.calls)
			}
			if e.Error() != "XRAY_USER_CONVERSION_FAILED" {
				t.Fatal("conversion error leaked credentials")
			}
			fourth := model.UserSpec{ID: 4, UUID: applicationFourthUUID}
			a, e = x.AddUsers([]model.UserSpec{valid, fourth})
			if a != 1 || !errors.Is(e, ErrUserOperation) {
				t.Fatal("actual partial count or operation error wrong", a, e)
			}
			x.mu.Lock()
			localCount := len(x.users)
			x.mu.Unlock()
			if localCount != 2 {
				t.Fatal("partial manager error falsely advanced local users")
			}
			if fault.GetUser(context.Background(), userEmail(3)) == nil || fault.GetUser(context.Background(), userEmail(4)) != nil {
				t.Fatal("partial manager proof not actual")
			}
			if r, e := x.RemoveUsers([]model.UserSpec{users[0]}); r != 0 || !errors.Is(e, ErrUserReconstructionRequired) || fault.removeCalls != 0 {
				t.Fatal("weak manager removal used despite strong revoke requirement")
			}
			x.Stop()
			x.userManagerOverride = nil
			desired := append(append([]model.UserSpec{}, users...), valid, fourth)
			if e := x.Start(nc, desired, kernel.TLSCert{}); e != nil {
				t.Fatal(e)
			}
			applicationEchoUser(t, kind, nc, valid.UUID, origin)
			applicationEchoUser(t, kind, nc, fourth.UUID, origin)
			applicationEchoUser(t, kind, nc, users[1].UUID, origin)
		})
	}
}

func TestXrayPartialUpdateAddReturnsActualCountAndPreservesPreviousBookkeeping(t *testing.T) {
	x, nc, users, origin := applicationKernel(t, "vless")
	x.mu.Lock()
	manager, err := x.getUserManager()
	originalHash := x.lastKernelHash
	x.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	fault := &failingApplicationManager{UserManager: manager, failAt: 2}
	x.userManagerOverride = func() (xrayProxy.UserManager, error) { return fault, nil }
	desired := append(append([]model.UserSpec(nil), users...), model.UserSpec{ID: 3, UUID: applicationNewUUID}, model.UserSpec{ID: 4, UUID: applicationFourthUUID})
	added, removed, err := x.UpdateUsers(desired)
	if added != 1 || removed != 0 || !errors.Is(err, ErrUserOperation) {
		t.Fatal("Update partial result falsely successful", added, removed, err)
	}
	x.mu.Lock()
	unchanged := len(x.users) == len(users) && x.lastKernelHash == originalHash
	x.mu.Unlock()
	if !unchanged {
		t.Fatal("partial update changed local applied facts")
	}
	x.Stop()
	x.userManagerOverride = nil
	if err := x.Start(nc, desired, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	applicationEchoUser(t, "vless", nc, applicationNewUUID, origin)
	applicationEchoUser(t, "vless", nc, applicationFourthUUID, origin)
}

func TestXrayLastUserRemovalClosesActualStreamAndRetainsStoppedMeter(t *testing.T) {
	for _, kind := range []string{"vless", "vmess"} {
		t.Run(kind, func(t *testing.T) {
			x, nc, users, origin := applicationKernel(t, kind)
			x.Stop()
			if e := x.Start(nc, users[:1], kernel.TLSCert{}); e != nil {
				t.Fatal(e)
			}
			stream, e := applicationDial(kind, nc, applicationOldUUID, origin)
			if e != nil {
				t.Fatal(e)
			}
			defer stream.Close()
			payload := []byte("last-xray-user-tail")
			applicationRoundtrip(t, stream, payload)
			removed, e := x.RemoveUsers(users[:1])
			if removed != 1 || e != nil || x.IsRunning() {
				t.Fatal("last-user removal not actual stop", removed, e)
			}
			applicationClosed(t, stream)
			tail, _, count, e := x.GetUserTraffic(context.Background())
			if e != nil || count != 0 || tail[1] != [2]int64{int64(len(payload)), int64(len(payload))} {
				t.Fatal("last-user stop lost or duplicated actual meter", tail, count, e)
			}
			x.mu.Lock()
			empty := len(x.users) == 0
			x.mu.Unlock()
			if !empty {
				t.Fatal("last-user successful stop not reflected in users")
			}
		})
	}
}
func TestXrayInvalidReplacementCannotLeaveOldInstanceServing(t *testing.T) {
	x, nc, users, origin := applicationKernel(t, "vless")
	stream, e := applicationDial("vless", nc, applicationOldUUID, origin)
	if e != nil {
		t.Fatal(e)
	}
	defer stream.Close()
	payload := []byte("failed-rebuild-tail")
	applicationRoundtrip(t, stream, payload)
	invalid := []model.UserSpec{{ID: 1, UUID: "private-invalid-credential-over-thirty-six-characters"}}
	if e := x.Start(nc, invalid, kernel.TLSCert{}); !errors.Is(e, ErrUserConversion) {
		t.Fatal("invalid replacement accepted", e)
	}
	if x.IsRunning() {
		t.Fatal("old instance remained serving after failed rebuild")
	}
	applicationClosed(t, stream)
	if conn, e := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(nc.ServerPort)), 100*time.Millisecond); e == nil {
		conn.Close()
		t.Fatal("failed replacement left listener")
	}
	tail, _, _, _ := x.GetUserTraffic(context.Background())
	if tail[1] != [2]int64{int64(len(payload)), int64(len(payload))} {
		t.Fatal("failed rebuild lost final meter", tail)
	}
	if e := x.Start(nc, users, kernel.TLSCert{}); e != nil {
		t.Fatal("identical desired retry", e)
	}
	applicationEchoUser(t, "vless", nc, applicationKeptUUID, origin)
}
