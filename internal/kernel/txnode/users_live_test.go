package txnode

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

type fixedUserHandler struct{ id int }

func (h fixedUserHandler) Handle(context.Context, net.Conn) (*core.Session, error) {
	return &core.Session{UserID: h.id}, nil
}

func handlerSessionForUser(t *testing.T, h *liveHandler, id int) (*core.Session, error) {
	t.Helper()
	state := h.state.Load()
	h.state.Store(&liveHandlerState{handler: fixedUserHandler{id: id}, security: state.security, credentials: state.credentials})
	return h.Handle(t.Context(), nil)
}

func TestLiveHandlerKeepsUnchangedUserAuthentication(t *testing.T) {
	users := []core.User{{ID: 1, UUID: "first"}}
	h, err := newLiveHandler(&spec{Protocol: "socks5"}, users, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	sess, err := handlerSessionForUser(t, h, 1)
	if err != nil || sess.AuthValid == nil || !sess.AuthValid() {
		t.Fatalf("initial auth: %v", err)
	}
	if err := h.SetUsers(append(users, core.User{ID: 2, UUID: "second"})); err != nil {
		t.Fatal(err)
	}
	if !sess.AuthValid() {
		t.Fatal("unrelated user addition revoked existing mux authentication")
	}
	if err := h.SetUsers([]core.User{{ID: 2, UUID: "second"}}); err != nil {
		t.Fatal(err)
	}
	if sess.AuthValid() {
		t.Fatal("removed user authentication remains valid")
	}
	if err := h.SetUsers(users); err != nil {
		t.Fatal(err)
	}
	if sess.AuthValid() {
		t.Fatal("readding credential revived revoked authentication")
	}
	restored, err := handlerSessionForUser(t, h, 1)
	if err != nil || !restored.AuthValid() {
		t.Fatalf("new authentication failed after readd: %v", err)
	}
	h.Retire()
	if restored.AuthValid() {
		t.Fatal("retired runtime authentication remains valid")
	}
}

func TestLiveHandlerRejectsUnidentifiedUser(t *testing.T) {
	for _, id := range []int{0, -1, 999} {
		h, err := newLiveHandler(&spec{Protocol: "socks5"}, []core.User{{ID: 1, UUID: "first"}}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		if sess, err := handlerSessionForUser(t, h, id); err != errCredentialsChanged || sess != nil {
			t.Fatalf("unidentified user %d accepted: sess=%v err=%v", id, sess, err)
		}
	}
}

func socksCredentialAccepted(t *testing.T, port int, secret string) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		return false
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{5, 2} {
		return false
	}
	request := append([]byte{1, 1, 'u', byte(len(secret))}, secret...)
	if _, err := c.Write(request); err != nil {
		return false
	}
	_, err = io.ReadFull(c, reply[:])
	return err == nil && reply == [2]byte{1, 0}
}

// Exercise listener construction and the public mutation methods, so missing
// production wiring cannot be hidden by assigning a private handler in a test.
func TestKernelHotUserCredentials(t *testing.T) {
	k := New(RuntimeConfig{TrustedProxies: "private", HandshakeTimeout: time.Second})
	port := freePortTB(t)
	if err := k.Start(&model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}, []model.UserSpec{{ID: 1, UUID: "first"}}, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer k.Stop()
	if !socksCredentialAccepted(t, port, "first") {
		t.Fatal("initial credential rejected")
	}
	if _, err := k.AddUsers([]model.UserSpec{{ID: 2, UUID: "added"}}); err != nil {
		t.Fatal(err)
	}
	if !socksCredentialAccepted(t, port, "added") {
		t.Fatal("new credential absent from listener")
	}
	if _, _, err := k.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "rotated"}, {ID: 2, UUID: "added"}}); err != nil {
		t.Fatal(err)
	}
	if socksCredentialAccepted(t, port, "first") {
		t.Fatal("old credential accepted after rotation")
	}
	if !socksCredentialAccepted(t, port, "rotated") {
		t.Fatal("rotated credential rejected")
	}
	if _, err := k.RemoveUsers([]model.UserSpec{{ID: 2}}); err != nil {
		t.Fatal(err)
	}
	if socksCredentialAccepted(t, port, "added") {
		t.Fatal("removed credential accepted")
	}
	if _, _, err := k.UpdateUsers(nil); err != nil {
		t.Fatal(err)
	}
	if socksCredentialAccepted(t, port, "rotated") {
		t.Fatal("empty user table still authenticates")
	}
	if _, err := k.AddUsers([]model.UserSpec{{ID: 3, UUID: "restored"}}); err != nil {
		t.Fatal(err)
	}
	if !socksCredentialAccepted(t, port, "restored") {
		t.Fatal("listener failed to recover from empty users")
	}
}

func TestKernelTrackerDeviceGateAdmission(t *testing.T) {
	k := New(RuntimeConfig{})
	k.SetDeviceLimitFunc(func(string) (int, bool) { return 1, true })
	if _, err := k.AddUsers([]model.UserSpec{{ID: 1, UUID: "u"}}); err != nil {
		t.Fatal(err)
	}
	first, ok := k.tracker.Acquire(1, mustAddr("192.0.2.20"), nil)
	if !ok {
		t.Fatal("first device refused")
	}
	defer first.Release()
	for _, ip := range []string{"192.0.2.30", "192.0.2.10"} {
		if lease, ok := k.tracker.Acquire(1, mustAddr(ip), nil); ok {
			lease.Release()
			t.Fatalf("new device %s bypassed gate", ip)
		}
	}
	k.UpdateGlobalDevices(map[int][]string{1: {"192.0.2.10", "192.0.2.20"}})
	if lease, ok := k.tracker.Acquire(1, mustAddr("192.0.2.10"), nil); ok {
		lease.Release()
		t.Fatal("panel-known device exceeded live local quota")
	}
	if got := k.tracker.Alive()[1]; len(got) != 1 {
		t.Fatalf("refused devices persisted: %v", got)
	}
}

func TestKernelRevokesLiveSessionsAndRetainsTraffic(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		name := "remove"
		if rotate {
			name = "rotate"
		}
		t.Run(name, func(t *testing.T) {
			origin, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			go func() {
				c, err := origin.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
			k := New(RuntimeConfig{TrustedProxies: "private", HandshakeTimeout: time.Second})
			port := freePortTB(t)
			if err := k.Start(&model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}, []model.UserSpec{{ID: 1, UUID: "first"}}, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			defer k.Stop()
			c := socksConnectTB(t, port, "first", origin.Addr().String())
			defer c.Close()
			if _, err := c.Write([]byte("tail")); err != nil {
				t.Fatal(err)
			}
			var response [4]byte
			if _, err := io.ReadFull(c, response[:]); err != nil {
				t.Fatal(err)
			}
			if rotate {
				if _, _, err := k.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "second"}}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := k.RemoveUsers([]model.UserSpec{{ID: 1}}); err != nil {
					t.Fatal(err)
				}
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if _, err := c.Read(b[:]); err == nil {
				t.Fatal("revoked connection stayed open")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("revoked connection timed out instead of closing")
			}
			deadline := time.Now().Add(time.Second)
			for {
				traffic, _, _, err := k.GetUserTraffic(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if got := traffic[1]; got[0] >= 4 && got[1] >= 4 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("revoked traffic lost: %v", traffic)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestLiveHandlerRejectsHandshakeAcrossRotation(t *testing.T) {
	h, err := newLiveHandler(&spec{Protocol: "socks5"}, []core.User{{ID: 1, UUID: "first"}}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := h.Handle(t.Context(), server); done <- err }()
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(append([]byte{1, 1, 'u', 5}, "first"...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply != [2]byte{1, 0} {
		t.Fatalf("auth = %v, %v", reply, err)
	}
	if err := h.SetUsers([]core.User{{ID: 1, UUID: "new"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	var connected [10]byte
	if _, err := io.ReadFull(client, connected[:]); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != errCredentialsChanged {
			t.Fatalf("obsolete handshake result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake did not finish")
	}
}

func TestKernelDeviceGateUsesRuntimeLimitAndIPv6Prefix(t *testing.T) {
	k := New(RuntimeConfig{DeviceLimit: 1, DeviceIPv6Prefix: 128})
	if _, err := k.AddUsers([]model.UserSpec{{ID: 1, UUID: "u"}}); err != nil {
		t.Fatal(err)
	}
	first, ok := k.tracker.Acquire(1, mustAddr("2001:db8::1"), nil)
	if !ok {
		t.Fatal("first IPv6 device refused")
	}
	defer first.Release()
	if lease, ok := k.tracker.Acquire(1, mustAddr("2001:db8::2"), nil); ok {
		lease.Release()
		t.Fatal("runtime limit or IPv6 prefix ignored")
	}
}
