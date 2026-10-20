package tuic

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

func TestUDPRelayOwnsDestinationDial(t *testing.T) {
	const uuid = "00112233-4455-4677-8899-aabbccddeeff"
	relayDone := make(chan error, 1)
	dest := socks.Addr{Host: "must-not-resolve.invalid", Port: 53}
	srv, err := NewServer(Options{TLSConfig: &tls.Config{}, Users: []core.User{{ID: 7, UUID: uuid + ":secret"}}, Relay: func(ctx context.Context, sess *core.Session) error {
		if sess.Conn != nil || sess.Packets == nil || sess.UserID != 7 || sess.AuthValid == nil || !sess.AuthValid() {
			relayDone <- errors.New("relay session lacks authenticated packet ownership")
			return nil
		}
		buf := make([]byte, 32)
		n, got, err := sess.Packets.ReadPacket(buf)
		if err == nil && (string(buf[:n]) != "hello" || got != dest) {
			err = errors.New("packet payload or destination changed")
		}
		relayDone <- err
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := parseUUID(uuid)
	c := &client{srv: srv, authed: true, userID: 7, userValid: srv.credentialValidity[id], ctx: context.Background(), sessions: make(map[uint16]*udpSession)}
	defer c.closeAll()
	c.deliverPacket(&frame{assocID: 1, hasAddr: true, addr: dest, payload: []byte("hello")})
	select {
	case err := <-relayDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP did not reach unified relay before any destination dial")
	}
}
