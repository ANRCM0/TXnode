package service

import (
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const liveProtocolUUID = "00112233-4455-6677-8899-aabbccddeeff"

func liveProtocolDial(t *testing.T, protocol, address, uuid string, destination M.Socksaddr) (*net.TCPConn, net.Conn) {
	t.Helper()
	dialer := net.Dialer{Timeout: 2 * time.Second}
	socket, err := dialer.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := socket.(*net.TCPConn)
	if !ok {
		socket.Close()
		t.Fatal("non-TCP fixture client")
	}
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	var conn net.Conn
	if protocol == "vless" {
		client, e := vless.NewClient(uuid, "", logger.NOP())
		if e != nil {
			raw.Close()
			t.Fatal(e)
		}
		conn, err = client.DialConn(raw, destination)
	} else {
		client, e := vmess.NewClient(uuid, "aes-128-gcm", 0)
		if e != nil {
			raw.Close()
			t.Fatal(e)
		}
		conn, err = client.DialConn(raw, destination)
	}
	if err != nil {
		raw.Close()
		t.Fatal("locked protocol DialConn", err)
	}
	return raw, conn
}

func liveProtocolWait(t *testing.T, done <-chan error, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if ready() {
			return
		}
		select {
		case err := <-done:
			t.Fatal("Service terminated before protocol evidence", err)
		case <-deadline.C:
			t.Fatal("live protocol evidence timeout")
		case <-tick.C:
		}
	}
}

func liveProtocolDecode(t *testing.T, path string, target any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || len(body) > 1<<20 || json.Unmarshal(body, target) != nil {
		t.Fatal("bounded fixture metadata unavailable", path, err)
	}
}
