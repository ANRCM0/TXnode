package service

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// liveProtocolDial dials a running node and speaks SOCKS5 (RFC1928/1929) to the
// requested destination. The sing-box data plane is gone, and the native data
// plane ships no client, so the service integration tests drive real traffic
// through the node's SOCKS5 inbound.
//
// The password is the panel user's UUID (the sample ignores the username). The
// returned raw socket is the TCP connection to the node; stream is the same
// connection after the CONNECT succeeded.
func liveProtocolDial(t *testing.T, protocol, address, uuid string, destination net.Addr) (*net.TCPConn, net.Conn) {
	t.Helper()
	if protocol != "socks" && protocol != "socks5" {
		t.Fatalf("fixture speaks socks5, got protocol %q", protocol)
	}
	socket, err := net.DialTimeout("tcp4", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := socket.(*net.TCPConn)
	if !ok {
		_ = socket.Close()
		t.Fatal("non-TCP fixture client")
	}
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := raw.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(raw, method[:]); err != nil || method[1] != 0x02 {
		t.Fatalf("socks method reply: %v %v", method, err)
	}
	auth := append([]byte{0x01, byte(len("fixture"))}, []byte("fixture")...)
	auth = append(auth, byte(len(uuid)))
	auth = append(auth, uuid...)
	if _, err := raw.Write(auth); err != nil {
		t.Fatal(err)
	}
	var authReply [2]byte
	if _, err := io.ReadFull(raw, authReply[:]); err != nil || authReply[1] != 0x00 {
		t.Fatalf("socks auth reply: %v %v", authReply, err)
	}

	host, portStr, err := net.SplitHostPort(destination.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host).To4(); ip != nil {
		req = append(req, 0x01)
		req = append(req, ip...)
	} else {
		if len(host) > 255 {
			t.Fatal("destination host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := raw.Write(req); err != nil {
		t.Fatal(err)
	}
	var head [4]byte
	if _, err := io.ReadFull(raw, head[:]); err != nil || head[1] != 0x00 {
		t.Fatalf("socks connect reply: %v %v", head, err)
	}
	switch head[3] {
	case 0x01:
		var tail [6]byte
		if _, err := io.ReadFull(raw, tail[:]); err != nil {
			t.Fatal(err)
		}
	case 0x04:
		var tail [18]byte
		if _, err := io.ReadFull(raw, tail[:]); err != nil {
			t.Fatal(err)
		}
	default:
		var l [1]byte
		if _, err := io.ReadFull(raw, l[:]); err != nil {
			t.Fatal(err)
		}
		var tail = make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(raw, tail); err != nil {
			t.Fatal(err)
		}
	}
	_ = raw.SetDeadline(time.Time{})
	return raw, raw
}

// liveProtocolWait waits for a node to accept connections while failing fast if
// the Service terminates first.
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
