//go:build linux

package service

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func nativeC2Decode(t *testing.T, path string, target any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || len(body) > 1<<20 || json.Unmarshal(body, target) != nil {
		t.Fatal("bounded native C2 metadata unavailable", path, err)
	}
}

func nativeC2VLESSDial(t *testing.T, address, uuid string, destination net.Addr) (net.Conn, net.Conn) {
	t.Helper()
	raw, err := net.DialTimeout("tcp4", address, 2*time.Second)
	if err != nil {
		t.Fatal("native C2 VLESS connection failed", err)
	}
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	stream, err := nativeC2VLESSClient(raw, uuid, destination)
	if err != nil {
		_ = raw.Close()
		t.Fatal("native C2 VLESS request failed", err)
	}
	return raw, stream
}

// The fixture speaks the VLESS wire format directly, keeping retired clients
// out of both the test module and the node runtime.
func nativeC2VLESSClient(raw net.Conn, uuid string, destination net.Addr) (net.Conn, error) {
	key, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil || len(key) != 16 {
		return nil, errors.New("invalid native C2 VLESS credential")
	}
	host, portText, err := net.SplitHostPort(destination.String())
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	ip := net.ParseIP(host).To4()
	if err != nil || port <= 0 || port > 65535 || ip == nil {
		return nil, errors.New("native C2 requires an IPv4 TCP origin")
	}
	header := append([]byte{0}, key...)
	header = append(header, 0, 1) // No addons; TCP command.
	header = binary.BigEndian.AppendUint16(header, uint16(port))
	header = append(header, 1) // IPv4 address.
	header = append(header, ip...)
	n, err := raw.Write(header)
	if err == nil && n != len(header) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return nil, err
	}
	return &nativeC2VLESSConn{Conn: raw}, nil
}

type nativeC2VLESSConn struct {
	net.Conn
	response sync.Once
	readErr  error
}

func (c *nativeC2VLESSConn) Read(p []byte) (int, error) {
	c.response.Do(func() {
		var header [2]byte
		if _, c.readErr = io.ReadFull(c.Conn, header[:]); c.readErr != nil {
			return
		}
		if header[0] != 0 {
			c.readErr = errors.New("invalid native C2 VLESS response version")
			return
		}
		_, c.readErr = io.CopyN(io.Discard, c.Conn, int64(header[1]))
	})
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(p)
}
