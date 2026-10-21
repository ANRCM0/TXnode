package mux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

type fixtureConn struct {
	input  *bytes.Reader
	output bytes.Buffer
	short  int
	closed bool
}

func (c *fixtureConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *fixtureConn) Write(p []byte) (int, error) {
	if c.short > 0 && len(p) > c.short {
		p = p[:c.short]
	}
	return c.output.Write(p)
}
func (c *fixtureConn) Close() error                   { c.closed = true; return nil }
func (*fixtureConn) LocalAddr() net.Addr              { return nil }
func (*fixtureConn) RemoteAddr() net.Addr             { return nil }
func (*fixtureConn) SetDeadline(time.Time) error      { return nil }
func (*fixtureConn) SetReadDeadline(time.Time) error  { return nil }
func (*fixtureConn) SetWriteDeadline(time.Time) error { return nil }

// Exact fixtures follow sing-mux caf09fe32475 server_conn.go/client_conn.go.
func TestPinnedPacketFraming(t *testing.T) {
	dest := socks.Addr{Host: "127.0.0.1", Port: 53}
	for _, test := range []struct {
		name              string
		flags             uint16
		request, response []byte
	}{
		{"fixed", FlagUDP, []byte{0, 3, 'a', 'b', 'c', 0, 0}, []byte{0, 0, 3, 'a', 'b', 'c', 0, 0}},
		{"address", FlagUDP | FlagAddr, []byte{1, 127, 0, 0, 1, 0, 53, 0, 3, 'a', 'b', 'c', 1, 127, 0, 0, 1, 0, 53, 0, 0}, []byte{0, 1, 127, 0, 0, 1, 0, 53, 0, 3, 'a', 'b', 'c', 1, 127, 0, 0, 1, 0, 53, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &fixtureConn{input: bytes.NewReader(test.request), short: 2}
			packets := NewServerPackets(conn, test.flags, dest)
			buffer := make([]byte, 32)
			for _, want := range []string{"abc", ""} {
				n, addr, err := packets.ReadPacket(buffer)
				if err != nil || string(buffer[:n]) != want || addr != dest {
					t.Fatalf("read n=%d addr=%v err=%v", n, addr, err)
				}
				if err := packets.WritePacket(buffer[:n], addr); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(conn.output.Bytes(), test.response) {
				t.Fatalf("reply=%x want=%x", conn.output.Bytes(), test.response)
			}
			client := newClientPackets(&fixtureConn{input: bytes.NewReader(test.response)}, test.flags, dest)
			for _, want := range []string{"abc", ""} {
				n, addr, err := client.ReadPacket(buffer)
				if err != nil || string(buffer[:n]) != want || addr != dest {
					t.Fatalf("client payload=%q addr=%v err=%v", buffer[:n], addr, err)
				}
			}
		})
	}
}

func TestPacketFramingBounds(t *testing.T) {
	dest := socks.Addr{Host: "127.0.0.1", Port: 53}
	conn := &fixtureConn{input: bytes.NewReader([]byte{0, 3, 'a', 'b', 'c', 0, 1, 'z'})}
	packets := NewServerPackets(conn, FlagUDP, dest)
	if _, _, err := packets.ReadPacket(make([]byte, 2)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short buffer=%v", err)
	}
	buffer := make([]byte, 1)
	if n, _, err := packets.ReadPacket(buffer); err != nil || n != 1 || buffer[0] != 'z' {
		t.Fatalf("next datagram=%x n=%d err=%v", buffer, n, err)
	}
	if err := packets.WritePacket(make([]byte, 65536), dest); err == nil {
		t.Fatal("oversized datagram accepted")
	}
	if err := packets.WritePacket(make([]byte, 65535), dest); err != nil {
		t.Fatalf("maximum datagram: %v", err)
	}
	truncated := NewServerPackets(&fixtureConn{input: bytes.NewReader([]byte{0, 2, 'x'})}, FlagUDP, dest)
	if _, _, err := truncated.ReadPacket(make([]byte, 8)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated packet=%v", err)
	}
}

type completionPacketConn struct {
	*fixtureConn
	accepted int
	err      error
}

func (c *completionPacketConn) Write(b []byte) (int, error) {
	n := len(b)
	if c.accepted >= 0 && n > c.accepted {
		n = c.accepted
	}
	_, _ = c.output.Write(b[:n])
	return n, c.err
}

func TestPacketWriteCountPreservesErroredPayloadTail(t *testing.T) {
	dest := socks.Addr{Host: "127.0.0.1", Port: 53}
	for _, flags := range []uint16{FlagUDP, FlagUDP | FlagAddr} {
		prefix := 3
		if flags&FlagAddr != 0 {
			prefix += 7
		}
		for _, test := range []struct {
			name     string
			accepted int
			want     int
		}{{"full", -1, 7}, {"partial", prefix + 3, 3}, {"header-only", prefix - 1, 0}} {
			t.Run(fmt.Sprintf("flags-%d/%s", flags, test.name), func(t *testing.T) {
				writeErr := errors.New("parent shutdown after wire acceptance")
				conn := &completionPacketConn{fixtureConn: &fixtureConn{}, accepted: test.accepted, err: writeErr}
				packets := NewServerPackets(conn, flags, dest)
				n, err := packets.WritePacketCount([]byte("payload"), dest)
				if n != test.want || !errors.Is(err, writeErr) || !conn.closed {
					t.Fatalf("payload n=%d err=%v closed=%v want=%d", n, err, conn.closed, test.want)
				}
			})
		}
	}
}

func TestPinnedMuxStreamFlags(t *testing.T) {
	for _, flags := range []uint16{0, FlagUDP, FlagUDP | FlagAddr} {
		var request bytes.Buffer
		dest := socks.Addr{Host: "127.0.0.1", Port: 53}
		if err := WriteStreamRequest(&request, flags, dest); err != nil {
			t.Fatal(err)
		}
		got, addr, err := ReadStreamRequest(&request)
		if err != nil || got != flags || addr != dest {
			t.Fatalf("flags=%x addr=%v err=%v", got, addr, err)
		}
	}
	for _, flags := range []uint16{FlagAddr, 4, 65535} {
		_, _, err := ReadStreamRequest(bytes.NewReader([]byte{byte(flags >> 8), byte(flags)}))
		if err == nil {
			t.Fatalf("flags=%x accepted", flags)
		}
	}
}
