package naive

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

type paddingFixtureConn struct {
	net.Conn
	reader   io.Reader
	written  bytes.Buffer
	fragment int
}

func (c *paddingFixtureConn) Read(p []byte) (int, error) {
	if c.fragment > 0 && len(p) > c.fragment {
		p = p[:c.fragment]
	}
	return c.reader.Read(p)
}
func (c *paddingFixtureConn) Write(p []byte) (int, error) {
	if c.fragment > 0 && len(p) > c.fragment {
		p = p[:c.fragment]
	}
	return c.written.Write(p)
}
func (c *paddingFixtureConn) Close() error { return nil }

func TestPaddingReadWireAndRawTransition(t *testing.T) {
	var wire, want bytes.Buffer
	// The first frame is an empty padded chunk; fragmented reads must consume
	// its padding without returning a spurious empty application read.
	wire.Write([]byte{0, 0, 2, 0x81, 0x82})
	for i := byte(1); i < 8; i++ {
		wire.Write([]byte{0, 2, 1, 'a', i, 0x99})
		want.Write([]byte{'a', i})
	}
	wire.WriteString("HTTP/1.1 raw after eight frames")
	want.WriteString("HTTP/1.1 raw after eight frames")
	conn := &paddingConn{Conn: &paddingFixtureConn{reader: bytes.NewReader(wire.Bytes()), fragment: 1}}
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read=%d %v", n, err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("decoded=%q want=%q err=%v", got, want.Bytes(), err)
	}
}

func TestPaddingWriteLargeAndRawTransition(t *testing.T) {
	raw := &paddingFixtureConn{fragment: 7}
	conn := &paddingConn{Conn: raw}
	large := bytes.Repeat([]byte{'x'}, 70000)
	if n, err := conn.Write(large); n != len(large) || err != nil {
		t.Fatalf("large write=%d %v", n, err)
	}
	for i := 0; i < 6; i++ {
		if n, err := conn.Write([]byte("next")); n != 4 || err != nil {
			t.Fatalf("next write=%d %v", n, err)
		}
	}
	raw.fragment = 0
	if _, err := conn.Write([]byte("HTTP/1.1")); err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(raw.written.Bytes())
	for _, size := range []int{65535, 4465, 4, 4, 4, 4, 4, 4} {
		var head [3]byte
		if _, err := io.ReadFull(reader, head[:]); err != nil {
			t.Fatal(err)
		}
		if got := int(binary.BigEndian.Uint16(head[:2])); got != size {
			t.Fatalf("frame payload=%d want=%d", got, size)
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(reader, payload); err != nil {
			t.Fatal(err)
		}
		if size > 4 && !bytes.Equal(payload, bytes.Repeat([]byte{'x'}, size)) {
			t.Fatal("large payload changed")
		}
		if size == 4 && string(payload) != "next" {
			t.Fatalf("payload=%q", payload)
		}
		if _, err := io.CopyN(io.Discard, reader, int64(head[2])); err != nil {
			t.Fatal(err)
		}
	}
	remaining, _ := io.ReadAll(reader)
	if string(remaining) != "HTTP/1.1" {
		t.Fatalf("raw transition=%q", remaining)
	}
}

func TestHTTP1PaddingNegotiationAndBufferedPayload(t *testing.T) {
	for _, padded := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "padded"}[padded], func(t *testing.T) {
			head := "CONNECT example.test:80 HTTP/1.1\r\nHost: example.test:80\r\nProxy-Authorization: user:secret\r\n"
			payload := []byte("GET / HTTP/1.1\r\n\r\n")
			body := payload
			if padded {
				head += "Padding: client-request\r\n"
				body = append([]byte{0, byte(len(payload)), 2}, payload...)
				body = append(body, 0x88, 0x99)
			}
			raw := &paddingFixtureConn{reader: io.MultiReader(strings.NewReader(head+"\r\n"), bytes.NewReader(body))}
			handler, err := NewHandler(Options{Users: []core.User{{ID: 7, UUID: "secret"}}})
			if err != nil {
				t.Fatal(err)
			}
			session, err := handler.Handle(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			if session.UserID != 7 {
				t.Fatalf("user=%d", session.UserID)
			}
			if strings.Contains(raw.written.String(), "Padding:") != padded {
				t.Fatalf("negotiation=%q", raw.written.String())
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(session.Conn, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("request=%q err=%v", got, err)
			}
		})
	}
}
