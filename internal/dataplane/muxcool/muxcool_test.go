package muxcool

// Unit coverage for the Mux.Cool framing. Xray interop in
// internal/kernel/txnode is the wire-level authority; these tests keep the
// frame parser/writer and the session stream covered without a third-party
// binary.

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

func TestMetadataRoundTrip(t *testing.T) {
	for _, dest := range []socks.Addr{
		{Host: "127.0.0.1", Port: 8080},
		{Host: "example.com", Port: 443},
		{Host: "::1", Port: 8443},
	} {
		var buf bytes.Buffer
		if err := writeMetadata(&buf, &Metadata{SessionID: 7, Status: StatusNew, Dest: dest}); err != nil {
			t.Fatalf("write %v: %v", dest, err)
		}
		got, err := readMetadata(&buf)
		if err != nil {
			t.Fatalf("read %v: %v", dest, err)
		}
		if got.SessionID != 7 || got.Status != StatusNew || got.Network != NetworkTCP {
			t.Fatalf("header %+v", got)
		}
		if got.Dest != dest {
			t.Fatalf("dest = %v, want %v", got.Dest, dest)
		}
	}
}

func TestChunkReader(t *testing.T) {
	var buf bytes.Buffer
	writeChunk := func(p string) {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(p)))
		buf.Write(size[:])
		buf.WriteString(p)
	}
	writeChunk("hello ")
	writeChunk("world")
	// Zero-size chunk is EOF for the body.
	buf.Write([]byte{0, 0})

	got, err := io.ReadAll(&chunkReader{r: &buf})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("chunks = %q", got)
	}
}

// fakeMuxPeer speaks the client half: it writes a NEW frame with a request,
// reads the response chunks, then the End frame.
type fakeMuxPeer struct {
	conn net.Conn
}

func (p *fakeMuxPeer) newSession(id uint16, dest socks.Addr, body []byte) error {
	var buf bytes.Buffer
	// Option=Data makes the body follow as chunks.
	if err := writeMetadata(&buf, &Metadata{SessionID: id, Status: StatusNew, Option: OptionData, Dest: dest}); err != nil {
		return err
	}
	if _, err := p.conn.Write(buf.Bytes()); err != nil {
		return err
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(body)))
	if _, err := p.conn.Write(size[:]); err != nil {
		return err
	}
	_, err := p.conn.Write(body)
	return err
}

func TestServeRelaysSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = Serve(conn, func(id uint16, dest socks.Addr, stream *Stream) error {
			if id != 9 || dest.Port != 53 {
				t.Errorf("session id=%d dest=%v", id, dest)
			}
			buf := make([]byte, 5)
			if _, err := io.ReadFull(stream, buf); err != nil {
				return err
			}
			if string(buf) != "query" {
				t.Errorf("request = %q", buf)
			}
			_, _ = stream.Write([]byte("reply"))
			return nil
		})
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer := &fakeMuxPeer{conn: client}
	if err := peer.newSession(9, socks.Addr{Host: "127.0.0.1", Port: 53}, []byte("query")); err != nil {
		t.Fatal(err)
	}
	// Read the KEEP metadata frame, then its chunked body.
	meta, err := readMetadata(client)
	if err != nil {
		t.Fatalf("response metadata: %v", err)
	}
	if meta.SessionID != 9 || meta.Status != StatusKeep || !meta.HasData() {
		t.Fatalf("response frame %+v", meta)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(&chunkReader{r: client}, got); err != nil {
		t.Fatalf("response body: %v", err)
	}
	if string(got) != "reply" {
		t.Fatalf("response = %q", got)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return")
	}
}
