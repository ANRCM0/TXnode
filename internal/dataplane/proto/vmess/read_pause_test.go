package vmess

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

type pauseCodecConn struct {
	net.Conn
	read  func([]byte) (int, error)
	write func([]byte) (int, error)
}

func (c *pauseCodecConn) Read(p []byte) (int, error)  { return c.read(p) }
func (c *pauseCodecConn) Write(p []byte) (int, error) { return c.write(p) }

func pauseCodecFixture(t *testing.T) (*codec, []byte, int) {
	t.Helper()
	var key, iv [16]byte
	key[0], iv[0] = 3, 7
	option := byte(OptionChunkStream | OptionAuthLength | OptionChunkMasking | OptionGlobalPadding)
	wr, err := newCodec(SecAES128GCM, key, iv, option, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := newCodec(SecAES128GCM, key, iv, option, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	// Fix padding at three bytes so the padding-boundary failure is covered.
	wr.xof, rd.xof = bytes.NewReader([]byte{0, 3}), bytes.NewReader([]byte{0, 3})
	pad, err := wr.nextPadding()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := wr.maskSize(7 + wr.overhead() + pad)
	if err != nil {
		t.Fatal(err)
	}
	lp, err := wr.sealLen(wire)
	if err != nil {
		t.Fatal(err)
	}
	body, err := wr.sealChunk([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	frame := append(append(append([]byte{}, lp...), body...), make([]byte, pad)...)
	return rd, frame, pad
}

func TestVMessPauseAtUntouchedLengthPreservesCipherState(t *testing.T) {
	rd, frame, _ := pauseCodecFixture(t)
	paused := true
	reader := bytes.NewReader(frame)
	c := &pauseCodecConn{read: func(p []byte) (int, error) {
		if paused {
			return 0, core.ErrReadPaused
		}
		return reader.Read(p)
	}}
	v := &vmessConn{conn: c, rd: rd}
	buf := make([]byte, 64)
	if n, err := v.Read(buf); n != 0 || !errors.Is(err, core.ErrReadPaused) || rd.count != 0 || rd.lenCount != 0 || reader.Len() != len(frame) || rd.xof.(*bytes.Reader).Len() != 2 {
		t.Fatalf("frame boundary mutated: n=%d err=%v dataNonce=%d lengthNonce=%d", n, err, rd.count, rd.lenCount)
	}
	paused = false
	if n, err := v.Read(buf); err != nil || string(buf[:n]) != "payload" || rd.count != 1 || rd.lenCount != 1 {
		t.Fatalf("resume corrupt: n=%d err=%v dataNonce=%d lengthNonce=%d", n, err, rd.count, rd.lenCount)
	}
}

func TestVMessPartialFramePauseIsTerminal(t *testing.T) {
	for _, part := range []string{"length", "body-start", "ciphertext", "padding"} {
		t.Run(part, func(t *testing.T) {
			rd, frame, pad := pauseCodecFixture(t)
			cut := 1
			switch part {
			case "body-start":
				cut = rd.lenSize()
			case "ciphertext":
				cut = rd.lenSize() + 1
			case "padding":
				if pad == 0 {
					t.Fatal("fixture needs padding")
				}
				cut = len(frame) - 1
			}
			reader := bytes.NewReader(frame[:cut])
			calls := 0
			c := &pauseCodecConn{read: func(p []byte) (int, error) {
				calls++
				if reader.Len() == 0 {
					return 0, core.ErrReadPaused
				}
				return reader.Read(p)
			}}
			v := &vmessConn{conn: c, rd: rd}
			buf := make([]byte, 64)
			n, err := v.Read(buf)
			if n != 0 || err == nil || errors.Is(err, core.ErrReadPaused) {
				t.Fatalf("partially consumed frame became retryable: n=%d err=%v", n, err)
			}
			oldCalls := calls
			if _, again := v.Read(buf); again != err || calls != oldCalls {
				t.Fatalf("failed frame read again: first=%v again=%v calls=%d/%d", err, again, oldCalls, calls)
			}
		})
	}
}

func TestVMessShortWireWriteNeverReportsWholeFrame(t *testing.T) {
	rd, _, _ := pauseCodecFixture(t)
	c := &pauseCodecConn{write: func(p []byte) (int, error) { return len(p) - 1, nil }}
	v := &vmessConn{conn: c, wr: rd}
	v.hdrOnce.Do(func() { v.hdrWritten = true })
	if n, err := v.Write([]byte("payload")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("partial encrypted frame reported success: %d %v", n, err)
	}
}

func TestVMessShortResponseHeaderStopsPayloadWrite(t *testing.T) {
	calls := 0
	c := &pauseCodecConn{write: func(p []byte) (int, error) { calls++; return len(p) - 1, nil }}
	v := &vmessConn{conn: c}
	if v.ReadPauseSupported() {
		t.Fatal("opaque transport advertised safe pause")
	}
	if n, err := v.Write([]byte("payload")); n != 0 || !errors.Is(err, io.ErrShortWrite) || calls != 1 {
		t.Fatalf("short header allowed payload: %d %v calls=%d", n, err, calls)
	}
	if err := v.PauseRead(); !errors.Is(err, core.ErrReadPauseUnsupported) {
		t.Fatalf("opaque transport claims safe pause: %v", err)
	}
}
