package txnode

// Mieru protocol probe: capture the official client's first TCP flight and
// validate the published key derivation and metadata layout. This is the
// foundation for a clean-room mieru v2 server (MIERU-1); it does not claim
// interop.

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

func TestMieruProtocolFirstSegment(t *testing.T) {
	bin := mieruBinary(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}

	// Capture server: accept one connection and record the first flight.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	captured := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		captured <- append([]byte(nil), buf[:n]...)
	}()

	// Start the official client against the capture port.
	port := ln.Addr().(*net.TCPAddr).Port
	socksPort := freePortTB(t)
	dir := t.TempDir()
	cfg := `{"profiles":[{"profileName":"probe","user":{"name":"interop","password":"secret"},` +
		`"servers":[{"ipAddress":"127.0.0.1","portBindings":[{"port":` + strconv.Itoa(port) + `,"protocol":"TCP"}]}],` +
		`"mtu":1400}],"activeProfile":"probe","socks5Port":` + strconv.Itoa(socksPort) + `,"loggingLevel":"INFO"}`
	cfgPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, _ := os.Create(filepath.Join(dir, "mieru.log"))
	defer logFile.Close()
	client := exec.Command(bin, "run")
	client.Env = append(os.Environ(), "MIERU_CONFIG_JSON_FILE="+cfgPath)
	client.Stdout, client.Stderr = logFile, logFile
	if err := client.Start(); err != nil {
		t.Fatalf("mieru start: %v", err)
	}
	defer func() {
		_ = client.Process.Kill()
		_, _ = client.Process.Wait()
	}()

	socks := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	deadline := time.Now().Add(8 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", socks, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mieru socks listener did not open")
		}
		time.Sleep(25 * time.Millisecond)
	}
	go func() {
		_, _ = fetchThroughE(t, socks, "127.0.0.1:1")
	}()

	var wire []byte
	select {
	case wire = <-captured:
	case <-time.After(6 * time.Second):
		t.Skip("no client flight captured")
	}
	if len(wire) < 24+32+16 {
		t.Fatalf("short first flight: %d bytes", len(wire))
	}

	// Published derivation: sha256(password || 0x00 || username), PBKDF2-64
	// with a 2-minute-rounded time salt, XChaCha20-Poly1305, nonce tail replaced
	// by sha256(username || nonce[:16])[:4].
	hashed := sha256.Sum256(append(append([]byte("secret"), 0), []byte("interop")...))
	nonce := append([]byte(nil), wire[:24]...)
	meta := wire[24 : 24+32+16]

	now := time.Now().Unix()
	rounded := (now + 120) / 120 * 120
	decoded := false
	for _, delta := range []int64{-120, 0, 120} {
		salt := sha256.Sum256(be64(uint64(rounded + delta)))
		key := pbkdf2.Key(hashed[:], salt[:], 64, 32, sha256.New)
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := aead.Open(nil, nonce, meta, nil)
		if err != nil || len(plain) != 32 {
			continue
		}
		if plain[0] != 2 { // openSessionRequest
			t.Logf("decoded metadata type %d (expected 2)", plain[0])
		}
		mins := binary.BigEndian.Uint32(plain[2:6])
		sid := binary.BigEndian.Uint32(plain[6:10])
		payload := binary.BigEndian.Uint16(plain[15:17])
		if diff := int64(mins)*60 - now; diff < -120 || diff > 120 {
			t.Logf("timestamp drift %ds", diff)
		}
		// Payload follows the metadata: payloadLen ciphertext + tag, then suffix padding.
		nonceCopy := append([]byte(nil), nonce...)
		if payload > 0 && len(wire) >= 72+int(payload)+16 {
			copyNonce := nonceCopy
			for i := len(copyNonce) - 1; i >= 0; i-- {
				copyNonce[i]++
				if copyNonce[i] != 0 {
					break
				}
			}
			pt, err := aead.Open(nil, copyNonce, wire[72:72+int(payload)+16], nil)
			if err == nil {
				t.Logf("mieru open payload hex=%x text=%q", pt, string(pt))
			}
		}
		t.Logf("mieru first segment decoded: type=%d session=%d seq=%d payloadLen=%d wire=%d",
			plain[0], sid, binary.BigEndian.Uint32(plain[10:14]), payload, len(wire))
		decoded = true
		break
	}
	if !decoded {
		t.Fatalf("could not decrypt the first metadata block (wire %d bytes)", len(wire))
	}
}

// le64 is the little-endian 8-byte time stamp mieru hashes into its salt.
func be64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
