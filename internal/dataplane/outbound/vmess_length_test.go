package outbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	inboundVMess "github.com/ANRCM0/TX-Node/internal/dataplane/proto/vmess"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

func TestAuthenticatedLengthMatchesXrayWireSize(t *testing.T) {
	for _, sec := range []byte{vmessSecAES128GCM, vmessSecChaCha20} {
		t.Run(fmt.Sprint(sec), func(t *testing.T) {
			key, iv := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{3}, 16)
			fresh := func() *vmessCodec {
				c, err := newVMessCodec(sec, key, iv, vmessOptionAuthLength, key, iv)
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			nonce := append([]byte(nil), iv[:12]...)
			binary.BigEndian.PutUint16(nonce[:2], 0)
			writer := fresh()
			sealed, err := writer.sealLen(100)
			if err != nil {
				t.Fatal(err)
			}
			// Inspect the actual AEAD plaintext instead of pairing our helpers.
			plain, err := writer.lenAEAD.Open(nil, nonce, sealed, nil)
			if err != nil || len(plain) != 2 || binary.BigEndian.Uint16(plain) != 84 {
				t.Fatalf("wire size 100 must authenticate BE16(84): %x, %v", plain, err)
			}
			reader := fresh()
			raw := []byte{0, 84}
			incoming := reader.lenAEAD.Seal(nil, nonce, raw, nil)
			if size, err := reader.openLen(incoming); err != nil || size != 100 {
				t.Fatalf("raw BE16(84) must decode to wire size 100: %d, %v", size, err)
			}
			for _, size := range []int{-1, 0, 15} {
				short := fresh()
				if _, err := short.sealLen(size); err == nil || short.lenCount != 0 {
					t.Fatalf("invalid wire size %d accepted or consumed nonce: %v", size, err)
				}
			}
			if _, err := fresh().openLen([]byte{0}); err == nil {
				t.Fatal("truncated authenticated length accepted")
			}
		})
	}
}

// One public Proxy is shared by every caller so Actions -race exercises the
// request builder and its per-connection framing options concurrently.
func TestVMessSharedProxyConcurrentDialTCP(t *testing.T) {
	const uuid = "00112233-4455-4677-8899-aabbccddeeff"
	const connections = 16
	handler, err := inboundVMess.NewHandler(inboundVMess.Options{Users: []core.User{{ID: 7, UUID: uuid}}, Cipher: "aes-128-gcm"})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	deadline := time.Now().Add(10 * time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	destination := socks.Addr{Host: "example.test", Port: 443}
	client, err := New("vmess", opt.Opt{"server": "127.0.0.1", "port": listener.Addr().(*net.TCPAddr).Port, "uuid": uuid, "method": "aes-128-gcm", "network": "tcp", "global_padding": true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	results := make(chan error, 2*connections)
	go func() {
		for i := 0; i < connections; i++ {
			raw, err := listener.AcceptTCP()
			if err != nil {
				results <- fmt.Errorf("accept: %w", err)
				return
			}
			go func() {
				results <- func() error {
					defer raw.Close()
					if err := raw.SetDeadline(deadline); err != nil {
						return err
					}
					session, err := handler.Handle(ctx, raw)
					if err != nil {
						return err
					}
					defer session.Conn.Close()
					if session.UserID != 7 || session.Dest != destination {
						return fmt.Errorf("concurrent request changed identity or destination")
					}
					body := make([]byte, 128)
					if _, err := io.ReadFull(session.Conn, body); err != nil {
						return err
					}
					if n, err := session.Conn.Write(body); err != nil {
						return err
					} else if n != len(body) {
						return io.ErrShortWrite
					}
					return nil
				}()
			}()
		}
	}()
	start := make(chan struct{})
	for i := 0; i < connections; i++ {
		go func(index int) {
			<-start
			results <- func() error {
				stream, err := client.DialTCP(ctx, destination)
				if err != nil {
					return err
				}
				defer stream.Close()
				if err := stream.SetDeadline(deadline); err != nil {
					return err
				}
				payload := bytes.Repeat([]byte{byte(index)}, 128)
				if n, err := stream.Write(payload); err != nil {
					return err
				} else if n != len(payload) {
					return io.ErrShortWrite
				}
				response := make([]byte, len(payload))
				if _, err := io.ReadFull(stream, response); err != nil {
					return err
				}
				if !bytes.Equal(response, payload) {
					return fmt.Errorf("connection %d response mismatch", index)
				}
				return nil
			}()
		}(i)
	}
	close(start)
	for i := 0; i < 2*connections; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("concurrent VMess connection: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent VMess exchange did not finish", ctx.Err())
		}
	}
}
