package outbound

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
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

func TestVMessCommandKeyUsesProtocolSalt(t *testing.T) {
	id, err := parseUUID("00112233-4455-4677-8899-aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{uuid: id}
	want := md5.Sum(append(id[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
	unsalted := md5.Sum(id[:])
	if !bytes.Equal(p.cmdKey(), want[:]) || bytes.Equal(p.cmdKey(), unsalted[:]) {
		t.Fatal("VMess command key differs from Xray protocol.NewID")
	}
}

// Real TCP exercises the public outbound, server authentication, response
// header and both independent frame codecs. This is not third-party interop.
func TestVMessClientServerAEADAndBodyFrames(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "chacha20-poly1305", "none", "zero"} {
		for _, framing := range []string{"plain", "masked", "padded"} {
			t.Run(method+"/"+framing, func(t *testing.T) {
				const uuid = "00112233-4455-4677-8899-aabbccddeeff"
				handler, err := inboundVMess.NewHandler(inboundVMess.Options{Users: []core.User{{ID: 7, UUID: uuid}}, Cipher: method})
				if err != nil {
					t.Fatal(err)
				}
				listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				deadline := time.Now().Add(5 * time.Second)
				listener.SetDeadline(deadline)
				destination := socks.Addr{Host: "example.test", Port: 443}
				requests := [][]byte{[]byte("first"), bytes.Repeat([]byte{0xa7}, 4097), bytes.Repeat([]byte("multi-frame"), 7000)}
				responses := [][]byte{[]byte("independent response"), bytes.Repeat([]byte{0x3c}, 2051), bytes.Repeat([]byte{0x5d}, 32769)}
				serverDone := make(chan error, 1)
				go func() {
					serverDone <- func() error {
						raw, err := listener.AcceptTCP()
						if err != nil {
							return err
						}
						defer raw.Close()
						raw.SetDeadline(deadline)
						session, err := handler.Handle(context.Background(), raw)
						if err != nil {
							return err
						}
						if session.UserID != 7 || session.Dest != destination || session.Packets != nil {
							return errors.New("VMess request changed its authenticated identity or destination")
						}
						defer session.Conn.Close()
						for i, request := range requests {
							body := make([]byte, len(request))
							if _, err := io.ReadFull(session.Conn, body); err != nil {
								return fmt.Errorf("request %d: %w", i, err)
							}
							if !bytes.Equal(body, request) {
								return fmt.Errorf("request %d changed payload bytes", i)
							}
							if n, err := session.Conn.Write(responses[i]); err != nil || n != len(responses[i]) {
								return fmt.Errorf("response %d write: n=%d err=%v", i, n, err)
							}
						}
						return nil
					}()
				}()
				settings := opt.Opt{"server": "127.0.0.1", "port": listener.Addr().(*net.TCPAddr).Port, "uuid": uuid, "method": method, "network": "tcp"}
				if framing != "plain" {
					settings["chunk_masking"] = true
				}
				if framing == "padded" {
					settings["global_padding"] = true
				}
				client, err := New("vmess", settings)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithDeadline(t.Context(), deadline)
				defer cancel()
				stream, err := client.DialTCP(ctx, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				stream.SetDeadline(deadline)
				for i, request := range requests {
					if n, err := stream.Write(request); err != nil || n != len(request) {
						t.Fatalf("request %d: n=%d err=%v", i, n, err)
					}
					body := make([]byte, len(responses[i]))
					if _, err := io.ReadFull(stream, body); err != nil || !bytes.Equal(body, responses[i]) {
						t.Fatalf("response %d mismatch: %v", i, err)
					}
				}
				select {
				case err := <-serverDone:
					if err != nil {
						t.Fatal("VMess server rejected client", err)
					}
				case <-ctx.Done():
					t.Fatal("VMess server did not finish", ctx.Err())
				}
			})
		}
	}
}

func TestVMessLengthAndBodyNonceSequencesAreIndependent(t *testing.T) {
	key, iv := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{3}, 16)
	c, err := newVMessCodec(vmessSecAES128GCM, key, iv, vmessOptionAuthLength, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if _, err := c.sealLen(20); err != nil || c.lenCount != uint16(i) || c.count != uint16(i-1) {
			t.Fatal("length advanced body nonce", err)
		}
		if _, err := c.sealChunk([]byte("body")); err != nil || c.count != uint16(i) || c.lenCount != uint16(i) {
			t.Fatal("body advanced length nonce", err)
		}
	}
}

type vmessShortWriter struct{}

func (vmessShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestVMessRequestRejectsShortHeaderWrite(t *testing.T) {
	id, err := parseUUID("00112233-4455-4677-8899-aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{uuid: id, security: vmessSecAES128GCM}
	if _, err := p.vmessRequest(vmessShortWriter{}, socks.Addr{Host: "example.test", Port: 443}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short header write accepted: %v", err)
	}
}
