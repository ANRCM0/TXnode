//go:build linux

package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func spliceTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	deadline := time.Now().Add(6 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return client, server
}

func splicePipeTargets(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	targets := make(map[string]bool)
	for _, entry := range entries {
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(target, "pipe:[") {
			targets[target] = true
		}
	}
	return targets
}

func TestSplicePipeHalfCloseAndCancellation(t *testing.T) {
	for _, cancelRelay := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancelRelay), func(t *testing.T) {
			client, left := spliceTCPPair(t)
			origin, right := spliceTCPPair(t)
			before := splicePipeTargets(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var upCount, downCount atomic.Int64
			type result struct {
				used bool
				err  error
			}
			done := make(chan result, 1)
			go func() {
				used, err := splicePipe(ctx, left, right, func(n int64) { upCount.Add(n) }, func(n int64) { downCount.Add(n) })
				done <- result{used, err}
			}()
			upload := bytes.Repeat([]byte("u"), copyBuf*3+17)
			download := bytes.Repeat([]byte("d"), copyBuf*4+31)
			originDone := make(chan error, 1)
			go func() {
				body := make([]byte, len(upload))
				_, err := io.ReadFull(origin, body)
				if err == nil && !bytes.Equal(body, upload) {
					err = errors.New("splice upload mismatch")
				}
				if err == nil && !cancelRelay {
					tail, tailErr := io.ReadAll(origin)
					if tailErr != nil || len(tail) != 0 {
						err = fmt.Errorf("upload half-close: tail=%d err=%v", len(tail), tailErr)
					} else if n, writeErr := origin.Write(download); writeErr != nil || n != len(download) {
						err = fmt.Errorf("download write: n=%d err=%v", n, writeErr)
					}
					_ = origin.CloseWrite()
				}
				originDone <- err
			}()
			if n, err := client.Write(upload); err != nil || n != len(upload) {
				t.Fatalf("upload write: n=%d err=%v", n, err)
			}
			if !cancelRelay {
				if err := client.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(client)
				if err != nil || !bytes.Equal(body, download) {
					t.Fatalf("download after upload FIN: bytes=%d err=%v", len(body), err)
				}
			}
			if err := <-originDone; err != nil {
				t.Fatal(err)
			}
			if cancelRelay {
				cancel()
			}
			select {
			case relay := <-done:
				if !relay.used || relay.err != nil {
					t.Fatalf("splice result: used=%t err=%v", relay.used, relay.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("splice did not finish after half-close or cancellation")
			}
			wantDown := int64(len(download))
			if cancelRelay {
				wantDown = 0
			}
			if upCount.Load() != int64(len(upload)) || downCount.Load() != wantDown {
				t.Fatalf("actual splice bytes: up=%d down=%d", upCount.Load(), downCount.Load())
			}
			for target := range splicePipeTargets(t) {
				if !before[target] {
					t.Fatalf("splice retained pipe after return: %s", target)
				}
			}
		})
	}
}
