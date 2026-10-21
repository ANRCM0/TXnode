//go:build linux

package core

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

type spliceDrainRawConn struct {
	write func(func(uintptr) bool) error
}

func (c spliceDrainRawConn) Control(func(uintptr)) error      { panic("unexpected Control") }
func (c spliceDrainRawConn) Read(func(uintptr) bool) error    { panic("unexpected Read") }
func (c spliceDrainRawConn) Write(f func(uintptr) bool) error { return c.write(f) }

func spliceDrainPipe(t *testing.T) *[2]int {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	return &fds
}

func TestDrainSplicePipeCountsPartialBeforeFailure(t *testing.T) {
	for _, failure := range []error{net.ErrClosed, context.Canceled, unix.EPIPE} {
		t.Run(failure.Error(), func(t *testing.T) {
			source, target := spliceDrainPipe(t), spliceDrainPipe(t)
			page := os.Getpagesize()
			for _, fd := range []int{source[1], target[1]} {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETPIPE_SZ, 2*page); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := unix.Write(source[1], make([]byte, 2*page)); err != nil || n != 2*page {
				t.Fatalf("fill source: n=%d err=%v", n, err)
			}
			if n, err := unix.Write(target[1], make([]byte, page)); err != nil || n != page {
				t.Fatalf("fill target: n=%d err=%v", n, err)
			}
			calls := 0
			inWrite := false
			var counted int64
			raw := spliceDrainRawConn{write: func(f func(uintptr) bool) error {
				inWrite = true
				defer func() { inWrite = false }()
				calls++
				if calls > 2 {
					t.Fatal("write did not terminate")
				}
				if calls == 2 {
					if failure == unix.EPIPE {
						// A real splice error after the first partial transfer.
						if err := unix.Close(target[0]); err != nil {
							t.Fatal(err)
						}
						target[0] = -1
						done := f(uintptr(target[1]))
						if !done {
							t.Fatal("closed pipe reader unexpectedly requested polling")
						}
						return nil
					}
					return failure
				}
				done := f(uintptr(target[1]))
				if !done {
					t.Fatal("first write unexpectedly requested polling")
				}
				return nil
			}}
			written, err := newSplicePipeDrainer(raw, source[0], func(n int64) {
				if inWrite {
					t.Fatal("counter ran before RawConn.Write returned")
				}
				counted += n
			})(int64(2 * page))
			if !errors.Is(err, failure) || counted != int64(page) || written != counted || calls != 2 {
				t.Fatalf("err=%v written=%d count=%d calls=%d; want %v/%d/2", err, written, counted, calls, failure, page)
			}
		})
	}
}

func TestDrainSplicePipeStopsOnZeroAfterProgress(t *testing.T) {
	source, target := spliceDrainPipe(t), spliceDrainPipe(t)
	page := os.Getpagesize()
	if _, err := unix.FcntlInt(uintptr(target[1]), unix.F_SETPIPE_SZ, 2*page); err != nil {
		t.Fatal(err)
	}
	if n, err := unix.Write(source[1], make([]byte, page)); err != nil || n != page {
		t.Fatalf("fill source: n=%d err=%v", n, err)
	}
	if err := unix.Close(source[1]); err != nil {
		t.Fatal(err)
	}
	source[1] = -1
	calls := 0
	raw := spliceDrainRawConn{write: func(f func(uintptr) bool) error {
		calls++
		if calls > 2 {
			t.Fatal("zero write did not terminate")
		}
		if !f(uintptr(target[1])) {
			t.Fatal("source EOF unexpectedly requested polling")
		}
		return nil
	}}
	var counted int64
	// Advertise more bytes than remain to exercise a real splice EOF after
	// progress without replacing the production syscall.
	written, err := newSplicePipeDrainer(raw, source[0], func(n int64) { counted += n })(int64(2 * page))
	if !errors.Is(err, errSpliceUnsupported) || counted != int64(page) || written != counted || calls != 2 {
		t.Fatalf("err=%v written=%d count=%d calls=%d", err, written, counted, calls)
	}
}
