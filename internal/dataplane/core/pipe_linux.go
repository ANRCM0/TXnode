//go:build linux

package core

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// splicePipe is the zero-copy path of notes/rev-core.md §7.1-§7.3:
// core.trySplice @0x7b8640 only checks tcpWriter(a) and then calls
// core.spliceRelay @0x7b8280. Here both ends must reduce to a *net.TCPConn.
//
// Each direction is: splice(socket -> pipe) followed by splice(pipe -> socket),
// using a private os.Pipe. When the syscall is unavailable (ENOSYS/EINVAL) the
// function reports ok=false so Pipe falls back to io.Copy.
func splicePipe(ctx context.Context, a, b net.Conn, up, down func(int64)) (bool, error) {
	ta, tb := tcpWriter(a), tcpWriter(b)
	if ta == nil || tb == nil {
		return false, nil
	}
	err := spliceBoth(ctx, ta, tb, up, down)
	return true, err
}

// Splice attempts the Linux splice(2) relay and falls back to Pipe. The boolean
// reports whether splice was used (REPLICATION.md §3.1).
func Splice(a, b net.Conn) (bool, error) {
	if ok, err := splicePipe(context.Background(), a, b, nil, nil); ok {
		return true, err
	}
	return false, Pipe(context.Background(), a, b, nil, nil)
}

func spliceBoth(ctx context.Context, a, b *net.TCPConn, up, down func(int64)) error {
	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)
	go func() {
		defer wg.Done()
		errCh <- spliceOne(ctx, b, a, up)
	}()
	go func() {
		defer wg.Done()
		errCh <- spliceOne(ctx, a, b, down)
	}()

	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-ctx.Done():
			// Closing the sockets makes the blocking splice return.
			_ = a.Close()
			_ = b.Close()
		case <-done:
		}
	}()
	wg.Wait()
	once.Do(func() { close(done) })
	close(errCh)

	var first error
	for err := range errCh {
		if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
			continue
		}
		if first == nil {
			first = err
		}
	}
	return first
}

var errSpliceUnsupported = errors.New("splice is not supported")

// spliceOne copies src→dst with splice(2), counting copied bytes.
func spliceOne(ctx context.Context, dst, src *net.TCPConn, count func(int64)) error {
	srcRC, err := src.SyscallConn()
	if err != nil {
		return err
	}
	dstRC, err := dst.SyscallConn()
	if err != nil {
		return err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pr.Close()
	defer pw.Close()
	// The splice pipe is used from the raw callbacks in non-blocking mode.
	if err := unix.SetNonblock(int(pr.Fd()), true); err != nil {
		return err
	}
	if err := unix.SetNonblock(int(pw.Fd()), true); err != nil {
		return err
	}

	var pipeBuf [copyBuf]byte
	_ = pipeBuf
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// 1. socket -> pipe
		var n int64
		var serr error
		readErr := srcRC.Read(func(fd uintptr) bool {
			n, serr = unix.Splice(int(fd), nil, int(pw.Fd()), nil, copyBuf, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			if serr == unix.EAGAIN {
				return false // wait for readability and retry
			}
			return true
		})
		if readErr != nil {
			return readErr
		}
		if serr != nil {
			return serr
		}
		if n == 0 {
			// EOF from the source: propagate the half close.
			return CloseWrite(dst)
		}
		// 2. pipe -> socket, retrying on EAGAIN without losing the offset.
		var off int64
		for off < n {
			var werr error
			writeErr := dstRC.Write(func(fd uintptr) bool {
				m, e := unix.Splice(int(pr.Fd()), nil, int(fd), nil, int(n-off), unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
				if e == unix.EAGAIN {
					return false // socket buffer full; wait then retry
				}
				if e != nil {
					werr = e
					return true
				}
				off += m
				return true
			})
			if writeErr != nil {
				return writeErr
			}
			if werr != nil {
				return werr
			}
			if off == 0 {
				return errSpliceUnsupported
			}
		}
		if count != nil {
			count(n)
		}
	}
}
