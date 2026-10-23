//go:build linux

package core

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// splicePipe is the zero-copy path of notes/rev-core.md §7.1-§7.3:
// core.trySplice @0x7b8640 only checks tcpWriter(a) and then calls
// core.spliceRelay @0x7b8280. Here both ends must reduce to a *net.TCPConn.
//
// Each direction is: splice(socket -> pipe) followed by splice(pipe -> socket),
// using a private pipe. When the syscall is unavailable (ENOSYS/EINVAL) the
// function reports ok=false so Pipe falls back to io.Copy.
func splicePipe(ctx context.Context, a, b net.Conn, up, down func(int64)) (bool, error) {
	return splicePipeWithHook(ctx, a, b, up, down, nil, Chunk{})
}

func splicePipeWithHook(ctx context.Context, a, b net.Conn, up, down func(int64), hook ChunkHook, meta Chunk) (bool, error) {
	ta, tb := tcpWriter(a), tcpWriter(b)
	if ta == nil || tb == nil {
		return false, nil
	}
	err := spliceBoth(ctx, ta, tb, up, down, hook, meta)
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

func spliceBoth(ctx context.Context, a, b *net.TCPConn, up, down func(int64), hook ChunkHook, meta Chunk) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)
	go func() {
		defer wg.Done()
		err := spliceOne(ctx, b, a, up, hook, meta, DirUpload)
		errCh <- err
		if err != nil {
			cancel()
		}
	}()
	go func() {
		defer wg.Done()
		err := spliceOne(ctx, a, b, down, hook, meta, DirDownload)
		errCh <- err
		if err != nil {
			cancel()
		}
	}()

	done := make(chan struct{})
	watcherExited := make(chan struct{})
	go func() {
		defer close(watcherExited)
		select {
		case <-ctx.Done():
			// Closing the sockets makes the blocking splice return.
			_ = a.Close()
			_ = b.Close()
		case <-done:
		}
	}()
	wg.Wait()
	close(done)
	// Let the watcher observe normal completion before deferred cancellation.
	<-watcherExited
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
func spliceOne(ctx context.Context, dst, src *net.TCPConn, count func(int64), hook ChunkHook, meta Chunk, dir ChunkDirection) error {
	srcRC, err := src.SyscallConn()
	if err != nil {
		return err
	}
	dstRC, err := dst.SyscallConn()
	if err != nil {
		return err
	}
	// Only the socket RawConns own readiness waits. The non-blocking splice
	// pipe needs no Go poller registration for its own readability/writability.
	var pipeFDs [2]int
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return err
	}
	prFD, pwFD := pipeFDs[0], pipeFDs[1]
	defer unix.Close(prFD)
	defer unix.Close(pwFD)
	drain := newSplicePipeDrainer(dstRC, prFD, count)

	var n int64
	var serr error
	read := func(fd uintptr) bool {
		for {
			n, serr = unix.Splice(int(fd), nil, pwFD, nil, copyBuf, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			// Compare concrete errno values without interface equality in this hot callback.
			if errno, ok := serr.(syscall.Errno); !ok || errno != unix.EINTR {
				return !ok || errno != unix.EAGAIN // wait for readability and retry
			}
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var token any
		if hook != nil && dir == DirUpload {
			c := meta
			c.Dir, c.N = dir, copyBuf
			token, err = hook.Begin(c)
			if err != nil {
				return err
			}
		}
		// 1. socket -> pipe. Hooks run outside the RawConn callback.
		n, serr = 0, nil
		readErr := srcRC.Read(read)
		if serr != nil {
			if readErr != nil {
				readErr = errors.Join(readErr, serr)
			} else {
				readErr = serr
			}
		}
		if n < 0 {
			n = 0
		}
		if readErr == nil && n == 0 {
			readErr = io.EOF
		}
		if hook != nil && dir == DirUpload {
			c := meta
			c.Dir, c.N, c.Err = dir, n, readErr
			hook.Complete(c, token)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if n == 0 {
			// EOF from the source: propagate the half close.
			return CloseWrite(dst)
		}
		if hook != nil && dir == DirDownload {
			c := meta
			c.Dir, c.N = dir, n
			token, err = hook.Begin(c)
			if err != nil {
				return err
			}
		}
		written, err := drain(n)
		if hook != nil && dir == DirDownload {
			c := meta
			c.Dir, c.N, c.Err = dir, written, err
			hook.Complete(c, token)
		}
		if err != nil {
			return err
		}
	}
}

// newSplicePipeDrainer reuses one callback per direction. Counts run outside
// RawConn.Write, including partial progress before a subsequent error.
func newSplicePipeDrainer(dstRC syscall.RawConn, pipeFD int, count func(int64)) func(int64) (int64, error) {
	var remaining, written int64
	var werr error
	write := func(fd uintptr) bool {
		for {
			written, werr = unix.Splice(pipeFD, nil, int(fd), nil, int(remaining), unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			if errno, ok := werr.(syscall.Errno); !ok || errno != unix.EINTR {
				return !ok || errno != unix.EAGAIN // socket buffer full: wait then retry
			}
		}
	}
	return func(n int64) (int64, error) {
		remaining = n
		for remaining > 0 {
			written, werr = 0, nil
			writeErr := dstRC.Write(write)
			if written > 0 {
				remaining -= written
				if count != nil {
					count(written)
				}
			}
			if writeErr != nil {
				return n - remaining, writeErr
			}
			if werr != nil {
				return n - remaining, werr
			}
			if written == 0 {
				return n - remaining, errSpliceUnsupported
			}
		}
		return n - remaining, nil
	}
}
