package core

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Pipe is core.pipe @0x7b4ac0: a bidirectional relay with byte counters and the
// 8-layer tcpWriter unwrap that decides whether the zero-copy splice path can be
// used (core.tcpWriter @0x7b51a0, core.trySplice @0x7b8640, notes/rev-core.md
// §7.1-§7.2). When either side cannot be reduced to a bare *net.TCPConn it
// falls back to io.Copy loops (pipeRaw @0x7a9460).
//
// up counts bytes a→b, down counts bytes b→a. The callbacks are invoked with
// increments, so a Tracker or OnTraffic hook can account live traffic.

// Pipe relays until both directions finish. It does not close the connections.
func Pipe(ctx context.Context, a, b net.Conn, up, down func(int64)) error {
	return pipeLimited(ctx, a, b, nil, nil, up, down, nil, Chunk{})
}

// waiter is the token-bucket surface relay needs: a Limiter, or a chain of a
// user bucket and a node bucket (both must admit the bytes).
type waiter interface {
	Wait(ctx context.Context, n int64) error
}

// waiterSet waits on several buckets in order.
type waiterSet []waiter

func (w waiterSet) Wait(ctx context.Context, n int64) error {
	for _, l := range w {
		if l == nil {
			continue
		}
		if err := l.Wait(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// activeLimiters drops nil / unlimited buckets so the splice path stays
// available when no rate limit is configured.
func activeLimiters(ls ...*Limiter) []waiter {
	var out []waiter
	for _, l := range ls {
		if l == nil {
			continue
		}
		if l.Rate() <= 0 {
			continue
		}
		out = append(out, l)
	}
	return out
}

// pipeLimited is Pipe with optional token buckets. The buckets throttle the read
// side, which turns a slow reader into backpressure on the writer, exactly like
// Limiter.Wait inside the original pipe.
func pipeLimited(ctx context.Context, a, b net.Conn, upLim, downLim []waiter, up, down func(int64), hook ChunkHook, meta Chunk) error {
	// A chunk hook needs a userspace copy: admission must happen before the
	// bytes move, which splice(2) cannot express.
	if hook == nil && len(upLim) == 0 && len(downLim) == 0 {
		if ok, err := splicePipe(ctx, a, b, up, down); ok {
			return err
		}
	}
	return copyPipe(ctx, a, b, upLim, downLim, up, down, hook, meta)
}

// copyPipe is the userspace fallback: one goroutine per direction, half-close on
// EOF so the peer's copy loop terminates.
func copyPipe(ctx context.Context, a, b net.Conn, upLim, downLim []waiter, up, down func(int64), hook ChunkHook, meta Chunk) error {
	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)
	go func() {
		defer wg.Done()
		errCh <- copyDirection(ctx, b, a, upLim, up, hook, meta, DirUpload)
	}()
	go func() {
		defer wg.Done()
		errCh <- copyDirection(ctx, a, b, downLim, down, hook, meta, DirDownload)
	}()

	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }
	go func() {
		select {
		case <-ctx.Done():
			// Unblock both copy loops.
			_ = a.SetDeadline(time.Now())
			_ = b.SetDeadline(time.Now())
			_ = a.Close()
			_ = b.Close()
		case <-done:
		}
	}()
	wg.Wait()
	stop()
	close(errCh)

	var first error
	for err := range errCh {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
			errors.Is(err, context.Canceled) {
			continue
		}
		if first == nil {
			first = err
		}
	}
	return first
}

// copyDirection copies src→dst honouring the limiter, counting bytes.
func copyDirection(ctx context.Context, dst, src net.Conn, lims []waiter, count func(int64), hook ChunkHook, meta Chunk, dir ChunkDirection) error {
	buf := make([]byte, copyBuf)
	for {
		var token any
		if hook != nil {
			c := meta
			c.Dir, c.N = dir, int64(len(buf))
			var herr error
			token, herr = hook.Begin(c)
			if herr != nil {
				return herr
			}
		}
		n, rerr := src.Read(buf)
		if hook != nil {
			c := meta
			c.Dir, c.N, c.Err = dir, int64(n), rerr
			hook.Complete(c, token)
		}
		if n > 0 {
			if len(lims) > 0 {
				if err := waiterSet(lims).Wait(ctx, int64(n)); err != nil {
					return err
				}
			}
			w, werr := dst.Write(buf[:n])
			if w > 0 && count != nil {
				count(int64(w))
			}
			if werr != nil {
				return werr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return CloseWrite(dst)
			}
			return rerr
		}
	}
}

// spliceable is the opt-in marker for a transparent wrapper: peeling it must not
// change the byte stream. Buffering wrappers (earlyConn, proxyConn) and TLS-like
// wrappers must never implement it, otherwise splice(2) would bypass decryption
// or lose buffered bytes.
type spliceable interface {
	SpliceConn() net.Conn
}

// tcpWriter reduces c to a bare *net.TCPConn through up to eight transparent
// layers, the condition for splice (core.tcpWriter @0x7b51a0; the original walks
// a fixed itab table at 0x178d250 and gives up after eight iterations).
//
// crypto/tls (and uTLS) expose NetConn() but reading the raw socket would hand
// ciphertext to the other side, so TLS conns are explicitly rejected. The same
// goes for the core buffering wrappers.
func tcpWriter(c net.Conn) *net.TCPConn {
	for i := 0; i < 8 && c != nil; i++ {
		if tc, ok := c.(*net.TCPConn); ok {
			return tc
		}
		if _, ok := c.(*tls.Conn); ok {
			return nil
		}
		switch c.(type) {
		case *earlyConn, *proxyConn:
			return nil
		}
		if v, ok := c.(spliceable); ok {
			c = v.SpliceConn()
			continue
		}
		return nil
	}
	return nil
}
