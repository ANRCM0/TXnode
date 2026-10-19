// Package tlsbuf exposes bytes that crypto/tls has already decrypted but the
// caller has not read yet.
//
// The binary probes reflect.Type.FieldByName("input") / ("rawInput") once and
// stores the offsets in .bss (tlsbuf.init @0x79e960, REPORT.md §18.4). Four
// conditions must hold before the fast path applies; otherwise it falls back to
// crypto/tls.(*Conn).Read. This implementation does the same, with bounds and
// type checks so a different Go runtime simply reports unavailable instead of
// corrupting memory.
package tlsbuf

import (
	"bytes"
	"crypto/tls"
	"reflect"
	"sync"
	"unsafe"
)

var (
	once      sync.Once
	available bool
	inputOff  uintptr
	rawOff    uintptr
)

func probe() {
	t := reflect.TypeOf(tls.Conn{})
	raw, ok := t.FieldByName("rawInput")
	if !ok || raw.Type != reflect.TypeOf((*bytes.Buffer)(nil)) {
		return
	}
	in, ok := t.FieldByName("input")
	if !ok || in.Type != reflect.TypeOf((*bytes.Reader)(nil)) {
		return
	}
	sz := t.Size()
	if raw.Offset == 0 || in.Offset == 0 || uintptr(raw.Offset) >= sz || uintptr(in.Offset) >= sz {
		return
	}
	rawOff = raw.Offset
	inputOff = in.Offset
	available = true
}

// Available reports whether the TLS internals match the expected layout.
func Available() bool {
	once.Do(probe)
	return available
}

// Pending returns a copy of the buffered plaintext, if any. It never consumes
// the connection state.
func Pending(c *tls.Conn) []byte {
	if c == nil || !Available() {
		return nil
	}
	defer func() { _ = recover() }()
	if rb := (*bytes.Buffer)(unsafe.Add(unsafe.Pointer(c), rawOff)); rb != nil {
		if rb.Len() > 0 {
			return append([]byte(nil), rb.Bytes()...)
		}
	}
	if rd := (*bytes.Reader)(unsafe.Add(unsafe.Pointer(c), inputOff)); rd != nil {
		if rd.Len() > 0 {
			b := make([]byte, rd.Len())
			_, _ = rd.ReadAt(b, 0)
			return b
		}
	}
	return nil
}

// Read returns pending plaintext first, then falls back to c.Read.
func Read(c *tls.Conn, p []byte) (int, error) {
	if b := Pending(c); len(b) > 0 {
		n := copy(p, b)
		return n, nil
	}
	return c.Read(p)
}
