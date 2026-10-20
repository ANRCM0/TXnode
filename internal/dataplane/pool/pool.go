// Package pool is kaze's buffer pool (REPORT.md §7.6: "pool 是缓冲池
// (4 个函数)"). Buffers are size-classed so a hot relay path reuses the same
// backing arrays instead of allocating per read.
package pool

import "sync"

const (
	smallSize = 4 << 10
	largeSize = 32 << 10
)

var (
	small = sync.Pool{New: func() any { return make([]byte, smallSize) }}
	large = sync.Pool{New: func() any { return make([]byte, largeSize) }}
)

// Get returns a buffer with at least n bytes. Buffers of 32 KiB or more come
// from the large class; the returned slice always has cap >= n.
func Get(n int) []byte {
	if n <= smallSize {
		return small.Get().([]byte)[:n]
	}
	if n <= largeSize {
		return large.Get().([]byte)[:n]
	}
	return make([]byte, n)
}

// Put returns a buffer obtained from Get. Oversized buffers are dropped.
func Put(b []byte) {
	if cap(b) == 0 {
		return
	}
	b = b[:cap(b)]
	switch cap(b) {
	case smallSize:
		small.Put(b)
	case largeSize:
		large.Put(b)
	}
}
