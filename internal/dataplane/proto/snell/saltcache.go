package snell

import (
	"sync"
	"time"
)

// saltCache remembers v3 salts to reject replays.
//
// Evidence: handshake @0xb28460 calls shadowsocks.(*saltCache).add @0xb1a1e0 for
// v3 (notes/rev-proto-udp.md §4.1). The shadowsocks salt cache lives in another
// owner's package here, so this is an equivalent cache: the contract allows an
// equivalent one inside snell.
//
// TTL: the SS 2022 cache uses "delta + 0x40" (notes/rev-proto-tcp.md §4.3,
// 637), where delta is the 30/60 s timestamp window, i.e. roughly 90 s. 90 s is
// the default below.
const defaultSaltTTL = 90 * time.Second

// saltCache is a fixed-TTL set of seen salts.
type saltCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[[saltLen]byte]time.Time
}

func newSaltCache(ttl time.Duration) *saltCache {
	if ttl <= 0 {
		ttl = defaultSaltTTL
	}
	return &saltCache{ttl: ttl, entries: make(map[[saltLen]byte]time.Time)}
}

// add records a salt. It returns false when the salt was already present inside
// the TTL, which is the replay signal.
func (c *saltCache) add(salt []byte) bool {
	if len(salt) != saltLen {
		return false
	}
	var key [saltLen]byte
	copy(key[:], salt)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, seen := range c.entries {
		if now.Sub(seen) > c.ttl {
			delete(c.entries, k)
		}
	}
	if _, ok := c.entries[key]; ok {
		return false
	}
	c.entries[key] = now
	return true
}

// len reports the number of live entries (tests).
func (c *saltCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
