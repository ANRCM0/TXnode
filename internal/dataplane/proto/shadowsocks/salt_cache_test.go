package shadowsocks

import (
	"bytes"
	"testing"
	"time"
)

func stopSaltCacheTimer(t *testing.T, cache *saltCache) {
	t.Helper()
	t.Cleanup(func() {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if cache.timer != nil {
			cache.timer.Stop()
		}
	})
}

func TestSaltCacheExactLengthAndLongSaltFallback(t *testing.T) {
	cache := newSaltCache(saltCacheTTL)
	stopSaltCacheTimer(t, cache)
	// The length byte distinguishes compact trailing-zero salts. Long salts
	// (including aez-384's 48-byte salt) must retain every byte, not a hash or
	// a truncated prefix that could produce a false replay or permit a replay.
	salts := [][]byte{
		{1}, {1, 0}, bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{7}, 32),
		append(bytes.Repeat([]byte{7}, 32), 1),
		append(bytes.Repeat([]byte{7}, 32), 2),
		bytes.Repeat([]byte{9}, 48), append(bytes.Repeat([]byte{9}, 48), 0),
	}
	for _, salt := range salts {
		if !cache.add(salt) {
			t.Fatalf("distinct salt refused: %x", salt)
		}
	}
	for _, salt := range salts {
		if cache.add(salt) {
			t.Fatalf("replay accepted: %x", salt)
		}
	}
	if !cache.add(nil) || !cache.add(nil) {
		t.Fatal("empty salt semantics changed")
	}
}

func TestSaltCachePreservesFullWindowAndReleasesExpiredMaps(t *testing.T) {
	if saltCacheTTL != 94*time.Second {
		t.Fatalf("replay window changed: %v", saltCacheTTL)
	}
	cache := newSaltCache(saltCacheTTL)
	stopSaltCacheTimer(t, cache)
	before := time.Since(cache.origin).Nanoseconds()
	if !cache.add([]byte("short")) || !cache.add(bytes.Repeat([]byte{4}, 48)) {
		t.Fatal("fresh salt refused")
	}
	after := time.Since(cache.origin).Nanoseconds()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	var first, last int64
	check := func(expiry int64) {
		if expiry < before+int64(saltCacheTTL) || expiry > after+int64(saltCacheTTL) {
			t.Fatalf("expiry shortened or not relative to monotonic origin: %d", expiry)
		}
		if first == 0 || expiry < first {
			first = expiry
		}
		if expiry > last {
			last = expiry
		}
	}
	for _, expiry := range cache.salts {
		check(expiry)
	}
	for _, expiry := range cache.oversized {
		check(expiry)
	}
	if next := cache.pruneLocked(first - 1); next != first || len(cache.salts) != 1 || len(cache.oversized) != 1 {
		t.Fatalf("live history removed before expiry: next=%d compact=%d fallback=%d", next, len(cache.salts), len(cache.oversized))
	}
	if next := cache.pruneLocked(last); next != 0 || cache.salts != nil || cache.oversized != nil {
		t.Fatalf("expired map storage retained: next=%d", next)
	}
}

func TestSaltCacheIdleTimerExpiresWithoutNewTraffic(t *testing.T) {
	cache := newSaltCache(25 * time.Millisecond)
	stopSaltCacheTimer(t, cache)
	if !cache.add([]byte("idle")) || !cache.add(bytes.Repeat([]byte{3}, 48)) {
		t.Fatal("fresh salt refused")
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		cache.mu.Lock()
		empty := cache.salts == nil && cache.oversized == nil && cache.timer == nil
		cache.mu.Unlock()
		if empty {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("idle cache retained expired history or kept scheduling")
		}
	}
	if !cache.add([]byte("idle")) {
		t.Fatal("expired salt was not accepted after idle cleanup")
	}
}

func TestSaltCachePruneRetainsEveryUnexpiredSalt(t *testing.T) {
	cache := newSaltCache(saltCacheTTL)
	expired, live := saltKey{1, 1}, saltKey{1, 2}
	cache.salts = map[saltKey]int64{expired: 100, live: 101}
	cache.oversized = map[string]int64{"expired-long": 99, "live-long": 102}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if next := cache.pruneLocked(100); next != 101 {
		t.Fatalf("next expiry=%d want=101", next)
	}
	if len(cache.salts) != 1 || cache.salts[live] != 101 || len(cache.oversized) != 1 || cache.oversized["live-long"] != 102 {
		t.Fatal("cleanup removed unexpired compact or fallback history")
	}
}

func TestSaltCacheReplayDoesNotExtendExpiry(t *testing.T) {
	cache := newSaltCache(saltCacheTTL)
	stopSaltCacheTimer(t, cache)
	salt := []byte("unchanged-window")
	if !cache.add(salt) {
		t.Fatal("fresh salt refused")
	}
	var key saltKey
	key[0] = byte(len(salt))
	copy(key[1:], salt)
	cache.mu.Lock()
	before := cache.salts[key]
	owner := cache.timer
	cache.mu.Unlock()
	if cache.add(salt) {
		t.Fatal("replay accepted")
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.salts[key] != before || cache.timer != owner {
		t.Fatal("replay extended expiry or installed a second timer")
	}
}
