package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// The padding scheme is the server-side half of the AnyTLS padding agreement
// (notes/rev-proto-tcp.md §6: (*session).settings parses `v` and `padding-md5`
// lines and compares the digest with strings.EqualFold; the server answers
// "v=2"). The scheme text is opaque to the protocol — only its MD5 travels — so
// the exact table below is kaze's default, not a recovered constant.
//
// UNVERIFIED: the default scheme text (anytls v2 style). What is verified is the
// mechanism: md5(scheme) in the settings line and padding frames before data.
const DefaultPaddingScheme = `stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
8=500-1000
stop=8`

// paddingItem is one entry of a scheme line.
type paddingItem struct {
	min  int
	max  int
	cont bool // the "c" marker: keep using this line for the following packets
}

// paddingScheme is a parsed scheme: packet index -> candidate padding lengths.
type paddingScheme struct {
	lines map[int][]paddingItem
	stop  int
}

// parseScheme parses the v2 line format "index=min-max[,c,...]".
func parseScheme(text string) paddingScheme {
	s := paddingScheme{lines: make(map[int][]paddingItem), stop: 0}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "stop" {
			if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
				s.stop = n
			}
			continue
		}
		idx, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		items := make([]paddingItem, 0, 4)
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if part == "c" {
				if n := len(items); n > 0 {
					items[n-1].cont = true
				}
				continue
			}
			lo, hi, ok := strings.Cut(part, "-")
			if !ok {
				continue
			}
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || b < a || a < 0 {
				continue
			}
			items = append(items, paddingItem{min: a, max: b})
		}
		if len(items) > 0 {
			s.lines[idx] = items
		}
	}
	return s
}

// padding returns the length of the waste frame to send before the n-th data
// frame. It returns 0 when the scheme has nothing for that index.
func (s paddingScheme) padding(n int) int {
	items, ok := s.lines[n]
	if !ok || len(items) == 0 {
		return 0
	}
	it := items[0]
	if it.max <= 0 {
		return 0
	}
	span := it.max - it.min + 1
	if span <= 0 {
		return it.min
	}
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return it.min
	}
	return it.min + int(binary.BigEndian.Uint32(buf[:]))%span
}

// schemeDigest is the "padding-md5" value: lower-case hex MD5 of the scheme text
// ((*session).settings @0x964220 does crypto/md5.Sum then compares the 32-char
// hex with strings.EqualFold).
func schemeDigest(text string) string {
	sum := md5.Sum([]byte(text))
	return hex.EncodeToString(sum[:])
}
