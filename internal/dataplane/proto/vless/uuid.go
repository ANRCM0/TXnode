// UUID parsing for the VLESS user table.
//
// Evidence: vless.ParseUUID @0xb3c640 — strings.Replace(s, "-", "", -1) followed
// by encoding/hex.DecodeString and a 16-byte length check. The sample stores the
// user table as map[[16]byte]*core.User (mapaccess2 with a 16-byte key at
// 0xb3d115), so the UUID is used as a raw 16-byte key.
package vless

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseUUID decodes the textual UUID form into its 16 raw bytes.
func ParseUUID(s string) ([16]byte, error) {
	var id [16]byte
	clean := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		return id, fmt.Errorf("vless: bad UUID %q: %w", s, err)
	}
	if len(b) != 16 {
		return id, fmt.Errorf("vless: bad UUID %q: %d bytes, want 16", s, len(b))
	}
	copy(id[:], b)
	return id, nil
}
