package mieru

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestV2EntropyFixedWireVectorAndUniformPadding(t *testing.T) {
	// The 32-bit half-mask repeats in both halves of the 64-bit wire word.
	// Selected low sixteen bits in each half carry 0x1234abcd in bit order.
	for _, fixture := range []struct {
		padding byte
		wire    string
	}{{0, "000012340000abcd"}, {1, "ffff1234ffffabcd"}} {
		wire, err := entropyEncode([]byte{0x12, 0x34, 0xab, 0xcd}, 1, 0x0000ffff, 0, fixture.padding)
		if err != nil || hex.EncodeToString(wire) != fixture.wire {
			t.Fatalf("wire=%x err=%v want=%s", wire, err, fixture.wire)
		}
		plain, err := entropyDecode(wire, 4, 1, 0x0000ffff, 0)
		if err != nil || !bytes.Equal(plain, []byte{0x12, 0x34, 0xab, 0xcd}) {
			t.Fatalf("decode=%x err=%v", plain, err)
		}
		wire[0] ^= 0x80
		if _, err := entropyDecode(wire, 4, 1, 0x0000ffff, 0); err == nil {
			t.Fatal("mixed padding polarity was accepted")
		}
	}
}

func TestV2EntropyModesRotationsAndTruncatedLastChunk(t *testing.T) {
	masks := []uint32{0, 0x0f0f0f0f, 0x1f1f1f1f, 0x3f3f3f3f, 0x7f7f7f7f}
	for mode := entropyMode(1); mode <= 4; mode++ {
		for _, rotation := range []entropyRotation{0, 1, 7, 15, 16, 48, 240} {
			t.Run(fmt.Sprintf("mode%d/rotation%d", mode, rotation), func(t *testing.T) {
				plain := bytes.Repeat([]byte{0, 1, 0x37, 0xff, 0x85}, 17)
				for _, bit := range []byte{0, 1} {
					wire, err := entropyEncode(plain, mode, masks[mode], rotation, bit)
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := entropyDecode(wire, len(plain), mode, masks[mode], rotation)
					if err != nil || !bytes.Equal(decoded, plain) {
						t.Fatalf("wire round trip failed: %v", err)
					}
				}
			})
		}
	}
	// Constants also appear in the fixed upstream v3.38.1 rotation fixtures.
	for _, fixture := range []struct {
		rotation entropyRotation
		index    int
		want     uint64
	}{{4, 1, 0xf0f0f0f0f0f0f0f0}, {48, 1, 0x7878787878787878}, {48, 2, 0xc3c3c3c3c3c3c3c3}} {
		mask, err := entropyMask(0x0f0f0f0f, 1, fixture.rotation, fixture.index)
		if err != nil || mask != fixture.want {
			t.Fatalf("mask=%x want=%x err=%v", mask, fixture.want, err)
		}
	}
	for _, bad := range []struct {
		mode entropyMode
		mask uint32
		rot  entropyRotation
	}{{0, 0xffff, 0}, {5, 0xffff, 0}, {1, 0xff, 0}, {1, 0xffff, 17}, {1, 0xffff, 255}} {
		if _, err := entropyEncode([]byte("data"), bad.mode, bad.mask, bad.rot, 0); err == nil {
			t.Fatal("invalid mode/mask/rotation was accepted")
		}
	}
}

func TestTrafficPatternExplicitFieldsAndStrictRejection(t *testing.T) {
	good := `{"tcpFragment":{"enable":true,"maxSleepMs":0},"nonce":{"type":"NONCE_TYPE_FIXED","applyToAllUDPPacket":true,"customHexStrings":["01020304"]},"padding":{"maxMiddlePaddingLen":0,"maxEndPaddingLen":11},"lowEntropy":{"mode":"LOW_ENTROPY_MODE_40","maskRotation":"LOW_ENTROPY_MASK_ROTATE_LEFT_3"}}`
	p, err := parseTrafficPattern(good)
	if err != nil {
		t.Fatal(err)
	}
	if p.LowEntropy.Mode != 2 || p.LowEntropy.MaskRotation != 48 {
		t.Fatal("explicit low entropy enum was not applied")
	}
	nonce := bytes.Repeat([]byte{0xfe}, 24)
	if err := p.nonce(nonce, false); err != nil || !bytes.Equal(nonce[:4], []byte{1, 2, 3, 4}) || nonce[12] != 0xfe {
		t.Fatalf("nonce pattern escaped prefix: %x err=%v", nonce, err)
	}
	if middle, err := p.padding(255, true); err != nil || len(middle) != 0 {
		t.Fatal("explicit zero padding was not applied")
	}
	for _, raw := range []string{
		"random", "null", `{} {}`, `{"unknown":true}`, `{"seed":0}`, `{"unlockAll":true}`,
		`{"nonce":{"type":9}}`, `{"nonce":{"minLen":8,"maxLen":7}}`, `{"nonce":{"maxLen":13}}`,
		`{"nonce":{"customHexStrings":["xx"]}}`, `{"padding":{"maxEndPaddingLen":256}}`,
		`{"tcpFragment":{"enable":true,"maxSleepMs":101}}`, `{"lowEntropy":{"mode":5}}`,
		`{"lowEntropy":{"mode":1,"maskRotation":17}}`,
	} {
		if err := ValidateTrafficPattern(raw); err == nil {
			t.Fatalf("unsupported traffic_pattern accepted: %s", raw)
		}
	}
}
