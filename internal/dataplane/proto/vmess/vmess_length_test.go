package vmess

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestAuthenticatedLengthMatchesXrayWireSize(t *testing.T) {
	for _, sec := range []byte{SecAES128GCM, SecChaCha20} {
		t.Run(fmt.Sprint(sec), func(t *testing.T) {
			key, iv := [16]byte{7}, [16]byte{3}
			fresh := func() *codec {
				c, err := newCodec(sec, key, iv, OptionAuthLength, key, iv)
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			nonce := append([]byte(nil), iv[:12]...)
			binary.BigEndian.PutUint16(nonce[:2], 0)
			writer := fresh()
			sealed, err := writer.sealLen(100)
			if err != nil {
				t.Fatal(err)
			}
			// Inspect the actual AEAD plaintext instead of pairing our helpers.
			plain, err := writer.lenAEAD.Open(nil, nonce, sealed, nil)
			if err != nil || len(plain) != 2 || binary.BigEndian.Uint16(plain) != 84 {
				t.Fatalf("wire size 100 must authenticate BE16(84): %x, %v", plain, err)
			}
			reader := fresh()
			raw := []byte{0, 84}
			incoming := reader.lenAEAD.Seal(nil, nonce, raw, nil)
			if size, err := reader.openLen(incoming); err != nil || size != 100 {
				t.Fatalf("raw BE16(84) must decode to wire size 100: %d, %v", size, err)
			}
			for _, size := range []int{-1, 0, 15} {
				short := fresh()
				if _, err := short.sealLen(size); err == nil || short.lenCount != 0 {
					t.Fatalf("invalid wire size %d accepted or consumed nonce: %v", size, err)
				}
			}
			if _, err := fresh().openLen([]byte{0}); err == nil {
				t.Fatal("truncated authenticated length accepted")
			}
		})
	}
}
