package mieru

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestImplicitPatternSeedVectors(t *testing.T) {
	for _, fixture := range []struct {
		seed                                int32
		unlock, fragment, udp               bool
		sleep, nonce, min, max, middle, end int
		mode, rotation                      int
	}{
		{0, false, false, true, 0, 1, 9, 11, 77, 255, 0, 160},
		{0, true, false, true, 37, 1, 6, 10, 77, 213, 0, 160},
		{-2147483648, false, false, true, 0, 2, 11, 11, 60, 255, 0, 128},
		{-2147483648, true, true, true, 87, 1, 6, 7, 60, 91, 4, 128},
		{2147483647, false, false, false, 0, 2, 9, 11, 0, 255, 0, 8},
		{2147483647, true, true, false, 20, 0, 9, 11, 0, 42, 0, 8},
	} {
		t.Run(fmt.Sprintf("seed=%d/unlock=%t", fixture.seed, fixture.unlock), func(t *testing.T) {
			p, err := parseTrafficPattern(fmt.Sprintf(`{"seed":%d,"unlockAll":%t}`, fixture.seed, fixture.unlock))
			if err != nil {
				t.Fatal(err)
			}
			if p.TCPFragment.Enable != fixture.fragment || *p.TCPFragment.MaxSleepMS != fixture.sleep ||
				int(p.Nonce.Type) != fixture.nonce || p.Nonce.ApplyToAllUDPPacket != fixture.udp ||
				*p.Nonce.MinLen != fixture.min || *p.Nonce.MaxLen != fixture.max ||
				*p.Padding.MaxMiddle != fixture.middle || *p.Padding.MaxEnd != fixture.end ||
				int(p.LowEntropy.Mode) != fixture.mode || int(p.LowEntropy.MaskRotation) != fixture.rotation {
				body, _ := json.Marshal(p)
				t.Fatalf("pinned seed vector differs: %s", body)
			}
		})
	}
}

func TestImplicitPatternKeepsExplicitZeroAndFalse(t *testing.T) {
	raw := `{"seed":-2147483648,"unlockAll":true,"tcpFragment":{"enable":false,"maxSleepMs":0},"nonce":{"type":0,"applyToAllUDPPacket":false,"minLen":0,"maxLen":0},"padding":{"maxMiddlePaddingLen":0,"maxEndPaddingLen":0},"lowEntropy":{"mode":0,"maskRotation":0}}`
	p, err := parseTrafficPattern(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.TCPFragment.Enable || *p.TCPFragment.MaxSleepMS != 0 || p.Nonce.Type != 0 ||
		p.Nonce.ApplyToAllUDPPacket || *p.Nonce.MinLen != 0 || *p.Nonce.MaxLen != 0 ||
		*p.Padding.MaxMiddle != 0 || *p.Padding.MaxEnd != 0 || p.LowEntropy.Mode != 0 || p.LowEntropy.MaskRotation != 0 {
		t.Fatal("generated values overrode explicit zero/false")
	}
	if _, err := parseTrafficPattern(`{"seed":0,"nonce":{"maxLen":0}}`); err == nil {
		t.Fatal("generated minimum silently overrode an incompatible explicit maximum")
	}
	p, err = parseTrafficPattern(`{"seed":0,"nonce":{"minLen":12}}`)
	if err != nil || *p.Nonce.MaxLen != 12 {
		t.Fatal("generated maximum did not respect the explicit minimum")
	}
}

func TestImplicitPatternRejectsAmbiguousFields(t *testing.T) {
	for _, raw := range []string{
		`{"seed":0,"seed":1}`,
		`{"seed":0,"Seed":1}`,
		`{"seed":0,"nonce":{"minLen":0,"MinLen":1}}`,
		`{"unlockAll":true,"padding":[]}`,
	} {
		if _, err := parseTrafficPattern(raw); err == nil {
			t.Fatalf("accepted ambiguous implicit pattern %s", raw)
		}
	}
	p, err := parseTrafficPattern(`{"Seed":0,"Nonce":{"Type":0,"ApplyToAllUDPPacket":false,"MinLen":0,"MaxLen":0}}`)
	if err != nil || p.Nonce.Type != 0 || p.Nonce.ApplyToAllUDPPacket || *p.Nonce.MinLen != 0 || *p.Nonce.MaxLen != 0 {
		t.Fatal("case-insensitive explicit fields lost their presence")
	}
}

func TestImplicitPatternHostSeedAndDefaultCompatibility(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"unlockAll":false}`} {
		p, err := parseTrafficPattern(raw)
		if err != nil || p.TCPFragment != nil || p.Nonce != nil || p.Padding != nil || p.LowEntropy != nil {
			t.Fatalf("default changed for %s: %v", raw, err)
		}
	}
	first, err := parseTrafficPattern(`{"unlockAll":true}`)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseTrafficPattern(`{"unlockAll":true}`)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("same-host default seed is unstable")
	}
	*first.Nonce.MinLen = 0
	third, err := parseTrafficPattern(`{"unlockAll":true}`)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := json.Marshal(third)
	if string(b) != string(c) {
		t.Fatal("pattern instances share mutable generated state")
	}
}
