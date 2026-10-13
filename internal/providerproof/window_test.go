package providerproof

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"sync"
	"testing"
	"time"
)

type controlledWindowClock struct {
	mu         sync.Mutex
	sample     windowSample
	reads      int
	afterFirst *windowSample
}

func (c *controlledWindowClock) read() windowSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.reads > 1 && c.afterFirst != nil {
		return *c.afterFirst
	}
	return c.sample
}

func (c *controlledWindowClock) set(seconds int64, nanos int, elapsed time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sample = windowSample{wall: time.Unix(seconds, int64(nanos)), elapsed: elapsed}
}

func openTestWindow(t *testing.T) (*Window, *Verifier, *controlledWindowClock) {
	t.Helper()
	v := verifier(t)
	c := &controlledWindowClock{}
	c.set(100, 500000000, time.Second)
	w, err := v.openWindow(sign(t, testHeader(), testPayload()), c.read)
	if err != nil {
		t.Fatal(err)
	}
	return w, v, c
}

func assertWindowRefused(t *testing.T, w *Window, v *Verifier) {
	t.Helper()
	proof, err := w.Check(v)
	if err != ErrWindowUnavailable || proof != (Proof{}) {
		t.Fatalf("unexpected window result: %v", err)
	}
}

func TestWindowValidDiagnosticDoesNotAuthorizeAndOwnsResult(t *testing.T) {
	w, v, c := openTestWindow(t)
	proof, err := w.Check(v)
	if err != nil || !proof.SignatureVerified || proof.AdmissionGranted || proof.KeyRevoked ||
		proof.WindowValidation != "valid_at_observation" || proof.BusinessEvidenceValidation != "not_evaluated" || proof.LiveCoreEligibility != "not_evaluated" {
		t.Fatal("window falsely advertised authorization")
	}
	proof.AdmissionGranted = true
	proof.WindowValidation = "caller mutation"
	// Even a copied signature result cannot populate the private clock/trust
	// initialized only by OpenWindow; a reverse-constructed shell is unusable.
	assertWindowRefused(t, &Window{proof: proof}, v)
	c.set(101, 0, 1500*time.Millisecond)
	again, err := w.Check(v)
	if err != nil || again.AdmissionGranted || again.WindowValidation != "valid_at_observation" {
		t.Fatal("caller mutated retained proof")
	}
	pure, err := v.VerifySignature(sign(t, testHeader(), testPayload()))
	if err != nil || pure.WindowValidation != "not_evaluated" {
		t.Fatal("signature history behavior changed")
	}
}

func TestWindowExactWallAndMonotonicDeadlines(t *testing.T) {
	cases := []struct {
		name     string
		second   int64
		nanos    int
		elapsed  time.Duration
		accepted bool
	}{
		{"same_observation", 100, 500000000, time.Second, true},
		{"last_nanosecond", 149, 999999999, 50500*time.Millisecond - time.Nanosecond, true},
		{"exact_wall_expiry", 150, 0, 2 * time.Second, false},
		{"wall_jump_past_expiry", 151, 0, 2 * time.Second, false},
		{"exact_monotonic_expiry_slow_wall", 101, 0, 50500 * time.Millisecond, false},
		{"monotonic_after_deadline", 110, 0, 51 * time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, v, c := openTestWindow(t)
			c.set(tc.second, tc.nanos, tc.elapsed)
			p, err := w.Check(v)
			if tc.accepted {
				if err != nil || p.AdmissionGranted {
					t.Fatal("valid diagnostic refused")
				}
				return
			}
			if err != ErrWindowUnavailable || p != (Proof{}) {
				t.Fatal("expiry accepted")
			}
			c.set(100, 500000000, time.Second)
			assertWindowRefused(t, w, v)
		})
	}
}

func TestWindowRegressionInvalidSamplesAndOverflowRemainTerminal(t *testing.T) {
	cases := []struct {
		name    string
		second  int64
		nanos   int
		elapsed time.Duration
	}{
		{"wall_second_regression", 100, 900000000, 3 * time.Second},
		{"wall_nanosecond_regression", 101, 9, 3 * time.Second},
		{"monotonic_regression", 102, 0, time.Second},
		{"negative_elapsed", 102, 0, -time.Second},
		{"negative_utc", -1, 0, 3 * time.Second},
		{"unsafe_utc", 9007199254740992, 0, 3 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, v, c := openTestWindow(t)
			c.set(101, 10, 2*time.Second)
			if _, err := w.Check(v); err != nil {
				t.Fatal(err)
			}
			c.set(tc.second, tc.nanos, tc.elapsed)
			assertWindowRefused(t, w, v)
			c.set(102, 0, 4*time.Second)
			assertWindowRefused(t, w, v)
		})
	}
	c := &controlledWindowClock{sample: windowSample{wall: time.Unix(100, 0), elapsed: time.Duration(1<<63 - 1)}}
	if w, err := verifier(t).openWindow(sign(t, testHeader(), testPayload()), c.read); err != ErrWindowUnavailable || w != nil {
		t.Fatal("deadline arithmetic overflow accepted")
	}
}

func TestWindowOpeningRefusesFutureExpiredRevokedAndCryptoTimeConsumption(t *testing.T) {
	cases := []struct {
		name    string
		before  windowSample
		after   *windowSample
		revoked bool
	}{
		{name: "future", before: windowSample{wall: time.Unix(99, 999999999)}},
		{name: "expired", before: windowSample{wall: time.Unix(150, 0)}},
		{name: "revoked", before: windowSample{wall: time.Unix(100, 0)}, revoked: true},
		{name: "expires_during_verification", before: windowSample{wall: time.Unix(100, 0)}, after: &windowSample{wall: time.Unix(150, 0), elapsed: 50 * time.Second}},
		{name: "regresses_during_verification", before: windowSample{wall: time.Unix(101, 0)}, after: &windowSample{wall: time.Unix(100, 0), elapsed: time.Second}},
		{name: "monotonic_expiry_during_verification", before: windowSample{wall: time.Unix(100, 0)}, after: &windowSample{wall: time.Unix(101, 0), elapsed: 50 * time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := testTrust
			key.Revoked = tc.revoked
			v, err := New([]TrustedKey{key})
			if err != nil {
				t.Fatal(err)
			}
			c := &controlledWindowClock{sample: tc.before, afterFirst: tc.after}
			if w, err := v.openWindow(sign(t, testHeader(), testPayload()), c.read); err != ErrWindowUnavailable || w != nil {
				t.Fatal("invalid opening returned a window")
			}
			if p, err := v.VerifySignature(sign(t, testHeader(), testPayload())); err != nil || p.WindowValidation != "not_evaluated" {
				t.Fatal("historical signature lost")
			}
		})
	}
	if w, err := verifier(t).OpenWindow("synthetic invalid statement"); err != ErrInvalidProof || w != nil {
		t.Fatal("invalid signature initialized window")
	}
	var v *Verifier
	if w, err := v.OpenWindow("synthetic invalid statement"); err != ErrInvalidProof || w != nil {
		t.Fatal("nil trust initialized window")
	}
}

func TestWindowTrustRefreshReplacementRemovalAndRevocation(t *testing.T) {
	cases := map[string]func(*TrustedKey){
		"revoked":             func(k *TrustedKey) { k.Revoked = true },
		"removed":             func(k *TrustedKey) { k.ID = "other-key" },
		"epoch_replaced":      func(k *TrustedKey) { k.Epoch = "2" },
		"not_before_replaced": func(k *TrustedKey) { k.NotBefore = 2 },
		"not_after_replaced":  func(k *TrustedKey) { k.NotAfter = 201 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w, v, _ := openTestWindow(t)
			key := testTrust
			mutate(&key)
			current, err := New([]TrustedKey{key})
			if err != nil {
				t.Fatal(err)
			}
			assertWindowRefused(t, w, current)
			assertWindowRefused(t, w, v)
		})
	}
	t.Run("nil", func(t *testing.T) {
		w, v, _ := openTestWindow(t)
		assertWindowRefused(t, w, nil)
		assertWindowRefused(t, w, v)
	})

	t.Run("spki_replaced", func(t *testing.T) {
		w, v, _ := openTestWindow(t)
		alternate, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal("synthetic alternate key generation failed")
		}
		der, err := x509.MarshalPKIXPublicKey(&alternate.PublicKey)
		if err != nil {
			t.Fatal("synthetic public key conversion failed")
		}
		key := testTrust
		key.PublicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		digest := sha256.Sum256(der)
		key.SPKISHA256 = hex.EncodeToString(digest[:])
		current, err := New([]TrustedKey{key})
		if err != nil {
			t.Fatal(err)
		}
		assertWindowRefused(t, w, current)
		assertWindowRefused(t, w, v)
	})
	t.Run("retained_predecessor", func(t *testing.T) {
		w, _, _ := openTestWindow(t)
		next := testTrust
		next.ID = "next-key"
		next.Epoch = "2"
		current, err := New([]TrustedKey{next, testTrust})
		if err != nil {
			t.Fatal(err)
		}
		if p, err := w.Check(current); err != nil || p.KeyID != testTrust.ID || p.AdmissionGranted {
			t.Fatal("unchanged trusted predecessor refused")
		}
	})
}

func TestWindowCloseAndConcurrentChecks(t *testing.T) {
	w, v, _ := openTestWindow(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				p, err := w.Check(v)
				if err != nil && err != ErrWindowUnavailable {
					t.Error("unexpected refusal")
				}
				if p.AdmissionGranted {
					t.Error("admission granted")
				}
			}
			if i == 16 {
				w.Close()
			}
		}(i)
	}
	wg.Wait()
	assertWindowRefused(t, w, v)
	w.Close()
	assertWindowRefused(t, w, v)
	var empty Window
	assertWindowRefused(t, &empty, v)
	var absent *Window
	absent.Close()
	assertWindowRefused(t, absent, v)
}

func TestWindowPublicClockUsesSignedBytesAndFiniteWindow(t *testing.T) {
	now := time.Now().Unix()
	key := testTrust
	key.NotBefore = now - 5
	key.NotAfter = now + 70
	v, err := New([]TrustedKey{key})
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload()
	payload["issued_at"] = now - 1
	payload["lease_expires_at"] = now + 40
	payload["key_not_before"] = key.NotBefore
	payload["key_not_after"] = key.NotAfter
	w, err := v.OpenWindow(sign(t, testHeader(), payload))
	if err != nil {
		t.Fatal(err)
	}
	p, err := w.Check(v)
	if err != nil || p.AdmissionGranted || p.LeaseExpiresAt != now+40 || p.WindowValidation != "valid_at_observation" {
		t.Fatal("process clock diagnostic failed")
	}
	w.Close()
	assertWindowRefused(t, w, v)
}
