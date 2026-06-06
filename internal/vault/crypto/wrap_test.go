package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	mathrand "math/rand/v2"
	"testing"
)

// testParams uses minimum-allowed params so tests stay fast. Real wraps
// use DefaultArgon2Params.
var testParams = Argon2Params{Time: 1, Memory: 8 * 1024, Threads: 1}

func mustVaultKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewVaultKey()
	if err != nil {
		t.Fatalf("NewVaultKey: %v", err)
	}
	if len(k) != VaultKeySize {
		t.Fatalf("NewVaultKey length = %d, want %d", len(k), VaultKeySize)
	}
	return k
}

func TestNewVaultKey_NonZeroAndUnique(t *testing.T) {
	k1 := mustVaultKey(t)
	k2 := mustVaultKey(t)
	if bytes.Equal(k1, make([]byte, VaultKeySize)) {
		t.Fatal("NewVaultKey returned all-zero key")
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("two NewVaultKey calls returned identical keys")
	}
}

func TestWrapUnwrap_Roundtrip(t *testing.T) {
	pw := []byte("correct horse battery staple")
	vk := mustVaultKey(t)
	wrapped, err := Wrap(pw, vk, testParams)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := Unwrap(pw, wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, vk) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestWrap_ProducesDifferentCiphertexts(t *testing.T) {
	pw := []byte("same-pw")
	vk := mustVaultKey(t)
	a, err := Wrap(pw, vk, testParams)
	if err != nil {
		t.Fatalf("Wrap a: %v", err)
	}
	b, err := Wrap(pw, vk, testParams)
	if err != nil {
		t.Fatalf("Wrap b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two Wrap calls with same inputs produced identical ciphertext")
	}
}

func TestUnwrap_WrongPassword(t *testing.T) {
	vk := mustVaultKey(t)
	wrapped, err := Wrap([]byte("right"), vk, testParams)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	_, err = Unwrap([]byte("wrong"), wrapped)
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: err = %v, want ErrWrongPassword", err)
	}
}

func TestUnwrap_TamperedCiphertext(t *testing.T) {
	pw := []byte("pw")
	vk := mustVaultKey(t)
	wrapped, err := Wrap(pw, vk, testParams)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// Each Unwrap runs Argon2id (slow). Sample byte positions across
	// each header region + body instead of iterating all ~120 bytes.
	// Boundaries: version byte, time field, memory field, threads,
	// length fields, salt start/mid/end, nonce start/mid/end, body
	// start/mid/end, last byte (tag).
	positions := []int{
		0,    // version
		1, 3, // time (uint32 BE)
		5, 8, // memory (uint32 BE)
		9,      // threads
		10, 13, // saltLen
		14, 17, // nonceLen
		wrapHeaderFixedLen,                // salt[0]
		wrapHeaderFixedLen + SaltSize/2,   // salt mid
		wrapHeaderFixedLen + SaltSize - 1, // salt last
		wrapHeaderFixedLen + SaltSize,     // nonce[0]
		len(wrapped) - 17,                 // body start (≈)
		len(wrapped) / 2,                  // body mid
		len(wrapped) - 1,                  // tag last byte
	}
	for _, i := range positions {
		if i >= len(wrapped) {
			continue
		}
		bad := append([]byte(nil), wrapped...)
		bad[i] ^= 0x01
		_, err := Unwrap(pw, bad)
		if err == nil {
			t.Fatalf("byte %d flip not detected", i)
		}
		if !errors.Is(err, ErrWrongPassword) && !errors.Is(err, ErrBadFormat) && !errors.Is(err, ErrBadParams) {
			t.Fatalf("byte %d flip: err = %v, want WrongPassword/BadFormat/BadParams", i, err)
		}
	}
}

func TestUnwrap_Truncated(t *testing.T) {
	pw := []byte("pw")
	vk := mustVaultKey(t)
	wrapped, err := Wrap(pw, vk, testParams)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// Sample lengths: each cut runs Argon2id, so iterating all is too
	// slow. Pick boundaries: 0, mid-header, end-of-header,
	// mid-salt, end-of-salt, mid-nonce, end-of-header+data,
	// mid-ciphertext, len-1.
	cuts := []int{
		0,
		wrapHeaderFixedLen / 2,
		wrapHeaderFixedLen - 1,
		wrapHeaderFixedLen,
		wrapHeaderFixedLen + SaltSize/2,
		wrapHeaderFixedLen + SaltSize - 1,
		len(wrapped) / 2,
		len(wrapped) - 1,
	}
	for _, cut := range cuts {
		_, err := Unwrap(pw, wrapped[:cut])
		if err == nil {
			t.Fatalf("len=%d not rejected", cut)
		}
	}
}

func TestUnwrap_UnknownVersion(t *testing.T) {
	pw := []byte("pw")
	vk := mustVaultKey(t)
	wrapped, err := Wrap(pw, vk, testParams)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped[0] = 0xFF
	if _, err := Unwrap(pw, wrapped); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("unknown version: err = %v, want ErrBadFormat", err)
	}
}

func TestWrap_RejectsBadKey(t *testing.T) {
	_, err := Wrap([]byte("pw"), make([]byte, 16), testParams)
	if !errors.Is(err, ErrBadKey) {
		t.Fatalf("Wrap wrong-size key: err = %v, want ErrBadKey", err)
	}
}

func TestWrap_RejectsBadParams(t *testing.T) {
	vk := mustVaultKey(t)
	bad := []Argon2Params{
		{Time: 0, Memory: 8 * 1024, Threads: 1},
		{Time: 1, Memory: 4 * 1024, Threads: 1}, // below 8 MiB floor
		{Time: 1, Memory: 8 * 1024, Threads: 0},
	}
	for i, p := range bad {
		_, err := Wrap([]byte("pw"), vk, p)
		if !errors.Is(err, ErrBadParams) {
			t.Fatalf("case %d params=%+v: err = %v, want ErrBadParams", i, p, err)
		}
	}
}

func TestUnwrap_DetectsTamperedParams(t *testing.T) {
	// Smashing the time field after wrap must fail authentication
	// because params are part of the AAD via the header bind.
	pw := []byte("pw")
	vk := mustVaultKey(t)
	wrapped, err := Wrap(pw, vk, testParams)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// Time field lives at bytes [1..5).
	wrapped[1] = 0
	wrapped[2] = 0
	wrapped[3] = 0
	wrapped[4] = 5 // valid but wrong
	_, err = Unwrap(pw, wrapped)
	if err == nil {
		t.Fatal("param tamper not detected")
	}
}

func TestWrapUnwrap_Property(t *testing.T) {
	rng := mathrand.New(mathrand.NewPCG(0xcaf3, 0xbabe))
	for i := 0; i < 25; i++ {
		// Reduced iteration count vs. the plan's 1000 because each
		// Wrap runs Argon2id which is expensive even at testParams.
		// hwkey/software_test.go does the 1000-input roundtrip; here
		// we just need enough random inputs to catch encoding bugs.
		pwLen := rng.IntN(64) + 1
		pw := make([]byte, pwLen)
		if _, err := rand.Read(pw); err != nil {
			t.Fatalf("iter %d rand pw: %v", i, err)
		}
		vk, err := NewVaultKey()
		if err != nil {
			t.Fatalf("iter %d NewVaultKey: %v", i, err)
		}
		wrapped, err := Wrap(pw, vk, testParams)
		if err != nil {
			t.Fatalf("iter %d Wrap: %v", i, err)
		}
		got, err := Unwrap(pw, wrapped)
		if err != nil {
			t.Fatalf("iter %d Unwrap: %v", i, err)
		}
		if !bytes.Equal(got, vk) {
			t.Fatalf("iter %d roundtrip mismatch", i)
		}
	}
}
