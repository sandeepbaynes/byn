package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	mathrand "math/rand/v2"
	"testing"
)

func mustNewKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewVaultKey()
	if err != nil {
		t.Fatalf("NewVaultKey: %v", err)
	}
	return k
}

func TestEncryptWithAAD_Roundtrip(t *testing.T) {
	k := mustNewKey(t)
	aad := []byte("vault-id-123||env_var||AWS_KEY")
	ct, err := EncryptWithAAD(k, []byte("plaintext"), aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD: %v", err)
	}
	got, err := DecryptWithAAD(k, ct, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD: %v", err)
	}
	if !bytes.Equal(got, []byte("plaintext")) {
		t.Fatalf("got %q, want plaintext", got)
	}
}

func TestDecryptWithAAD_MismatchFails(t *testing.T) {
	k := mustNewKey(t)
	ct, err := EncryptWithAAD(k, []byte("plaintext"), []byte("a"))
	if err != nil {
		t.Fatalf("EncryptWithAAD: %v", err)
	}
	if _, err := DecryptWithAAD(k, ct, []byte("b")); !errors.Is(err, ErrTampered) {
		t.Fatalf("DecryptWithAAD with wrong AAD: err = %v, want ErrTampered", err)
	}
	// Decrypt without any AAD against a ciphertext that was AAD-bound
	// must also fail.
	if _, err := Decrypt(k, ct); !errors.Is(err, ErrTampered) {
		t.Fatalf("Decrypt (nil AAD) of AAD-bound ciphertext: err = %v, want ErrTampered", err)
	}
}

func TestEncryptDecrypt_NilAADCompat(t *testing.T) {
	k := mustNewKey(t)
	// Encrypt with nil AAD and Decrypt with nil AAD must continue to
	// work — i.e., AAD-less ciphertexts remain interoperable across
	// the old and new helpers.
	ct1, err := Encrypt(k, []byte("hi"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct2, err := EncryptWithAAD(k, []byte("hi"), nil)
	if err != nil {
		t.Fatalf("EncryptWithAAD nil: %v", err)
	}
	// Both formats round-trip through both decrypt helpers.
	for _, ct := range [][]byte{ct1, ct2} {
		if _, err := Decrypt(k, ct); err != nil {
			t.Errorf("Decrypt: %v", err)
		}
		if _, err := DecryptWithAAD(k, ct, nil); err != nil {
			t.Errorf("DecryptWithAAD nil: %v", err)
		}
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	k := mustNewKey(t)
	cases := [][]byte{
		nil,
		{},
		[]byte("x"),
		[]byte("aws_access_key_id=AKIA..."),
		bytes.Repeat([]byte{0xAB}, 4096),
	}
	for i, plain := range cases {
		ct, err := Encrypt(k, plain)
		if err != nil {
			t.Fatalf("case %d Encrypt: %v", i, err)
		}
		// Only check ciphertext doesn't contain plaintext for inputs ≥8
		// bytes — for shorter plaintexts, random bytes in the nonce or
		// tag have a non-trivial chance of matching by coincidence
		// (and this is a sanity check, not a security one — AEAD
		// already guarantees confidentiality).
		if len(plain) >= 8 && bytes.Contains(ct, plain) {
			t.Fatalf("case %d ciphertext contains plaintext", i)
		}
		got, err := Decrypt(k, ct)
		if err != nil {
			t.Fatalf("case %d Decrypt: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("case %d mismatch: got %x, want %x", i, got, plain)
		}
	}
}

func TestEncrypt_ProducesDifferentCiphertexts(t *testing.T) {
	k := mustNewKey(t)
	plain := []byte("same")
	a, err := Encrypt(k, plain)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := Encrypt(k, plain)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("nonce reused — identical ciphertexts")
	}
}

func TestEncrypt_RejectsBadKey(t *testing.T) {
	if _, err := Encrypt(make([]byte, 16), []byte("x")); !errors.Is(err, ErrBadKey) {
		t.Fatalf("Encrypt wrong-size key: err = %v, want ErrBadKey", err)
	}
}

func TestDecrypt_RejectsBadKey(t *testing.T) {
	if _, err := Decrypt(make([]byte, 16), []byte("x")); !errors.Is(err, ErrBadKey) {
		t.Fatalf("Decrypt wrong-size key: err = %v, want ErrBadKey", err)
	}
}

func TestDecrypt_RejectsTamperedCiphertext(t *testing.T) {
	k := mustNewKey(t)
	ct, err := Encrypt(k, []byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	for i := range ct {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if _, err := Decrypt(k, bad); !errors.Is(err, ErrTampered) {
			t.Fatalf("byte %d flip: err = %v, want ErrTampered", i, err)
		}
	}
}

func TestDecrypt_RejectsTruncated(t *testing.T) {
	k := mustNewKey(t)
	ct, err := Encrypt(k, []byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	for cut := 0; cut < len(ct); cut++ {
		if _, err := Decrypt(k, ct[:cut]); !errors.Is(err, ErrTampered) {
			t.Fatalf("len=%d: err = %v, want ErrTampered", cut, err)
		}
	}
}

func TestDecrypt_RejectsWrongKey(t *testing.T) {
	k1 := mustNewKey(t)
	k2 := mustNewKey(t)
	ct, err := Encrypt(k1, []byte("x"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(k2, ct); !errors.Is(err, ErrTampered) {
		t.Fatalf("wrong key: err = %v, want ErrTampered", err)
	}
}

func TestDecrypt_RejectsUnknownVersion(t *testing.T) {
	k := mustNewKey(t)
	ct, err := Encrypt(k, []byte("x"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct[0] = 0xFF
	if _, err := Decrypt(k, ct); !errors.Is(err, ErrTampered) {
		t.Fatalf("bad version: err = %v, want ErrTampered", err)
	}
}

func TestEncryptDecrypt_Property(t *testing.T) {
	k := mustNewKey(t)
	rng := mathrand.New(mathrand.NewPCG(0xa11c, 0xe))
	for i := 0; i < 1000; i++ {
		n := rng.IntN(4096)
		buf := make([]byte, n)
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("iter %d rand: %v", i, err)
		}
		ct, err := Encrypt(k, buf)
		if err != nil {
			t.Fatalf("iter %d Encrypt: %v", i, err)
		}
		got, err := Decrypt(k, ct)
		if err != nil {
			t.Fatalf("iter %d Decrypt: %v", i, err)
		}
		if !bytes.Equal(got, buf) {
			t.Fatalf("iter %d mismatch", i)
		}
	}
}
