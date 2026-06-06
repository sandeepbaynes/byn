package hwkey

import (
	"bytes"
	"crypto/rand"
	"errors"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

func newTestSoftware(t *testing.T) *Software {
	t.Helper()
	dir := t.TempDir()
	return NewSoftware(filepath.Join(dir, "hwkey-software.bin"))
}

func TestSoftware_NameAndAvailable(t *testing.T) {
	s := newTestSoftware(t)
	if got, want := s.Name(), "software"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
	if !s.Available() {
		t.Fatal("Available() = false, want true")
	}
}

func TestSoftware_CreateOrLoad_CreatesNewKey(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad: %v", err)
	}
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := info.Mode().Perm(); got != softwareKeyFileMode {
		t.Fatalf("key file mode = %o, want %o", got, softwareKeyFileMode)
	}
}

func TestSoftware_CreateOrLoad_IsIdempotent(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("first CreateOrLoad: %v", err)
	}
	key1 := append([]byte(nil), s.key...)

	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("second CreateOrLoad: %v", err)
	}
	if !bytes.Equal(key1, s.key) {
		t.Fatal("CreateOrLoad changed the key on second call")
	}
}

func TestSoftware_CreateOrLoad_LoadsExistingFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hwkey-software.bin")

	s1 := NewSoftware(path)
	if err := s1.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad s1: %v", err)
	}
	wantKey := append([]byte(nil), s1.key...)

	s2 := NewSoftware(path)
	if err := s2.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad s2: %v", err)
	}
	if !bytes.Equal(s2.key, wantKey) {
		t.Fatal("s2 loaded a different key than s1 wrote")
	}
}

func TestSoftware_CreateOrLoad_RejectsInsecureMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hwkey-software.bin")

	s := NewSoftware(path)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	s2 := NewSoftware(path)
	err := s2.CreateOrLoad()
	if err == nil {
		t.Fatal("CreateOrLoad accepted world-readable key file")
	}
}

func TestSoftware_Wrap_BeforeCreateReturnsErrKeyNotFound(t *testing.T) {
	s := newTestSoftware(t)
	_, err := s.Wrap([]byte("x"))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Wrap pre-CreateOrLoad err = %v, want ErrKeyNotFound", err)
	}
}

func TestSoftware_Unwrap_BeforeCreateReturnsErrKeyNotFound(t *testing.T) {
	s := newTestSoftware(t)
	_, err := s.Unwrap([]byte("x"))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Unwrap pre-CreateOrLoad err = %v, want ErrKeyNotFound", err)
	}
}

func TestSoftware_WrapUnwrap_Roundtrip(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad: %v", err)
	}
	cases := [][]byte{
		nil,
		{},
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 1024),
	}
	for i, plain := range cases {
		ct, err := s.Wrap(plain)
		if err != nil {
			t.Fatalf("case %d Wrap: %v", i, err)
		}
		got, err := s.Unwrap(ct)
		if err != nil {
			t.Fatalf("case %d Unwrap: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("case %d roundtrip mismatch: got %x, want %x", i, got, plain)
		}
	}
}

func TestSoftware_Wrap_ProducesDifferentCiphertexts(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad: %v", err)
	}
	plain := []byte("same input")
	a, err := s.Wrap(plain)
	if err != nil {
		t.Fatalf("Wrap a: %v", err)
	}
	b, err := s.Wrap(plain)
	if err != nil {
		t.Fatalf("Wrap b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two Wrap calls produced identical ciphertext (nonce reuse?)")
	}
}

func TestSoftware_Unwrap_RejectsTamperedCiphertext(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad: %v", err)
	}
	ct, err := s.Wrap([]byte("plaintext"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	for i := range ct {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		_, err := s.Unwrap(bad)
		if !errors.Is(err, ErrUnwrap) {
			t.Fatalf("Unwrap of byte-%d-flipped ciphertext err = %v, want ErrUnwrap", i, err)
		}
	}
}

func TestSoftware_Unwrap_RejectsTruncated(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad: %v", err)
	}
	ct, err := s.Wrap([]byte("plaintext"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	for cut := 0; cut < len(ct); cut++ {
		_, err := s.Unwrap(ct[:cut])
		if !errors.Is(err, ErrUnwrap) {
			t.Fatalf("Unwrap of len=%d err = %v, want ErrUnwrap", cut, err)
		}
	}
}

func TestSoftware_Unwrap_RejectsWrongKey(t *testing.T) {
	dir := t.TempDir()
	s1 := NewSoftware(filepath.Join(dir, "k1"))
	s2 := NewSoftware(filepath.Join(dir, "k2"))
	if err := s1.CreateOrLoad(); err != nil {
		t.Fatalf("s1 CreateOrLoad: %v", err)
	}
	if err := s2.CreateOrLoad(); err != nil {
		t.Fatalf("s2 CreateOrLoad: %v", err)
	}
	ct, err := s1.Wrap([]byte("hi"))
	if err != nil {
		t.Fatalf("s1 Wrap: %v", err)
	}
	_, err = s2.Unwrap(ct)
	if !errors.Is(err, ErrUnwrap) {
		t.Fatalf("s2.Unwrap(s1 ciphertext) err = %v, want ErrUnwrap", err)
	}
}

func TestSoftware_Unwrap_RejectsUnknownVersion(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad: %v", err)
	}
	ct, err := s.Wrap([]byte("hi"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	ct[0] = 0xFF
	_, err = s.Unwrap(ct)
	if !errors.Is(err, ErrUnwrap) {
		t.Fatalf("Unwrap unknown-version err = %v, want ErrUnwrap", err)
	}
}

func TestSoftware_Erase_RemovesKeyFile(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad: %v", err)
	}
	if err := s.Erase(); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if _, err := os.Stat(s.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after Erase, stat err = %v, want ErrNotExist", err)
	}
	// In-memory key cleared; subsequent Wrap fails until CreateOrLoad.
	if _, err := s.Wrap([]byte("x")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("post-Erase Wrap err = %v, want ErrKeyNotFound", err)
	}
}

func TestSoftware_Erase_OnMissingKeyReturnsErrKeyNotFound(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.Erase(); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Erase pre-CreateOrLoad err = %v, want ErrKeyNotFound", err)
	}
}

func TestSoftware_RoundtripProperty(t *testing.T) {
	s := newTestSoftware(t)
	if err := s.CreateOrLoad(); err != nil {
		t.Fatalf("CreateOrLoad: %v", err)
	}
	// Deterministic across runs: seed from a fixed source.
	rng := mathrand.New(mathrand.NewPCG(0x5eed, 0xface))
	for i := 0; i < 1000; i++ {
		n := rng.IntN(4096)
		buf := make([]byte, n)
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("iter %d rand: %v", i, err)
		}
		ct, err := s.Wrap(buf)
		if err != nil {
			t.Fatalf("iter %d Wrap (n=%d): %v", i, n, err)
		}
		got, err := s.Unwrap(ct)
		if err != nil {
			t.Fatalf("iter %d Unwrap (n=%d): %v", i, n, err)
		}
		if !bytes.Equal(got, buf) {
			t.Fatalf("iter %d roundtrip mismatch (n=%d)", i, n)
		}
	}
}
