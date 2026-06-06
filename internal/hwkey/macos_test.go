//go:build darwin && cgo

package hwkey

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"
)

// uniqueHandle returns a per-test keychain tag so parallel runs and
// rerun-after-crash don't collide with leftover entries.
func uniqueHandle(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return fmt.Sprintf("com.byn.test.%x.%d", b, time.Now().UnixNano())
}

// requireSE skips the test if Secure Enclave creation isn't available
// on this host. On unsigned binaries / CI VMs without SE, key creation
// returns errSecMissingEntitlement and we cannot proceed.
func requireSE(t *testing.T) *MacOS {
	t.Helper()
	m := NewMacOS(uniqueHandle(t))
	if !m.Available() {
		t.Skip("Secure Enclave API unavailable on this host")
	}
	if err := m.CreateOrLoad(); err != nil {
		if errors.Is(err, ErrProviderUnavailable) {
			t.Skip("SE provider reports unavailable")
		}
		// Most common reason in dev: errSecMissingEntitlement on
		// unsigned binaries, or running on Intel Macs without an SE.
		t.Skipf("SE key creation failed (likely missing entitlement / no SE): %v", err)
	}
	t.Cleanup(func() {
		if err := m.Erase(); err != nil && !errors.Is(err, ErrKeyNotFound) {
			t.Logf("cleanup Erase: %v", err)
		}
	})
	return m
}

func TestMacOS_NameAndProvider(t *testing.T) {
	m := NewMacOS("com.byn.test.name")
	if got, want := m.Name(), "macos-secure-enclave"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
	// Available() is cheap and must not panic regardless of SE
	// presence.
	_ = m.Available()
}

func TestMacOS_CreateOrLoad_Idempotent(t *testing.T) {
	m := requireSE(t)
	if err := m.CreateOrLoad(); err != nil {
		t.Fatalf("second CreateOrLoad: %v", err)
	}
}

func TestMacOS_WrapUnwrap_Roundtrip(t *testing.T) {
	m := requireSE(t)
	plain := []byte("vault-key-material-32-bytes-long")
	ct, err := m.Wrap(plain)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("ciphertext contains plaintext bytes")
	}
	got, err := m.Unwrap(ct)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %x, want %x", got, plain)
	}
}

func TestMacOS_Wrap_ProducesDifferentCiphertexts(t *testing.T) {
	m := requireSE(t)
	plain := []byte("repeat-me")
	a, err := m.Wrap(plain)
	if err != nil {
		t.Fatalf("Wrap a: %v", err)
	}
	b, err := m.Wrap(plain)
	if err != nil {
		t.Fatalf("Wrap b: %v", err)
	}
	// ECIES uses a fresh ephemeral keypair per encryption — outputs
	// must differ.
	if bytes.Equal(a, b) {
		t.Fatal("two Wrap calls produced identical ciphertext")
	}
}

func TestMacOS_Unwrap_RejectsTamperedCiphertext(t *testing.T) {
	m := requireSE(t)
	ct, err := m.Wrap([]byte("plaintext"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// Flip one bit in the middle (avoid header bytes that some impls
	// validate before the MAC).
	bad := append([]byte(nil), ct...)
	bad[len(bad)/2] ^= 0x01
	if _, err := m.Unwrap(bad); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("Unwrap tampered: err = %v, want ErrUnwrap", err)
	}
}

func TestMacOS_Unwrap_RejectsWrongKey(t *testing.T) {
	m1 := requireSE(t)
	m2 := requireSE(t)
	ct, err := m1.Wrap([]byte("hi"))
	if err != nil {
		t.Fatalf("m1 Wrap: %v", err)
	}
	if _, err := m2.Unwrap(ct); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("m2.Unwrap(m1 ciphertext): err = %v, want ErrUnwrap", err)
	}
}

func TestMacOS_Erase_RemovesKey(t *testing.T) {
	m := NewMacOS(uniqueHandle(t))
	if !m.Available() {
		t.Skip("SE unavailable")
	}
	if err := m.CreateOrLoad(); err != nil {
		t.Skipf("CreateOrLoad failed (likely no SE / missing entitlement): %v", err)
	}
	if err := m.Erase(); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if _, err := m.Wrap([]byte("x")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("post-Erase Wrap: err = %v, want ErrKeyNotFound", err)
	}
	if err := m.Erase(); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("second Erase: err = %v, want ErrKeyNotFound", err)
	}
}
