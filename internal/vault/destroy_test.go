package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

func TestVerifyPassword_KeepsLockState(t *testing.T) {
	st, _ := newOpenedVault(t) // unlocked

	// Correct password while UNLOCKED → ok, still unlocked.
	if err := st.VerifyPassword([]byte(testPassword)); err != nil {
		t.Fatalf("VerifyPassword (unlocked): %v", err)
	}
	if st.IsLocked() {
		t.Error("VerifyPassword locked an unlocked vault")
	}

	// Correct password while LOCKED → ok, stays LOCKED (the whole point).
	st.Lock()
	if err := st.VerifyPassword([]byte(testPassword)); err != nil {
		t.Fatalf("VerifyPassword (locked): %v", err)
	}
	if !st.IsLocked() {
		t.Error("VerifyPassword unlocked a locked vault — must not change lock state")
	}
}

func TestVerifyPassword_MissingWrappedKey(t *testing.T) {
	st, dir := newOpenedVault(t)
	st.Lock()
	if err := os.Remove(filepath.Join(Dir(dir, DefaultVaultName), wrappedFilename)); err != nil {
		t.Fatalf("remove wrapped key: %v", err)
	}
	if err := st.VerifyPassword([]byte(testPassword)); err == nil {
		t.Fatal("expected an error when the wrapped key is missing")
	}
}

func TestVerifyPassword_Wrong(t *testing.T) {
	st, _ := newOpenedVault(t)
	st.Lock()
	if err := st.VerifyPassword([]byte("not-the-password")); !errors.Is(err, vcrypto.ErrWrongPassword) {
		t.Fatalf("got %v, want ErrWrongPassword", err)
	}
	if !st.IsLocked() {
		t.Error("a wrong VerifyPassword changed lock state")
	}
}

func TestDestroy_RemovesVaultDir(t *testing.T) {
	dir := t.TempDir()
	st, err := Init(context.Background(), dir, "acme", []byte(testPassword))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	_ = st.Close()
	vdir := Dir(dir, "acme")
	if _, err := os.Stat(vdir); err != nil {
		t.Fatalf("vault dir missing pre-destroy: %v", err)
	}
	if err := Destroy(dir, "acme"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(vdir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("vault dir still present after Destroy: %v", err)
	}
}

func TestDestroy_RefusesDefault(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), dir, DefaultVaultName, []byte(testPassword)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := Destroy(dir, DefaultVaultName); !errors.Is(err, ErrProtectedVault) {
		t.Fatalf("got %v, want ErrProtectedVault", err)
	}
	if _, err := os.Stat(Dir(dir, DefaultVaultName)); err != nil {
		t.Error("default vault dir was removed despite refusal")
	}
}

func TestDestroy_NotInit(t *testing.T) {
	if err := Destroy(t.TempDir(), "ghost"); !errors.Is(err, ErrNotInit) {
		t.Fatalf("got %v, want ErrNotInit", err)
	}
}

func TestDestroy_BadName(t *testing.T) {
	if err := Destroy(t.TempDir(), "bad/name"); err == nil {
		t.Fatal("expected a validation error for a bad vault name")
	}
}

func TestOverwriteWithRandom_ChangesContentSameLength(t *testing.T) {
	f := filepath.Join(t.TempDir(), "k")
	orig := bytes.Repeat([]byte{0xAB}, 96)
	if err := os.WriteFile(f, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := overwriteWithRandom(f); err != nil {
		t.Fatalf("overwriteWithRandom: %v", err)
	}
	got, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(orig) {
		t.Fatalf("length changed: %d vs %d", len(got), len(orig))
	}
	if bytes.Equal(got, orig) {
		t.Error("content unchanged after overwrite")
	}
}

func TestOverwriteWithRandom_Missing(t *testing.T) {
	if err := overwriteWithRandom(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected an error overwriting a missing file")
	}
}
