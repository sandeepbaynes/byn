package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

func TestRenameVault_MovesDirAndUpdatesMeta(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	pw := []byte(testPassword)
	st, err := Init(ctx, dir, "acme", pw)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	_ = st.Close()

	if err := RenameVault(dir, "acme", "brand"); err != nil {
		t.Fatalf("RenameVault: %v", err)
	}
	if _, err := os.Stat(Dir(dir, "acme")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("old dir still present: %v", err)
	}
	if _, err := os.Stat(Dir(dir, "brand")); err != nil {
		t.Errorf("new dir missing: %v", err)
	}
	// Reopening under the new name validates the meta fingerprint and name.
	st2, err := Open(ctx, dir, "brand")
	if err != nil {
		t.Fatalf("Open brand: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	if err := st2.Unlock(pw); err != nil {
		t.Fatalf("unlock brand: %v", err)
	}
}

func TestRenameVault_DataSurvives(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	pw := []byte(testPassword)
	st, err := Init(ctx, dir, "acme", pw)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := st.Unlock(pw); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := st.PutEnvVar(ctx, defaultScope(), "API_KEY", []byte("s3cret"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = st.Close()

	if err := RenameVault(dir, "acme", "brand"); err != nil {
		t.Fatalf("RenameVault: %v", err)
	}
	st2, err := Open(ctx, dir, "brand")
	if err != nil {
		t.Fatalf("Open brand: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	if err := st2.Unlock(pw); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	got, err := st2.GetEnvVar(ctx, defaultScope(), "API_KEY")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("s3cret")) {
		t.Fatalf("value = %q, want s3cret", got.Value)
	}
}

func TestRenameVault_RefusesDefault(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), dir, DefaultVaultName, []byte(testPassword)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := RenameVault(dir, DefaultVaultName, "other"); !errors.Is(err, ErrProtectedVault) {
		t.Fatalf("got %v, want ErrProtectedVault", err)
	}
}

func TestRenameVault_DestExists(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	for _, n := range []string{"acme", "beta"} {
		st, err := Init(ctx, dir, n, []byte(testPassword))
		if err != nil {
			t.Fatalf("Init %s: %v", n, err)
		}
		_ = st.Close()
	}
	if err := RenameVault(dir, "acme", "beta"); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("got %v, want ErrVaultExists", err)
	}
}

func TestRenameVault_ToDefaultReserved(t *testing.T) {
	dir := t.TempDir()
	st, err := Init(context.Background(), dir, "acme", []byte(testPassword))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	_ = st.Close()
	if err := RenameVault(dir, "acme", DefaultVaultName); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("got %v, want ErrVaultExists", err)
	}
}

func TestRenameVault_NotInit(t *testing.T) {
	if err := RenameVault(t.TempDir(), "ghost", "other"); !errors.Is(err, ErrNotInit) {
		t.Fatalf("got %v, want ErrNotInit", err)
	}
}

func TestRenameVault_BadNames(t *testing.T) {
	if err := RenameVault(t.TempDir(), "Bad Name", "ok"); err == nil {
		t.Fatal("expected error for bad old name")
	}
	if err := RenameVault(t.TempDir(), "ok", "Bad/New"); err == nil {
		t.Fatal("expected error for bad new name")
	}
}
