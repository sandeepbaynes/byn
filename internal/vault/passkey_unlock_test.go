package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func addTestPasskey(t *testing.T, st *Store, credID []byte) {
	t.Helper()
	if err := st.AddPasskey(context.Background(), Passkey{CredentialID: credID, PublicKey: []byte("k")}); err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
}

func TestPasskeyUnlock_AddAndGet(t *testing.T) {
	st := newPasskeyStore(t)
	ctx := context.Background()
	credID := []byte{1, 2, 3}
	addTestPasskey(t, st, credID)
	rec := PasskeyUnlock{
		CredentialID:    credID,
		PRFSalt:         bytes.Repeat([]byte{9}, 32),
		WrappedVaultKey: []byte("wrapped-vk-ciphertext"),
		HKDFInfoVersion: 1,
		AEADAlg:         "xchacha20poly1305",
		Label:           "Touch ID",
	}
	if err := st.AddPasskeyUnlock(ctx, rec); err != nil {
		t.Fatalf("AddPasskeyUnlock: %v", err)
	}
	got, err := st.PasskeyUnlockByCredentialID(ctx, credID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got.WrappedVaultKey, rec.WrappedVaultKey) || !bytes.Equal(got.PRFSalt, rec.PRFSalt) ||
		got.AEADAlg != rec.AEADAlg || got.HKDFInfoVersion != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}
}

func TestPasskeyUnlock_GetMissing(t *testing.T) {
	st := newPasskeyStore(t)
	if _, err := st.PasskeyUnlockByCredentialID(context.Background(), []byte("nope")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestPasskeyUnlock_List(t *testing.T) {
	st := newPasskeyStore(t)
	ctx := context.Background()
	for _, id := range [][]byte{{1}, {2}} {
		addTestPasskey(t, st, id)
		if err := st.AddPasskeyUnlock(ctx, PasskeyUnlock{
			CredentialID: id, PRFSalt: bytes.Repeat([]byte{1}, 32), WrappedVaultKey: []byte("w"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := st.PasskeyUnlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2, got %d", len(list))
	}
}

// Revoking a credential must cascade-delete its PRF-unlock record (FK ON DELETE
// CASCADE), so a revoked passkey can never unlock the vault.
func TestPasskeyUnlock_CascadeOnRevoke(t *testing.T) {
	st := newPasskeyStore(t)
	ctx := context.Background()
	credID := []byte{7}
	addTestPasskey(t, st, credID)
	if err := st.AddPasskeyUnlock(ctx, PasskeyUnlock{
		CredentialID: credID, PRFSalt: bytes.Repeat([]byte{1}, 32), WrappedVaultKey: []byte("w"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeletePasskey(ctx, credID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PasskeyUnlockByCredentialID(ctx, credID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke should cascade-delete the unlock record, got %v", err)
	}
}

func TestPasskeyUnlock_RequiresFields(t *testing.T) {
	st := newPasskeyStore(t)
	addTestPasskey(t, st, []byte{1})
	if err := st.AddPasskeyUnlock(context.Background(), PasskeyUnlock{CredentialID: []byte{1}}); err == nil {
		t.Fatal("missing prf_salt/wrapped_vault_key should error")
	}
}
