package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func newPasskeyStore(t *testing.T) *Store {
	t.Helper()
	st, err := Init(context.Background(), t.TempDir(), DefaultVaultName, []byte("pw"))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestPasskey_AddAndGet(t *testing.T) {
	st := newPasskeyStore(t)
	ctx := context.Background()
	pk := Passkey{
		CredentialID: []byte{1, 2, 3},
		PublicKey:    []byte("pubkey-bytes"),
		SignCount:    5,
		AAGUID:       []byte{9, 9},
		Transports:   "internal",
		Label:        "MacBook Touch ID",
	}
	if err := st.AddPasskey(ctx, pk); err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
	got, err := st.PasskeyByCredentialID(ctx, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("PasskeyByCredentialID: %v", err)
	}
	if !bytes.Equal(got.PublicKey, pk.PublicKey) || got.SignCount != 5 || got.Label != pk.Label {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}
}

func TestPasskey_GetMissing(t *testing.T) {
	st := newPasskeyStore(t)
	_, err := st.PasskeyByCredentialID(context.Background(), []byte("nope"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestPasskey_DuplicateCredentialIDRejected(t *testing.T) {
	st := newPasskeyStore(t)
	ctx := context.Background()
	pk := Passkey{CredentialID: []byte{1}, PublicKey: []byte("k")}
	if err := st.AddPasskey(ctx, pk); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPasskey(ctx, pk); err == nil {
		t.Fatal("expected a duplicate credential_id to be rejected")
	}
}

func TestPasskey_RequiresFields(t *testing.T) {
	st := newPasskeyStore(t)
	if err := st.AddPasskey(context.Background(), Passkey{PublicKey: []byte("k")}); err == nil {
		t.Fatal("missing credential_id should error")
	}
}

func TestPasskey_List(t *testing.T) {
	st := newPasskeyStore(t)
	ctx := context.Background()
	for _, id := range [][]byte{{1}, {2}} {
		if err := st.AddPasskey(ctx, Passkey{CredentialID: id, PublicKey: []byte("k")}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := st.Passkeys(ctx)
	if err != nil {
		t.Fatalf("Passkeys: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2, got %d", len(list))
	}
}

func TestPasskey_UpdateSignCount(t *testing.T) {
	st := newPasskeyStore(t)
	ctx := context.Background()
	if err := st.AddPasskey(ctx, Passkey{CredentialID: []byte{1}, PublicKey: []byte("k"), SignCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdatePasskeySignCount(ctx, []byte{1}, 42); err != nil {
		t.Fatalf("UpdatePasskeySignCount: %v", err)
	}
	got, _ := st.PasskeyByCredentialID(ctx, []byte{1})
	if got.SignCount != 42 {
		t.Fatalf("sign count = %d, want 42", got.SignCount)
	}
	if err := st.UpdatePasskeySignCount(ctx, []byte("absent"), 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update absent: want ErrNotFound, got %v", err)
	}
}

func TestPasskey_Delete(t *testing.T) {
	st := newPasskeyStore(t)
	ctx := context.Background()
	if err := st.AddPasskey(ctx, Passkey{CredentialID: []byte{1}, PublicKey: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	removed, err := st.DeletePasskey(ctx, []byte{1})
	if err != nil || !removed {
		t.Fatalf("DeletePasskey: removed=%v err=%v", removed, err)
	}
	removed, _ = st.DeletePasskey(ctx, []byte{1})
	if removed {
		t.Error("second delete should report removed=false")
	}
}

func TestPasskey_ClearEnrollments(t *testing.T) {
	st := newPasskeyStore(t)
	ctx := context.Background()

	// Enroll two credentials, one of which also has a PRF-unlock record
	// (the FK requires the passkey row to exist first).
	for _, id := range [][]byte{{1}, {2}} {
		if err := st.AddPasskey(ctx, Passkey{CredentialID: id, PublicKey: []byte("k")}); err != nil {
			t.Fatalf("AddPasskey %v: %v", id, err)
		}
	}
	if err := st.AddPasskeyUnlock(ctx, PasskeyUnlock{
		CredentialID:    []byte{1},
		PRFSalt:         bytes.Repeat([]byte{0xAB}, 32),
		WrappedVaultKey: []byte("wrapped"),
	}); err != nil {
		t.Fatalf("AddPasskeyUnlock: %v", err)
	}

	// Sanity: both tables are non-empty before the clear.
	pks, err := st.Passkeys(ctx)
	if err != nil || len(pks) != 2 {
		t.Fatalf("pre-clear Passkeys: len=%d err=%v", len(pks), err)
	}
	unlocks, err := st.PasskeyUnlocks(ctx)
	if err != nil || len(unlocks) != 1 {
		t.Fatalf("pre-clear PasskeyUnlocks: len=%d err=%v", len(unlocks), err)
	}

	if err := st.ClearPasskeyEnrollments(ctx); err != nil {
		t.Fatalf("ClearPasskeyEnrollments: %v", err)
	}

	// Both tables are now empty.
	pks, err = st.Passkeys(ctx)
	if err != nil || len(pks) != 0 {
		t.Fatalf("post-clear Passkeys: len=%d err=%v", len(pks), err)
	}
	unlocks, err = st.PasskeyUnlocks(ctx)
	if err != nil || len(unlocks) != 0 {
		t.Fatalf("post-clear PasskeyUnlocks: len=%d err=%v", len(unlocks), err)
	}

	// Idempotent: clearing again on empty tables is a no-op success.
	if err := st.ClearPasskeyEnrollments(ctx); err != nil {
		t.Fatalf("second ClearPasskeyEnrollments: %v", err)
	}

	// The vault is otherwise intact: the default project/env still resolve.
	if _, err := st.ListProjects(ctx); err != nil {
		t.Fatalf("vault unusable after clear: %v", err)
	}
}
