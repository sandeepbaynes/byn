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
