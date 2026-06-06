package vault

import (
	"bytes"
	"errors"
	"testing"
)

func TestWrapVaultKey_RoundTrip(t *testing.T) {
	st := newPasskeyStore(t)
	if err := st.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	want := st.snapshotVaultKey()
	kek := bytes.Repeat([]byte{4}, 32)
	aad := []byte("vault|cred|passkey-unlock-v1")

	wrapped, err := st.WrapVaultKey(kek, aad)
	if err != nil {
		t.Fatalf("WrapVaultKey: %v", err)
	}
	st.Lock()
	if err := st.UnlockWithKEK(kek, wrapped, aad); err != nil {
		t.Fatalf("UnlockWithKEK: %v", err)
	}
	if st.IsLocked() {
		t.Fatal("UnlockWithKEK should unlock the vault")
	}
	if got := st.snapshotVaultKey(); !bytes.Equal(got, want) {
		t.Fatal("passkey-unwrapped key differs from the password-unlocked key")
	}
}

func TestWrapVaultKey_LockedRefused(t *testing.T) {
	st := newPasskeyStore(t) // locked
	if _, err := st.WrapVaultKey(bytes.Repeat([]byte{4}, 32), []byte("aad")); !errors.Is(err, ErrLocked) {
		t.Fatalf("wrapping a locked vault: want ErrLocked, got %v", err)
	}
}

func TestUnlockWithKEK_WrongKEK_FailsClosed(t *testing.T) {
	st := newPasskeyStore(t)
	if err := st.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	aad := []byte("aad")
	wrapped, err := st.WrapVaultKey(bytes.Repeat([]byte{4}, 32), aad)
	if err != nil {
		t.Fatal(err)
	}
	st.Lock()
	if err := st.UnlockWithKEK(bytes.Repeat([]byte{5}, 32), wrapped, aad); err == nil {
		t.Fatal("a wrong KEK must fail")
	}
	if !st.IsLocked() {
		t.Fatal("a failed passkey unlock must leave the vault locked")
	}
}

func TestUnlockWithKEK_Tampered_FailsClosed(t *testing.T) {
	st := newPasskeyStore(t)
	if err := st.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	kek := bytes.Repeat([]byte{4}, 32)
	aad := []byte("aad")
	wrapped, err := st.WrapVaultKey(kek, aad)
	if err != nil {
		t.Fatal(err)
	}
	st.Lock()
	wrapped[len(wrapped)-1] ^= 0xff // flip a tag byte
	if err := st.UnlockWithKEK(kek, wrapped, aad); err == nil {
		t.Fatal("tampered ciphertext must fail closed")
	}
}

// Binding matters: a wrap made under one AAD must not unwrap under another.
func TestUnlockWithKEK_AADMismatch_FailsClosed(t *testing.T) {
	st := newPasskeyStore(t)
	if err := st.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	kek := bytes.Repeat([]byte{4}, 32)
	wrapped, err := st.WrapVaultKey(kek, []byte("cred-A"))
	if err != nil {
		t.Fatal(err)
	}
	st.Lock()
	if err := st.UnlockWithKEK(kek, wrapped, []byte("cred-B")); err == nil {
		t.Fatal("a different AAD must fail to unwrap")
	}
}
