package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

func TestChangePassword_OldFailsNewWorks(t *testing.T) {
	st, _ := newOpenedVault(t) // init + unlock with testPassword
	newPw := []byte("brand-new-passphrase-9000")
	if err := st.ChangePassword([]byte(testPassword), newPw); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	// Re-wrap must not change lock state: still unlocked.
	if st.IsLocked() {
		t.Error("ChangePassword locked an unlocked vault")
	}
	// Old password no longer unlocks; the new one does.
	st.Lock()
	if err := st.Unlock([]byte(testPassword)); !errors.Is(err, vcrypto.ErrWrongPassword) {
		t.Fatalf("old password still unlocks: %v", err)
	}
	if err := st.Unlock(newPw); err != nil {
		t.Fatalf("new password failed to unlock: %v", err)
	}
}

func TestChangePassword_WrongOld(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.ChangePassword([]byte("not-the-old-one"), []byte("whatever-new")); !errors.Is(err, vcrypto.ErrWrongPassword) {
		t.Fatalf("got %v, want ErrWrongPassword", err)
	}
}

func TestChangePassword_EmptyNew(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.ChangePassword([]byte(testPassword), nil); err == nil {
		t.Fatal("expected an error for an empty new password")
	}
}

// Data written under the old password is readable after the change — only
// the wrapping changes, the vault key (and thus the ciphertext) does not.
func TestChangePassword_DataSurvives(t *testing.T) {
	st, dir := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "API_KEY", []byte("s3cret"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	newPw := []byte("rotated-passphrase")
	if err := st.ChangePassword([]byte(testPassword), newPw); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	st.Close()

	// Reopen from disk — this validates meta.json's fingerprint against the
	// freshly-written wrapped.key — then unlock with the new password.
	st2, err := Open(ctx, dir, DefaultVaultName)
	if err != nil {
		t.Fatalf("Open after change: %v (meta fingerprint not updated?)", err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	if err := st2.Unlock(newPw); err != nil {
		t.Fatalf("unlock after reopen: %v", err)
	}
	got, err := st2.GetEnvVar(ctx, defaultScope(), "API_KEY")
	if err != nil {
		t.Fatalf("get after change: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("s3cret")) {
		t.Fatalf("value after change = %q, want s3cret", got.Value)
	}
}
