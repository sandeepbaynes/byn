package vault

import (
	"bytes"
	"errors"
	"testing"
)

func TestDeriveSubkey(t *testing.T) {
	st, _ := newOpenedVault(t)

	k1, err := st.DeriveSubkey("byn:trust-vk-mac:v1")
	if err != nil {
		t.Fatalf("DeriveSubkey: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("len = %d, want 32", len(k1))
	}

	// Deterministic for the same info label.
	k1b, err := st.DeriveSubkey("byn:trust-vk-mac:v1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k1b) {
		t.Fatal("DeriveSubkey is not deterministic for the same info")
	}

	// Different info ⇒ different key (domain separation).
	k2, err := st.DeriveSubkey("byn:something-else:v1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("different info labels produced the same subkey")
	}

	// Locked ⇒ ErrLocked, no key material.
	st.Lock()
	if _, err := st.DeriveSubkey("byn:trust-vk-mac:v1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked DeriveSubkey err = %v, want ErrLocked", err)
	}
}

func TestDeriveSubkeyWithPassword(t *testing.T) {
	st, _ := newOpenedVault(t)
	const info = "byn:trust-vk-mac:v1"

	// Same vault key ⇒ identical to the in-memory derivation.
	want, err := st.DeriveSubkey(info)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.DeriveSubkeyWithPassword([]byte(testPassword), info)
	if err != nil {
		t.Fatalf("DeriveSubkeyWithPassword: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("password-derived subkey differs from in-memory derivation")
	}

	// Works while locked — grant time may have no in-memory key.
	st.Lock()
	got2, err := st.DeriveSubkeyWithPassword([]byte(testPassword), info)
	if err != nil {
		t.Fatalf("DeriveSubkeyWithPassword (locked): %v", err)
	}
	if !bytes.Equal(got2, want) {
		t.Fatal("locked password-derived subkey differs from unlocked one")
	}

	// Wrong password ⇒ error, no key.
	if _, err := st.DeriveSubkeyWithPassword([]byte("wrong-password"), info); err == nil {
		t.Fatal("expected an error on wrong password")
	}
}
