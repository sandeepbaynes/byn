package vault

import (
	"context"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestEmptyCiphertextLen verifies that emptyCiphertextLen matches the actual
// overhead of EncryptWithAAD applied to an empty plaintext. This ensures that
// the length-based emptiness check in ListEnvVars / listEntriesForEnv is correct.
func TestEmptyCiphertextLen(t *testing.T) {
	// Compute expected overhead: 1 (version) + nonceSize (24) + overhead (16) = 41.
	aead, err := chacha20poly1305.NewX(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}
	expected := 1 + aead.NonceSize() + aead.Overhead()
	if emptyCiphertextLen != expected {
		t.Errorf("emptyCiphertextLen = %d, want %d", emptyCiphertextLen, expected)
	}
}

// TestListEnvVars_IsEmpty verifies that EntryInfo.IsEmpty is correctly set:
// true for entries with empty values and false for non-empty values.
func TestListEnvVars_IsEmpty(t *testing.T) {
	ctx := context.Background()
	st, _ := newOpenedVault(t)
	scope := defaultScope()

	// Put an entry with empty value.
	if err := st.PutEnvVar(ctx, scope, "EMPTY_KEY", []byte{}, PutOpt{}); err != nil {
		t.Fatalf("put empty: %v", err)
	}
	// Put an entry with a non-empty value.
	if err := st.PutEnvVar(ctx, scope, "NON_EMPTY_KEY", []byte("value"), PutOpt{}); err != nil {
		t.Fatalf("put non-empty: %v", err)
	}

	infos, err := st.ListEnvVars(ctx, scope)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	m := make(map[string]EntryInfo)
	for _, info := range infos {
		m[info.Name] = info
	}

	emptyInfo, ok := m["EMPTY_KEY"]
	if !ok {
		t.Fatal("EMPTY_KEY not in list")
	}
	if !emptyInfo.IsEmpty {
		t.Error("EMPTY_KEY: IsEmpty=false, want true")
	}

	nonEmptyInfo, ok := m["NON_EMPTY_KEY"]
	if !ok {
		t.Fatal("NON_EMPTY_KEY not in list")
	}
	if nonEmptyInfo.IsEmpty {
		t.Error("NON_EMPTY_KEY: IsEmpty=true, want false")
	}
}

// TestListEnvVars_IsEmptyInherited verifies IsEmpty propagates correctly for
// inherited (default-env) entries when listing from a non-default env.
func TestListEnvVars_IsEmptyInherited(t *testing.T) {
	ctx := context.Background()
	st, _ := newOpenedVault(t)
	defScope := defaultScope()

	// Put an empty value in the default env.
	if err := st.PutEnvVar(ctx, defScope, "BASE_EMPTY", []byte{}, PutOpt{}); err != nil {
		t.Fatalf("put base empty: %v", err)
	}

	// Create a non-default env and put an override with a non-empty value.
	if err := st.CreateEnv(ctx, defScope.Project, "staging"); err != nil {
		t.Fatalf("create staging env: %v", err)
	}
	stagingScope := Scope{Project: defScope.Project, Env: "staging"}
	if err := st.PutEnvVar(ctx, stagingScope, "OVERRIDE", []byte{}, PutOpt{}); err != nil {
		t.Fatalf("put override empty: %v", err)
	}

	infos, err := st.ListEnvVars(ctx, stagingScope)
	if err != nil {
		t.Fatalf("list staging: %v", err)
	}
	m := make(map[string]EntryInfo)
	for _, info := range infos {
		m[info.Name] = info
	}

	// BASE_EMPTY is inherited from default; should still show IsEmpty=true.
	baseInfo, ok := m["BASE_EMPTY"]
	if !ok {
		t.Fatal("BASE_EMPTY not in staging list (should be inherited)")
	}
	if !baseInfo.IsEmpty {
		t.Error("BASE_EMPTY: IsEmpty=false, want true (inherited empty value)")
	}
	if baseInfo.Source != SourceDefault {
		t.Errorf("BASE_EMPTY: Source=%v, want SourceDefault", baseInfo.Source)
	}

	// OVERRIDE is in staging scope with empty value.
	overrideInfo, ok := m["OVERRIDE"]
	if !ok {
		t.Fatal("OVERRIDE not in staging list")
	}
	if !overrideInfo.IsEmpty {
		t.Error("OVERRIDE: IsEmpty=false, want true")
	}
}
