package vault

import (
	"context"
	"errors"
	"testing"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// rowCiphertext reads the raw stored ciphertext for an env_var by name.
func rowCiphertext(t *testing.T, st *Store, name string) []byte {
	t.Helper()
	var ct []byte
	if err := st.db.QueryRowContext(context.Background(),
		`SELECT value FROM entries WHERE kind='env_var' AND name=?`, name).Scan(&ct); err != nil {
		t.Fatalf("read ciphertext for %q: %v", name, err)
	}
	return ct
}

// rowAADVersion reads the stored aad_version for an env_var by name.
func rowAADVersion(t *testing.T, st *Store, name string) int {
	t.Helper()
	var ver int
	if err := st.db.QueryRowContext(context.Background(),
		`SELECT aad_version FROM entries WHERE kind='env_var' AND name=?`, name).Scan(&ver); err != nil {
		t.Fatalf("read aad_version for %q: %v", name, err)
	}
	return ver
}

// rewriteAsLegacyV1 takes an existing row and rewrites it in place as a legacy
// v1 row (sealed directly with the vault key, aad_version=1) carrying value —
// simulating a vault written before per-row keys existed.
func rewriteAsLegacyV1(t *testing.T, st *Store, name string, value []byte) {
	t.Helper()
	vk := st.snapshotVaultKey()
	if vk == nil {
		t.Fatal("vault is locked")
	}
	defer zero(vk)
	ct, err := vcrypto.EncryptWithAAD(vk, value, st.entryAAD(kindAADEnvVar, name))
	if err != nil {
		t.Fatalf("v1 seal: %v", err)
	}
	if _, err := st.db.ExecContext(context.Background(),
		`UPDATE entries SET value=?, aad_version=1 WHERE kind='env_var' AND name=?`, ct, name); err != nil {
		t.Fatalf("rewrite as v1: %v", err)
	}
}

// TestStore_PutWritesRowKeyVersion: new writes use the per-row-key scheme
// (aad_version=2) and round-trip correctly.
func TestStore_PutWritesRowKeyVersion(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "API_KEY", []byte("sekret"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if v := rowAADVersion(t, st, "API_KEY"); v != currentAADVersion {
		t.Fatalf("aad_version=%d, want %d (per-row key)", v, currentAADVersion)
	}
	e, err := st.GetEnvVar(ctx, defaultScope(), "API_KEY")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(e.Value) != "sekret" {
		t.Fatalf("value=%q, want sekret", e.Value)
	}
}

// TestStore_LegacyV1RowReadable: a row sealed under the OLD scheme (vault key
// direct, aad_version=1) is still decryptable — upgrade compatibility.
func TestStore_LegacyV1RowReadable(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "LEGACY", []byte("placeholder"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	rewriteAsLegacyV1(t, st, "LEGACY", []byte("v1-secret"))
	if v := rowAADVersion(t, st, "LEGACY"); v != aadVersionVaultKey {
		t.Fatalf("setup: aad_version=%d, want 1", v)
	}
	e, err := st.GetEnvVar(ctx, defaultScope(), "LEGACY")
	if err != nil {
		t.Fatalf("get legacy v1: %v", err)
	}
	if string(e.Value) != "v1-secret" {
		t.Fatalf("value=%q, want v1-secret (must decrypt via the v1 path)", e.Value)
	}
}

// TestStore_RenameMigratesV1ToV2: renaming a legacy v1 row re-seals it under the
// new name's per-row key (aad_version becomes 2), value preserved.
func TestStore_RenameMigratesV1ToV2(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "OLD", []byte("x"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	rewriteAsLegacyV1(t, st, "OLD", []byte("carry-me"))
	if err := st.RenameEnvVar(ctx, defaultScope(), "OLD", "NEW"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if v := rowAADVersion(t, st, "NEW"); v != currentAADVersion {
		t.Fatalf("renamed row aad_version=%d, want %d", v, currentAADVersion)
	}
	e, err := st.GetEnvVar(ctx, defaultScope(), "NEW")
	if err != nil {
		t.Fatalf("get renamed: %v", err)
	}
	if string(e.Value) != "carry-me" {
		t.Fatalf("value=%q, want carry-me", e.Value)
	}
}

// TestStore_UnknownAADVersionRejected: an out-of-band aad_version is treated as
// corruption — get fails rather than silently mis-decrypting.
func TestStore_UnknownAADVersionRejected(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "BAD", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := st.db.ExecContext(ctx,
		`UPDATE entries SET aad_version=99 WHERE kind='env_var' AND name='BAD'`); err != nil {
		t.Fatalf("corrupt version: %v", err)
	}
	if _, err := st.GetEnvVar(ctx, defaultScope(), "BAD"); err == nil {
		t.Fatal("get with unknown aad_version must error")
	}
}

// TestCaptureRowKeys_ReturnsDecryptingKeys: the captured keys actually decrypt
// their rows (the property the capability relies on).
func TestCaptureRowKeys_ReturnsDecryptingKeys(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	vals := map[string]string{"DB_URL": "pg://x", "API_KEY": "k-123"}
	for n, v := range vals {
		if err := st.PutEnvVar(ctx, defaultScope(), n, []byte(v), PutOpt{}); err != nil {
			t.Fatalf("put %s: %v", n, err)
		}
	}
	keys, err := st.CaptureRowKeys(ctx, defaultScope(), []string{"DB_URL", "API_KEY"})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	for n, want := range vals {
		if keys[n] == nil {
			t.Fatalf("no key captured for %q", n)
		}
		pt, err := vcrypto.DecryptWithAAD(keys[n], rowCiphertext(t, st, n), st.entryAAD(kindAADEnvVar, n))
		if err != nil {
			t.Fatalf("decrypt %q with captured key: %v", n, err)
		}
		if string(pt) != want {
			t.Fatalf("%q = %q, want %q", n, pt, want)
		}
	}
}

// TestCaptureRowKeys_MigratesV1: capturing a legacy v1 var migrates it to v2 and
// the returned key decrypts the migrated row.
func TestCaptureRowKeys_MigratesV1(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "OLD", []byte("x"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	rewriteAsLegacyV1(t, st, "OLD", []byte("legacy-val"))
	keys, err := st.CaptureRowKeys(ctx, defaultScope(), []string{"OLD"})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if v := rowAADVersion(t, st, "OLD"); v != currentAADVersion {
		t.Fatalf("after capture aad_version=%d, want %d (migrated)", v, currentAADVersion)
	}
	pt, err := vcrypto.DecryptWithAAD(keys["OLD"], rowCiphertext(t, st, "OLD"), st.entryAAD(kindAADEnvVar, "OLD"))
	if err != nil {
		t.Fatalf("decrypt migrated with captured key: %v", err)
	}
	if string(pt) != "legacy-val" {
		t.Fatalf("value=%q, want legacy-val", pt)
	}
}

// TestCaptureRowKeys_SkipsMissing: vars that don't exist are absent from the map.
func TestCaptureRowKeys_SkipsMissing(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "PRESENT", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	keys, err := st.CaptureRowKeys(ctx, defaultScope(), []string{"PRESENT", "ABSENT"})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if _, ok := keys["PRESENT"]; !ok {
		t.Fatal("PRESENT should be captured")
	}
	if _, ok := keys["ABSENT"]; ok {
		t.Fatal("ABSENT must be skipped (not created)")
	}
}

// TestCaptureRowKeys_LockedReturnsErrLocked: the in-memory variant needs an
// unlocked vault.
func TestCaptureRowKeys_LockedReturnsErrLocked(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "V", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	st.Lock()
	if _, err := st.CaptureRowKeys(ctx, defaultScope(), []string{"V"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked capture err = %v, want ErrLocked", err)
	}
}

// TestCaptureRowKeysWithPassword: the locked + password path works (trust grant
// is proof-of-presence and may run while locked); a wrong password fails.
func TestCaptureRowKeysWithPassword(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "V", []byte("secret"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	st.Lock()
	keys, err := st.CaptureRowKeysWithPassword(ctx, []byte(testPassword), defaultScope(), []string{"V"})
	if err != nil {
		t.Fatalf("capture w/ password: %v", err)
	}
	pt, err := vcrypto.DecryptWithAAD(keys["V"], rowCiphertext(t, st, "V"), st.entryAAD(kindAADEnvVar, "V"))
	if err != nil || string(pt) != "secret" {
		t.Fatalf("decrypt: pt=%q err=%v", pt, err)
	}
	if _, err := st.CaptureRowKeysWithPassword(ctx, []byte("wrong-password"), defaultScope(), []string{"V"}); err == nil {
		t.Fatal("wrong password must fail")
	}
}
