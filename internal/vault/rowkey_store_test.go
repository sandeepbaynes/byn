package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

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
		// Go through the production read path so the test follows whatever
		// scheme the row is actually stored under, rather than pinning one AAD.
		pt, err := st.OpenEnvVarWithRowKey(ctx, defaultScope(), n, keys[n])
		if err != nil {
			t.Fatalf("decrypt %q with captured key: %v", n, err)
		}
		if string(pt) != want {
			t.Fatalf("%q = %q, want %q", n, pt, want)
		}
	}
}

// TestCaptureRowKeys_MigratesV1: capturing a legacy v1 var migrates it to the
// current scheme and the returned key decrypts the migrated row.
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
	pt, err := st.OpenEnvVarWithRowKey(ctx, defaultScope(), "OLD", keys["OLD"])
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
	pt, err := st.OpenEnvVarWithRowKey(ctx, defaultScope(), "V", keys["V"])
	if err != nil || string(pt) != "secret" {
		t.Fatalf("decrypt: pt=%q err=%v", pt, err)
	}
	if _, err := st.CaptureRowKeysWithPassword(ctx, []byte("wrong-password"), defaultScope(), []string{"V"}); err == nil {
		t.Fatal("wrong password must fail")
	}
}

// TestOpenEnvVarWithRowKey_WorksWhileLocked: a captured row key decrypts the var
// even after the vault is LOCKED — the autonomous-exec read path needs no vault
// key. Plus: wrong key fails, missing var → ErrNotFound, legacy v1 row refused.
func TestOpenEnvVarWithRowKey_WorksWhileLocked(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "TOKEN", []byte("t-secret"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	keys, err := st.CaptureRowKeys(ctx, defaultScope(), []string{"TOKEN"})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	rowKey := append([]byte(nil), keys["TOKEN"]...) // keep a copy across lock

	st.Lock() // no vault key in memory now
	got, err := st.OpenEnvVarWithRowKey(ctx, defaultScope(), "TOKEN", rowKey)
	if err != nil {
		t.Fatalf("open while locked: %v", err)
	}
	if string(got) != "t-secret" {
		t.Fatalf("value=%q, want t-secret", got)
	}

	// Wrong row key → AEAD failure.
	if _, err := st.OpenEnvVarWithRowKey(ctx, defaultScope(), "TOKEN", make([]byte, 32)); err == nil {
		t.Fatal("wrong row key must fail")
	}
	// Missing var.
	if _, err := st.OpenEnvVarWithRowKey(ctx, defaultScope(), "NOPE", rowKey); err == nil {
		t.Fatal("missing var must error")
	}
}

// TestOpenEnvVarWithRowKey_RefusesLegacyV1: a v1 row (no per-row key) is refused
// rather than silently failing the AEAD.
func TestOpenEnvVarWithRowKey_RefusesLegacyV1(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "OLD", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	rewriteAsLegacyV1(t, st, "OLD", []byte("legacy"))
	if _, err := st.OpenEnvVarWithRowKey(ctx, defaultScope(), "OLD", make([]byte, 32)); err == nil {
		t.Fatal("a v1 row must be refused under the per-row-key read path")
	}
}

// ── Env-inheritance parity for the exec capability path ─────────────────────
// Reads (GetEnvVar / ListEnvVars) fall back from a non-default env to the
// project's default env for missing names. The capability capture + open path
// must apply the SAME fallback, or a var whose value lives only in default is
// silently absent from trusted exec while `byn get` shows it (real incident:
// example-project EXAMPLE_TIMEOUT_SECONDS, 2026-07-28).

// TestCaptureRowKeys_InheritsDefaultEnv: capturing in a non-default env picks
// up a var that exists only in the default env.
func TestCaptureRowKeys_InheritsDefaultEnv(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "INHERITED", []byte("from-default"), PutOpt{}); err != nil {
		t.Fatalf("put default: %v", err)
	}
	if err := st.CreateEnv(ctx, DefaultProjectName, "stg"); err != nil {
		t.Fatalf("create env: %v", err)
	}
	stg := Scope{Project: DefaultProjectName, Env: "stg"}
	keys, err := st.CaptureRowKeys(ctx, stg, []string{"INHERITED", "ABSENT"})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	rk, ok := keys["INHERITED"]
	if !ok {
		t.Fatal("INHERITED must be captured via default-env fallback")
	}
	if _, ok := keys["ABSENT"]; ok {
		t.Fatal("ABSENT must still be skipped")
	}
	// The captured key must decrypt through the same scope the exec uses.
	val, err := st.OpenEnvVarWithRowKey(ctx, stg, "INHERITED", rk)
	if err != nil {
		t.Fatalf("open with row key (inherited): %v", err)
	}
	if string(val) != "from-default" {
		t.Fatalf("value=%q, want from-default", val)
	}
}

// TestCaptureRowKeys_ScopeRowShadowsDefault: when both envs have the var, the
// non-default env's own row wins (same shadowing rule as GetEnvVar).
func TestCaptureRowKeys_ScopeRowShadowsDefault(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "SHADOWED", []byte("default-val"), PutOpt{}); err != nil {
		t.Fatalf("put default: %v", err)
	}
	if err := st.CreateEnv(ctx, DefaultProjectName, "stg"); err != nil {
		t.Fatalf("create env: %v", err)
	}
	stg := Scope{Project: DefaultProjectName, Env: "stg"}
	if err := st.PutEnvVar(ctx, stg, "SHADOWED", []byte("stg-val"), PutOpt{}); err != nil {
		t.Fatalf("put stg: %v", err)
	}
	keys, err := st.CaptureRowKeys(ctx, stg, []string{"SHADOWED"})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	val, err := st.OpenEnvVarWithRowKey(ctx, stg, "SHADOWED", keys["SHADOWED"])
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(val) != "stg-val" {
		t.Fatalf("value=%q, want stg-val (scope row must shadow default)", val)
	}
}

// TestOpenEnvVarWithRowKey_InheritsDefaultEnv: the locked-exec read path
// applies the same default-env fallback as GetEnvVar.
func TestOpenEnvVarWithRowKey_InheritsDefaultEnv(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "RO_INHERIT", []byte("dv"), PutOpt{}); err != nil {
		t.Fatalf("put default: %v", err)
	}
	if err := st.CreateEnv(ctx, DefaultProjectName, "stg"); err != nil {
		t.Fatalf("create env: %v", err)
	}
	keys, err := st.CaptureRowKeys(ctx, defaultScope(), []string{"RO_INHERIT"})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	stg := Scope{Project: DefaultProjectName, Env: "stg"}
	val, err := st.OpenEnvVarWithRowKey(ctx, stg, "RO_INHERIT", keys["RO_INHERIT"])
	if err != nil {
		t.Fatalf("open inherited: %v", err)
	}
	if string(val) != "dv" {
		t.Fatalf("value=%q, want dv", val)
	}
	// A name in neither env is still ErrNotFound.
	if _, err := st.OpenEnvVarWithRowKey(ctx, stg, "NOPE", keys["RO_INHERIT"]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing name err=%v, want ErrNotFound", err)
	}
}

// A grant is sealed against a scope, so the key it hands out must open entries
// that did not exist when the grant was made. This is the whole point of the
// scope-key layer: under the flat scheme a capability froze the exact set of
// rows present at grant time, and every new variable forced a re-trust.
func TestEnvKey_OpensRowsCreatedAfterCapture(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()

	projectID, envID, err := st.scopeIDs(ctx, defaultScope())
	if err != nil {
		t.Fatalf("scope ids: %v", err)
	}
	vk := st.snapshotVaultKey()
	if vk == nil {
		t.Fatal("vault locked")
	}
	kenv, err := st.EnvKey(vk, projectID, envID)
	if err != nil {
		t.Fatalf("env key: %v", err)
	}

	// The variable is written only AFTER the scope key was taken.
	if err := st.PutEnvVar(ctx, defaultScope(), "ADDED_LATER", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	krow, err := vcrypto.DeriveRowKeyFromEnvKey(kenv, rowAAD(kindAADEnvVar, "ADDED_LATER"))
	if err != nil {
		t.Fatalf("row key from env key: %v", err)
	}
	pt, err := st.OpenEnvVarWithRowKey(ctx, defaultScope(), "ADDED_LATER", krow)
	if err != nil {
		t.Fatalf("open row created after capture: %v", err)
	}
	if string(pt) != "v" {
		t.Fatalf("value=%q, want v", pt)
	}
}

// A scope key must not travel: holding one env's key must not open another
// env's row of the same name. Under the flat scheme both derived the same key.
func TestEnvKey_DoesNotCrossEnvs(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	other := Scope{Project: DefaultProjectName, Env: "staging"}
	if err := st.CreateEnv(ctx, DefaultProjectName, "staging"); err != nil {
		t.Fatalf("create env: %v", err)
	}
	if err := st.PutEnvVar(ctx, defaultScope(), "SHARED", []byte("from-default"), PutOpt{}); err != nil {
		t.Fatalf("put default: %v", err)
	}
	if err := st.PutEnvVar(ctx, other, "SHARED", []byte("from-staging"), PutOpt{}); err != nil {
		t.Fatalf("put staging: %v", err)
	}

	vk := st.snapshotVaultKey()
	stagingProj, stagingEnv, err := st.scopeIDs(ctx, other)
	if err != nil {
		t.Fatalf("scope ids: %v", err)
	}
	kenv, err := st.EnvKey(vk, stagingProj, stagingEnv)
	if err != nil {
		t.Fatalf("env key: %v", err)
	}
	krow, err := vcrypto.DeriveRowKeyFromEnvKey(kenv, rowAAD(kindAADEnvVar, "SHARED"))
	if err != nil {
		t.Fatalf("row key: %v", err)
	}

	if pt, err := st.OpenEnvVarWithRowKey(ctx, other, "SHARED", krow); err != nil {
		t.Fatalf("staging key must open its own row: %v", err)
	} else if string(pt) != "from-staging" {
		t.Fatalf("staging value=%q", pt)
	}
	if _, err := st.OpenEnvVarWithRowKey(ctx, defaultScope(), "SHARED", krow); err == nil {
		t.Fatal("staging scope key opened the default env's row — scopes are not isolated")
	}
}

// Rows written before the scope-key scheme must stay readable forever; nothing
// is rewritten until the row is next written.
func TestMixedAADVersions_StayReadable(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "LEGACY", []byte("old-value"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	rewriteAsLegacyV1(t, st, "LEGACY", []byte("old-value"))
	if err := st.PutEnvVar(ctx, defaultScope(), "MODERN", []byte("new-value"), PutOpt{}); err != nil {
		t.Fatalf("put modern: %v", err)
	}
	if v := rowAADVersion(t, st, "MODERN"); v != currentAADVersion {
		t.Fatalf("new write aad_version=%d, want %d", v, currentAADVersion)
	}
	for name, want := range map[string]string{"LEGACY": "old-value", "MODERN": "new-value"} {
		e, err := st.GetEnvVar(ctx, defaultScope(), name)
		if err != nil {
			t.Fatalf("get %q: %v", name, err)
		}
		if string(e.Value) != want {
			t.Fatalf("%q = %q, want %q", name, e.Value, want)
		}
	}
}

// An existing vault must upgrade in place on open: the sync columns appear, the
// version advances, and every value written under the old schema still reads.
func TestMigrateV4toV5_InPlace(t *testing.T) {
	st, dir := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "BEFORE", []byte("kept"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Rewind to v4: drop the columns v5 adds and reset the recorded version.
	db, err := openDB(ctx, filepath.Join(Dir(dir, DefaultVaultName), dbFilename))
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	for _, stmt := range []string{
		`ALTER TABLE entries DROP COLUMN lamport`,
		`ALTER TABLE entries DROP COLUMN origin_device`,
		`UPDATE meta SET value = '4' WHERE key = 'schema_version'`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("rewind (%s): %v", stmt, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	st2 := reopenVault(t, dir)
	var got string
	if err := st2.db.QueryRowContext(ctx,
		`SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&got); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if got != "5" {
		t.Fatalf("schema_version=%s after open, want 5", got)
	}
	var lamport int64
	if err := st2.db.QueryRowContext(ctx,
		`SELECT lamport FROM entries WHERE name = 'BEFORE'`).Scan(&lamport); err != nil {
		t.Fatalf("sync columns missing after migrate: %v", err)
	}
	e, err := st2.GetEnvVar(ctx, defaultScope(), "BEFORE")
	if err != nil {
		t.Fatalf("read pre-migration value: %v", err)
	}
	if string(e.Value) != "kept" {
		t.Fatalf("value=%q, want kept", e.Value)
	}

	// Upgrading is one-way, so the pre-migration snapshot must exist and be a
	// readable vault in its own right.
	bak := filepath.Join(Dir(dir, DefaultVaultName), dbFilename+".v4.bak")
	if _, err := os.Stat(bak); err != nil {
		t.Fatalf("no pre-migration backup written: %v", err)
	}
	bdb, err := openDB(ctx, bak)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer func() { _ = bdb.Close() }()
	var ver string
	if err := bdb.QueryRowContext(ctx,
		`SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&ver); err != nil {
		t.Fatalf("read backup version: %v", err)
	}
	if ver != "4" {
		t.Fatalf("backup schema_version=%s, want 4 (the version left behind)", ver)
	}
}

// reopenVault opens an existing vault directory again, running whatever schema
// migrations the on-disk version calls for.
func reopenVault(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := Open(context.Background(), dir, DefaultVaultName)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Unlock([]byte(testPassword)); err != nil {
		t.Fatalf("unlock after reopen: %v", err)
	}
	return st
}
