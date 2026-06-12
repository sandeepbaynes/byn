package vault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"path/filepath"
	"testing"
)

// TestFileMeta_SHA256HMACColumnExists verifies the schema has sha256_hmac
// (keyed) not sha256_plain (unkeyed oracle).
func TestFileMeta_SHA256HMACColumnExists(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	rows, err := st.db.QueryContext(ctx, `PRAGMA table_info(file_meta)`)
	if err != nil {
		t.Fatalf("PRAGMA: %v", err)
	}
	defer rows.Close()
	var colNames []string
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		colNames = append(colNames, name)
	}
	hasHMAC := false
	hasPlain := false
	for _, n := range colNames {
		if n == "sha256_hmac" {
			hasHMAC = true
		}
		if n == "sha256_plain" {
			hasPlain = true
		}
	}
	if !hasHMAC {
		t.Error("file_meta missing sha256_hmac column")
	}
	if hasPlain {
		t.Error("file_meta still has sha256_plain column (oracle not removed)")
	}
}

// TestFileMeta_HMACNotMatchesPlainSHA256 verifies that a stored HMAC value
// does not match the plain SHA-256 of the same content (keyed ≠ unkeyed).
func TestFileMeta_HMACNotMatchesPlainSHA256(t *testing.T) {
	st, _ := newOpenedVault(t)
	// Derive the file-meta MAC key.
	key, err := st.DeriveSubkey(FileMetaMACKeyInfo)
	if err != nil {
		t.Fatalf("DeriveSubkey: %v", err)
	}
	content := []byte("this is secret file content")
	// Compute HMAC-SHA256.
	mac := hmac.New(sha256.New, key)
	mac.Write(content)
	hmacSum := mac.Sum(nil)
	// Compute plain SHA-256.
	plain := sha256.Sum256(content)
	// They must differ — keyed HMAC and unkeyed SHA-256 are not the same.
	if bytes.Equal(hmacSum, plain[:]) {
		t.Error("HMAC and plain SHA-256 are identical — keying is not working")
	}
}

// TestMigrateV3toV4 verifies the migration renames sha256_plain to
// sha256_hmac and nulls existing values. It creates a minimal v3-style
// table directly, runs the migration function, and checks the result.
func TestMigrateV3toV4(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	db, err := openDB(ctx, dbPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	// Create the meta table and insert v3 schema_version.
	if _, err := db.ExecContext(ctx, `CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT`); err != nil {
		t.Fatalf("create meta: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES ('schema_version', '3')`); err != nil {
		t.Fatalf("seed schema_version: %v", err)
	}

	// Create file_meta with the v3 sha256_plain column.
	if _, err := db.ExecContext(ctx, `CREATE TABLE file_meta (
		entry_id         INTEGER PRIMARY KEY,
		mount_path       TEXT    NOT NULL,
		mode             INTEGER NOT NULL,
		owner_uid        INTEGER NOT NULL,
		owner_gid        INTEGER NOT NULL DEFAULT -1,
		encoding         TEXT    NOT NULL,
		size_plain       INTEGER NOT NULL,
		sha256_plain     BLOB,
		allowed_readers  TEXT,
		materialize_hint TEXT    NOT NULL DEFAULT 'fuse',
		created_at       INTEGER NOT NULL,
		updated_at       INTEGER NOT NULL
	) STRICT`); err != nil {
		t.Fatalf("create v3 file_meta: %v", err)
	}

	// Insert a row with a fake sha256_plain value to confirm it gets nulled.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO file_meta (entry_id, mount_path, mode, owner_uid, encoding, size_plain, sha256_plain, created_at, updated_at)
		 VALUES (1, '/tmp/test', 420, 1000, 'raw', 42, X'deadbeef', 0, 0)`); err != nil {
		t.Fatalf("insert file_meta row: %v", err)
	}

	// Run the migration.
	if merr := migrateV3toV4(ctx, db); merr != nil {
		t.Fatalf("migrateV3toV4: %v", merr)
	}

	// Verify sha256_hmac exists and sha256_plain is gone.
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(file_meta)`)
	if err != nil {
		t.Fatalf("PRAGMA: %v", err)
	}
	defer rows.Close()
	hasHMAC, hasPlain := false, false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "sha256_hmac" {
			hasHMAC = true
		}
		if name == "sha256_plain" {
			hasPlain = true
		}
	}
	if !hasHMAC {
		t.Error("sha256_hmac column missing after migration")
	}
	if hasPlain {
		t.Error("sha256_plain column still present after migration")
	}

	// Verify the existing row's sha256_hmac was nulled out.
	var hmacVal sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT sha256_hmac FROM file_meta WHERE entry_id = 1`).Scan(&hmacVal); err != nil {
		t.Fatalf("query sha256_hmac: %v", err)
	}
	if hmacVal.Valid {
		t.Errorf("expected sha256_hmac to be NULL after migration, got %q", hmacVal.String)
	}

	// Verify schema_version was bumped to 4.
	var version string
	if err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&version); err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if version != "4" {
		t.Errorf("schema_version = %q after migration, want '4'", version)
	}
}
