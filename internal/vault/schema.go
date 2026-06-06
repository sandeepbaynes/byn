package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// openDB opens the SQLite database in WAL mode with safe defaults.
//
// modernc.org/sqlite uses URI-style options. We force WAL so that
// readers don't block the single writer during long Argon2-derived
// unlocks, and synchronous=NORMAL because the daemon owns the file
// and there's no separate fsync responsibility outside the process.
func openDB(ctx context.Context, path string) (*sql.DB, error) {
	dsn := "file:" + path + "?" +
		"_pragma=journal_mode(WAL)&" +
		"_pragma=synchronous(NORMAL)&" +
		"_pragma=foreign_keys(ON)&" +
		"_pragma=busy_timeout(2000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("vault: open db: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("vault: ping db: %w", err)
	}
	// Single connection — the vault is a single-writer system and
	// extra conns cost FDs without giving us anything.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// schemaStatements is the v2 schema applied to a fresh vault. Tables
// are STRICT (typed columns), foreign keys cascade where deletion
// should fan out, and integrity-relevant columns have CHECK
// constraints.
//
// We start fresh at v2 — no v1 → v2 migration is supported (the user
// explicitly waived backward compatibility during Phase 1
// development). Future schema versions will introduce migration code.
var schemaStatements = []string{
	`CREATE TABLE meta (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	) STRICT`,

	`CREATE TABLE projects (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		UNIQUE(name)
	) STRICT`,

	`CREATE TABLE envs (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name       TEXT NOT NULL,
		is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0,1)),
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		UNIQUE(project_id, name)
	) STRICT`,
	`CREATE INDEX envs_by_project ON envs(project_id)`,
	`CREATE UNIQUE INDEX envs_one_default_per_project ON envs(project_id) WHERE is_default = 1`,

	`CREATE TABLE entries (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		env_id      INTEGER NOT NULL REFERENCES envs(id)     ON DELETE CASCADE,
		kind        TEXT    NOT NULL CHECK (kind IN ('env_var','file')),
		name        TEXT    NOT NULL,
		value       BLOB    NOT NULL,
		aad_version INTEGER NOT NULL DEFAULT 1,
		deleted_at  INTEGER,
		require_2fa INTEGER NOT NULL DEFAULT 0 CHECK (require_2fa IN (0,1)),
		created_at  INTEGER NOT NULL,
		updated_at  INTEGER NOT NULL,
		UNIQUE(project_id, env_id, name)
	) STRICT`,
	`CREATE INDEX entries_lookup      ON entries(project_id, env_id, kind, name)`,
	`CREATE INDEX entries_by_env_kind ON entries(env_id, kind, name)`,

	`CREATE TABLE file_meta (
		entry_id         INTEGER PRIMARY KEY REFERENCES entries(id) ON DELETE CASCADE,
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
	) STRICT`,
	`CREATE INDEX idx_file_meta_mount_path ON file_meta(mount_path)`,

	`CREATE TABLE entry_versions (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		entry_id    INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
		version_no  INTEGER NOT NULL,
		value       BLOB NOT NULL,
		aad_version INTEGER NOT NULL,
		op          TEXT NOT NULL CHECK (op IN ('put','rename','delete')),
		op_meta     TEXT,
		created_at  INTEGER NOT NULL,
		UNIQUE(entry_id, version_no)
	) STRICT`,
	`CREATE INDEX idx_entry_versions_entry ON entry_versions(entry_id, version_no DESC)`,

	passkeyTableDDL,
	passkeyUnlockTableDDL,
}

// passkeyTableDDL is the per-vault WebAuthn credential store. It is additive
// and idempotent (CREATE TABLE IF NOT EXISTS): created on a fresh vault via
// schemaStatements, and ensured on open for vaults that predate it (see
// ensurePasskeyTable) — so no schema-version bump or re-init is needed. All
// columns are non-secret; security rests on possession of the authenticator +
// user verification. The PRF cold-unlock columns arrive with slice A-auth.2.
const passkeyTableDDL = `CREATE TABLE IF NOT EXISTS passkey (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	credential_id   BLOB    NOT NULL UNIQUE,
	public_key      BLOB    NOT NULL,
	sign_count      INTEGER NOT NULL DEFAULT 0,
	aaguid          BLOB,
	transports      TEXT    NOT NULL DEFAULT '',
	label           TEXT    NOT NULL DEFAULT '',
	backup_eligible INTEGER NOT NULL DEFAULT 0,
	backup_state    INTEGER NOT NULL DEFAULT 0,
	created_at      INTEGER NOT NULL
) STRICT`

// passkeyUnlockTableDDL is the PRF-derived second wrapping of the vault key,
// one row per credential (A-auth.2). All columns are non-secret — the KEK that
// unwraps wrapped_vault_key is HKDF(prfOut), computed in the browser and never
// stored. ON DELETE CASCADE ties it to the credential, so revoking a passkey
// also drops its unlock path.
const passkeyUnlockTableDDL = `CREATE TABLE IF NOT EXISTS passkey_unlock (
	credential_id     BLOB    PRIMARY KEY REFERENCES passkey(credential_id) ON DELETE CASCADE,
	prf_salt          BLOB    NOT NULL,
	wrapped_vault_key BLOB    NOT NULL,
	hkdf_info_version INTEGER NOT NULL DEFAULT 1,
	aead_alg          TEXT    NOT NULL DEFAULT 'xchacha20poly1305',
	label             TEXT    NOT NULL DEFAULT '',
	created_at        INTEGER NOT NULL
) STRICT`

// ensurePasskeyTables adds the passkey + passkey_unlock tables to a vault that
// predates them. Idempotent and non-destructive — safe on every open. Order
// matters: passkey_unlock has a FK into passkey.
func ensurePasskeyTables(ctx context.Context, db *sql.DB) error {
	for _, ddl := range []string{passkeyTableDDL, passkeyUnlockTableDDL} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("vault: ensure passkey tables: %w", err)
		}
	}
	// Additive column migration for a passkey table that predates the WebAuthn
	// backup flags. SQLite has no ADD COLUMN IF NOT EXISTS, so run the ALTER and
	// ignore the duplicate-column error on already-migrated DBs.
	for _, alt := range []string{
		"ALTER TABLE passkey ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE passkey ADD COLUMN backup_state INTEGER NOT NULL DEFAULT 0",
	} {
		if _, err := db.ExecContext(ctx, alt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("vault: ensure passkey columns: %w", err)
		}
	}
	return nil
}

// Reserved meta keys. Values are stored as TEXT; callers convert.
const (
	metaKeySchemaVersion    = "schema_version"
	metaKeyVaultID          = "vault_id"
	metaKeyName             = "name"
	metaKeyCreatedAt        = "created_at"
	metaKeyDefaultProjectID = "default_project_id"

	// Audit chain anchors (v3). Seed is set at init and never
	// changes; head is updated on every append.
	MetaKeyAuditChainSeed = "audit_chain_seed"
	MetaKeyAuditChainHead = "audit_chain_head"

	// Entries-state tamper-evidence anchor (v3). Updated on every
	// data-plane commit; verified on unlock fast-check.
	MetaKeyEntriesStateHash = "entries_state_hash"

	// TOTP secret slot (v3). Holds the AEAD ciphertext of the
	// 20-byte TOTP secret (per-vault), encrypted under the vault key
	// with AAD = vault_id || 0x1F || "totp_secret_v1". NULL until
	// `vault.enroll_totp` runs.
	MetaKeyTOTPSecretV1 = "totp_secret_v1"
)

// createSchema applies the v2 schema to a fresh DB and seeds initial
// meta rows. Callers (Init) must subsequently bootstrap a default
// project + default env via bootstrapDefaults.
func createSchema(ctx context.Context, db *sql.DB, vaultID, vaultName string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range schemaStatements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("vault: schema stmt failed: %w\nstatement: %s", err, stmt)
		}
	}

	now := nowUnix()
	// Audit chain seed: 32 random bytes, hex-encoded. Used as the HMAC
	// key for chaining audit events; never rotated.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return fmt.Errorf("vault: gen audit seed: %w", err)
	}
	metaRows := []struct{ k, v string }{
		{metaKeySchemaVersion, strconv.Itoa(schemaVersion)},
		{metaKeyVaultID, vaultID},
		{metaKeyName, vaultName},
		{metaKeyCreatedAt, strconv.FormatInt(now, 10)},
		{MetaKeyAuditChainSeed, hex.EncodeToString(seed[:])},
		{MetaKeyAuditChainHead, ""}, // empty until first audit append
		{MetaKeyEntriesStateHash, ""},
	}
	for _, r := range metaRows {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO meta (key, value) VALUES (?, ?)`, r.k, r.v); err != nil {
			return fmt.Errorf("vault: write meta %q: %w", r.k, err)
		}
	}
	return tx.Commit()
}

// bootstrapDefaults creates the "default" project and its "default"
// env, then records meta.default_project_id. Called by Init after the
// schema is in place. Idempotent only inside a single Init — callers
// should not invoke it on an already-initialized DB.
func bootstrapDefaults(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := nowUnix()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO projects (name, created_at, updated_at) VALUES (?, ?, ?)`,
		DefaultProjectName, now, now)
	if err != nil {
		return fmt.Errorf("vault: create default project: %w", err)
	}
	projectID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("vault: get project id: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO envs (project_id, name, is_default, created_at, updated_at)
		 VALUES (?, ?, 1, ?, ?)`,
		projectID, DefaultEnvName, now, now); err != nil {
		return fmt.Errorf("vault: create default env: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES (?, ?)`,
		metaKeyDefaultProjectID, strconv.FormatInt(projectID, 10)); err != nil {
		return fmt.Errorf("vault: write default_project_id: %w", err)
	}
	return tx.Commit()
}

// verifySchema confirms an existing DB is at a version this binary
// understands. Future versions will add migration logic here.
func verifySchema(ctx context.Context, db *sql.DB) error {
	var raw string
	err := db.QueryRowContext(ctx,
		`SELECT value FROM meta WHERE key = ?`, metaKeySchemaVersion).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSchemaUnknown
	}
	if err != nil {
		// "no such table" etc. — treat as ErrSchemaUnknown so callers
		// don't have to special-case sqlite messages.
		return ErrSchemaUnknown
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return ErrSchemaUnknown
	}
	if n > schemaVersion {
		return fmt.Errorf("%w: on-disk version %d > supported %d (downgrade?)", ErrSchemaUnknown, n, schemaVersion)
	}
	if n < schemaVersion {
		// Pre-1.0 explicitly waives backward compatibility. Refuse
		// rather than attempt a phantom migration.
		return fmt.Errorf("%w: on-disk version %d < supported %d (pre-1.0: re-init the vault)", ErrSchemaUnknown, n, schemaVersion)
	}
	return nil
}

// readVaultID returns meta.vault_id. Used by the Store to seed AEAD AAD.
func readVaultID(ctx context.Context, db *sql.DB) (string, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, metaKeyVaultID).Scan(&v)
	if err != nil {
		return "", fmt.Errorf("vault: read vault_id: %w", err)
	}
	return v, nil
}

// MetaGet returns the value of a meta key. Returns the zero string
// and no error when the key is missing (callers can distinguish
// "not set yet" from "error" via the error path). Exported so the
// audit and tamper-check packages can read the chain anchors.
func (s *Store) MetaGet(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("vault: meta get %q: %w", key, err)
	}
	return v, nil
}

// MetaSet upserts a meta key. Used by the audit log to advance the
// chain head, and by the tamper-check layer to update the entries
// state hash on each commit.
func (s *Store) MetaSet(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	if err != nil {
		return fmt.Errorf("vault: meta set %q: %w", key, err)
	}
	return nil
}
