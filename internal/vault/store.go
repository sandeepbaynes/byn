package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// Per-vault on-disk layout (all under <root>/vaults/<vaultName>/):
//
//	vault.db      — SQLite database (v2 schema)
//	wrapped.key   — Argon2id-wrapped vault key blob
//	meta.json     — sidecar with vault_id + fingerprint(wrapped.key)
//
// The top-level <root>/ (typically ~/.byn/) holds the daemon
// socket, pidfile, logs, auth-state.json — NOT vault data.
const (
	dbFilename      = "vault.db"
	wrappedFilename = "wrapped.key"

	// schemaVersion is the current vault schema. Bump on incompatible
	// changes; no v1 migration is supported (pre-1.0 waiver). v3
	// added: entries.require_2fa column, meta keys for audit chain
	// seed/head, entries_state_hash, and meta.totp_secret_v1 reserved
	// slot.
	schemaVersion = 3

	// DefaultProjectName is the project created at vault init. It's a
	// regular project — no leading-underscore sentinel — so rename and
	// delete behave like any other.
	DefaultProjectName = "default"

	// DefaultEnvName is the implicit base env in every project. Other
	// envs inherit from it: a Get against env=local falls back to
	// env=default when the local env has no override.
	DefaultEnvName = "default"

	// AAD bytes for the env_var kind, used in EncryptWithAAD when
	// writing env_var entries. The kind string itself is reused as
	// the AAD segment — short, stable, unambiguous. kindAADFile is
	// declared here but consumed in a later slice when file-content
	// CRUD lands; it's part of the AAD design contract.
	kindAADEnvVar = "env_var"
	kindAADFile   = "file" //nolint:unused // reserved for file-content CRUD in a later slice
)

// Dir returns the per-vault directory `<root>/vaults/<name>/`.
// Callers use it when they need the path without opening.
func Dir(root, name string) string {
	return filepath.Join(root, VaultsSubdir, name)
}

// Sentinel errors returned by Store. Match via errors.Is.
var (
	// ErrLocked is returned when an operation requires the vault to be
	// unlocked but it isn't.
	ErrLocked = errors.New("vault: locked")

	// ErrNotFound is returned by Get / Delete / Rename when no entry
	// matches the requested name in the requested scope (after
	// inheritance fallback, for reads).
	ErrNotFound = errors.New("vault: entry not found")

	// ErrExists is returned by Put with CreateOnly when the name is
	// already taken in scope, or by Rename when the destination is
	// taken.
	ErrExists = errors.New("vault: entry already exists")

	// ErrAlreadyInit is returned by Init when a vault is already
	// present at the configured location.
	ErrAlreadyInit = errors.New("vault: already initialized")

	// ErrNotInit is returned by Open when no vault is present at the
	// configured location.
	ErrNotInit = errors.New("vault: not initialized")

	// ErrWrongPassword is returned by Unlock / VerifyPassword /
	// ChangePassword when the supplied password fails to unwrap the vault
	// key. Re-exported from the crypto package so callers (the daemon) can
	// match it without importing internal/vault/crypto.
	ErrWrongPassword = vcrypto.ErrWrongPassword

	// ErrBadName is returned when an entry name violates the naming
	// rules (empty, contains NUL, too long).
	ErrBadName = errors.New("vault: invalid entry name")

	// ErrSchemaUnknown is returned when the on-disk schema version is
	// newer than this binary supports (downgrade) or otherwise
	// unrecognized.
	ErrSchemaUnknown = errors.New("vault: unknown schema version")

	// ErrProjectNotFound is returned by ops that name a project that
	// doesn't exist in the vault.
	ErrProjectNotFound = errors.New("vault: project not found")

	// ErrProjectExists is returned by CreateProject when the name is
	// already in use.
	ErrProjectExists = errors.New("vault: project already exists")

	// ErrEnvNotFound is returned by ops that name an env that doesn't
	// exist in the given project.
	ErrEnvNotFound = errors.New("vault: env not found")

	// ErrEnvExists is returned by CreateEnv when the name is already
	// in use in the project.
	ErrEnvExists = errors.New("vault: env already exists")

	// ErrEnvProtected is returned by DeleteEnv/RenameEnv when the
	// caller tries to mutate the default env (the inheritance base).
	ErrEnvProtected = errors.New("vault: default env cannot be renamed or deleted")

	// ErrBadProjectName / ErrBadEnvName are returned when the
	// respective naming rules are violated.
	ErrBadProjectName = errors.New("vault: invalid project name")
	ErrBadEnvName     = errors.New("vault: invalid env name")
)

// MaxNameLen caps entry name length. Matches AWS Secrets Manager's limit.
const MaxNameLen = 512

// MaxValueLen caps the size of a single entry value (post-encryption
// the row also carries nonce/version overhead).
const MaxValueLen = 1 << 20

// Scope identifies a (project, env) pair within a vault. Required on
// most Store data-plane ops.
type Scope struct {
	Project string
	Env     string
}

// Validate checks Scope field shape. Caller-visible names use the
// same rules as Validate-Project/Env-Name; empty strings are rejected
// at the Store boundary — the daemon layer can default them before
// reaching here.
func (s Scope) Validate() error {
	if err := ValidateProjectName(s.Project); err != nil {
		return err
	}
	return ValidateEnvName(s.Env)
}

// Entry is a get result. Value is decrypted plaintext.
type Entry struct {
	Name      string
	Value     []byte
	Kind      string // "env_var" or "file"
	Source    Source
	CreatedAt time.Time
	UpdatedAt time.Time
}

// EntryInfo is a list-only view (no plaintext value). List doesn't
// require Unlock; daemon callers can show the index of a locked
// vault.
type EntryInfo struct {
	Name      string
	Kind      string
	Source    Source
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Source distinguishes a value that lives in the requested env from
// one inherited from the default env.
type Source uint8

// Source values.
const (
	// SourceScope means the value is set in the requested env.
	SourceScope Source = iota
	// SourceDefault means the value comes from the default env via
	// inheritance fallback.
	SourceDefault
)

// String implements fmt.Stringer for human-readable logs/tests.
func (s Source) String() string {
	switch s {
	case SourceScope:
		return "scope"
	case SourceDefault:
		return "default"
	}
	return "unknown"
}

// ProjectInfo is a list-only view of a project.
type ProjectInfo struct {
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// EnvInfo is a list-only view of an env.
type EnvInfo struct {
	Name      string
	IsDefault bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PutOpt configures Put. Default: upsert (create or replace).
type PutOpt struct {
	// CreateOnly causes Put to return ErrExists if an entry with that
	// name already exists in the SAME scope (not from inheritance).
	CreateOnly bool
}

// Store is the encrypted secrets vault.
type Store struct {
	dir string
	db  *sql.DB

	mu       sync.RWMutex
	vaultKey []byte // nil ⇒ locked. 32 bytes when unlocked.
	vaultID  string // cached from the meta table at Open; used in AEAD AAD.
}

// Open opens (or refuses to open) the vault named vaultName under
// root. Returns ErrNotInit if no vault exists at that path; use Init
// first. The returned Store is locked.
//
// Open verifies the meta.json fingerprint against wrapped.key on
// disk. A mismatch returns ErrFingerprintMismatch.
func Open(ctx context.Context, root, vaultName string) (*Store, error) {
	if err := ValidateVaultName(vaultName); err != nil {
		return nil, err
	}
	dir := Dir(root, vaultName)
	dbPath := filepath.Join(dir, dbFilename)
	wrappedPath := filepath.Join(dir, wrappedFilename)
	metaPath := filepath.Join(dir, MetaFilename)

	dbExists := fileExists(dbPath)
	wrappedExists := fileExists(wrappedPath)
	metaExists := fileExists(metaPath)

	if !dbExists && !wrappedExists && !metaExists {
		return nil, ErrNotInit
	}
	if !dbExists || !wrappedExists || !metaExists {
		return nil, fmt.Errorf("vault: partial state at %s — db=%v wrapped=%v meta=%v (refusing to proceed)",
			dir, dbExists, wrappedExists, metaExists)
	}

	wrappedBytes, err := os.ReadFile(wrappedPath) // #nosec G304 -- path is store-derived
	if err != nil {
		return nil, fmt.Errorf("vault: read wrapped key: %w", err)
	}
	if _, err := readMeta(metaPath, wrappedBytes); err != nil {
		return nil, err
	}

	db, err := openDB(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	if err := verifySchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensurePasskeyTables(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	vaultID, err := readVaultID(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{dir: dir, db: db, vaultID: vaultID}, nil
}

// Init creates a fresh vault named vaultName under root. Writes
// wrapped.key → vault.db → meta.json (crash leaves a partial-state
// directory that Open refuses to load; caller can rm -rf + retry).
//
// The new vault is bootstrapped with a "default" project containing a
// "default" env. The returned Store is locked.
func Init(ctx context.Context, root, vaultName string, password []byte) (*Store, error) {
	if err := ValidateVaultName(vaultName); err != nil {
		return nil, err
	}
	if password == nil {
		return nil, errors.New("vault: empty password")
	}
	dir := Dir(root, vaultName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("vault: mkdir: %w", err)
	}
	dbPath := filepath.Join(dir, dbFilename)
	wrappedPath := filepath.Join(dir, wrappedFilename)
	metaPath := filepath.Join(dir, MetaFilename)
	if fileExists(dbPath) || fileExists(wrappedPath) || fileExists(metaPath) {
		return nil, ErrAlreadyInit
	}

	vk, err := vcrypto.NewVaultKey()
	if err != nil {
		return nil, err
	}
	defer zero(vk)

	wrapped, err := vcrypto.Wrap(password, vk, vcrypto.DefaultArgon2Params)
	if err != nil {
		return nil, fmt.Errorf("vault: wrap: %w", err)
	}
	if err := writeFileAtomic(wrappedPath, wrapped, 0o600); err != nil {
		return nil, fmt.Errorf("vault: write wrapped key: %w", err)
	}

	cleanupOnErr := func() {
		_ = os.Remove(dbPath)
		_ = os.Remove(wrappedPath)
		_ = os.Remove(metaPath)
	}

	db, err := openDB(ctx, dbPath)
	if err != nil {
		cleanupOnErr()
		return nil, err
	}
	vaultID, err := newVaultID()
	if err != nil {
		_ = db.Close()
		cleanupOnErr()
		return nil, fmt.Errorf("vault: gen vault id: %w", err)
	}
	if err := createSchema(ctx, db, vaultID, vaultName); err != nil {
		_ = db.Close()
		cleanupOnErr()
		return nil, err
	}
	if err := bootstrapDefaults(ctx, db); err != nil {
		_ = db.Close()
		cleanupOnErr()
		return nil, err
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		_ = db.Close()
		cleanupOnErr()
		return nil, fmt.Errorf("vault: chmod db: %w", err)
	}

	meta := Meta{
		SchemaVersion:  MetaFormatVersion,
		Name:           vaultName,
		VaultID:        vaultID,
		CreatedAt:      nowUnix(),
		Fingerprint:    computeFingerprint(wrapped),
		FingerprintAlg: FingerprintAlg,
	}
	if err := writeMeta(metaPath, meta); err != nil {
		_ = db.Close()
		cleanupOnErr()
		return nil, fmt.Errorf("vault: write meta: %w", err)
	}
	return &Store{dir: dir, db: db, vaultID: vaultID}, nil
}

// Close releases DB resources and clears any cached vault key.
func (s *Store) Close() error {
	s.mu.Lock()
	zero(s.vaultKey)
	s.vaultKey = nil
	s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Unlock derives the vault key from the password and the wrapped-key
// blob on disk.
func (s *Store) Unlock(password []byte) error {
	wrapped, err := os.ReadFile(filepath.Join(s.dir, wrappedFilename)) // #nosec G304 -- path is store-configured
	if err != nil {
		return fmt.Errorf("vault: read wrapped key: %w", err)
	}
	vk, err := vcrypto.Unwrap(password, wrapped)
	if err != nil {
		return err
	}
	s.mu.Lock()
	zero(s.vaultKey)
	s.vaultKey = vk
	s.mu.Unlock()
	return nil
}

// VerifyPassword checks password against the wrapped-key blob WITHOUT
// changing the lock state. It unwraps the vault key only to confirm the
// password is correct, then immediately zeroes it — the vault stays
// exactly as locked/unlocked as before. Returns vcrypto.ErrWrongPassword
// on a bad password.
//
// This authorizes operations that do NOT need the key (delete, which
// touches names/IDs only) while keeping the vault locked, so values can
// never be read by a process watching daemon memory.
func (s *Store) VerifyPassword(password []byte) error {
	wrapped, err := os.ReadFile(filepath.Join(s.dir, wrappedFilename)) // #nosec G304 -- path is store-configured
	if err != nil {
		return fmt.Errorf("vault: read wrapped key: %w", err)
	}
	vk, err := vcrypto.Unwrap(password, wrapped)
	if err != nil {
		return err
	}
	zero(vk)
	return nil
}

// ChangePassword re-wraps the vault key under a new password. It unwraps the
// on-disk key with oldPassword (returns vcrypto.ErrWrongPassword on a bad
// password), wraps it under newPassword with a fresh salt + nonce, then
// writes the new wrapped.key and updates meta.json's fingerprint.
//
// The vault KEY itself does not change, so encrypted data is never touched
// and the in-memory lock state is preserved — an unlocked vault stays
// unlocked, a locked one stays locked. This is the security model's
// "password change = re-wrap, never re-encrypt".
func (s *Store) ChangePassword(oldPassword, newPassword []byte) error {
	if len(newPassword) == 0 {
		return errors.New("vault: empty new password")
	}
	wrappedPath := filepath.Join(s.dir, wrappedFilename)
	metaPath := filepath.Join(s.dir, MetaFilename)

	oldWrapped, err := os.ReadFile(wrappedPath) // #nosec G304 -- store-configured path
	if err != nil {
		return fmt.Errorf("vault: read wrapped key: %w", err)
	}
	// Read meta against the CURRENT wrapped key — this validates the
	// fingerprint before we touch anything, and gives us the record to
	// rewrite with the new fingerprint.
	meta, err := readMeta(metaPath, oldWrapped)
	if err != nil {
		return err
	}
	vk, err := vcrypto.Unwrap(oldPassword, oldWrapped)
	if err != nil {
		return err // ErrWrongPassword or ErrBadFormat
	}
	defer zero(vk)

	newWrapped, err := vcrypto.Wrap(newPassword, vk, vcrypto.DefaultArgon2Params)
	if err != nil {
		return fmt.Errorf("vault: wrap: %w", err)
	}
	if err := writeFileAtomic(wrappedPath, newWrapped, 0o600); err != nil {
		return fmt.Errorf("vault: write wrapped key: %w", err)
	}
	meta.Fingerprint = computeFingerprint(newWrapped)
	if err := writeMeta(metaPath, meta); err != nil {
		return fmt.Errorf("vault: write meta: %w", err)
	}
	return nil
}

// Lock zeros the in-memory vault key. Idempotent.
//
// Callers MUST NOT snapshot s.vaultKey under RLock and then use the
// snapshot after RUnlock — see snapshotVaultKey for the safe pattern.
func (s *Store) Lock() {
	s.mu.Lock()
	zero(s.vaultKey)
	s.vaultKey = nil
	s.mu.Unlock()
}

// snapshotVaultKey returns a fresh-backing-array copy of the in-memory
// vault key. Callers MUST zero the returned slice when done.
//
// This is the safe pattern for data-plane ops (Put/Get/Rename) that
// need the key beyond the RLock window. The previous "key :=
// s.vaultKey" snapshot only copied the slice HEADER; the backing
// array was shared with Store.vaultKey. A concurrent Lock() then
// wrote zeros into that shared array mid-AEAD, sealing ciphertext
// under a zero key. snapshotVaultKey allocates a new backing array,
// copies under the read lock, releases the lock, and hands a slice
// the caller fully owns and is responsible for zeroing.
func (s *Store) snapshotVaultKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.vaultKey == nil {
		return nil
	}
	out := make([]byte, len(s.vaultKey))
	copy(out, s.vaultKey)
	return out
}

// IsLocked reports whether the vault is currently locked.
func (s *Store) IsLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.vaultKey == nil
}

// VaultID returns the UUID assigned at Init. Used by callers (e.g.,
// the daemon's audit log) that need to scope events to a specific
// vault.
func (s *Store) VaultID() string {
	return s.vaultID
}

// ---- Project CRUD -------------------------------------------------------

// CreateProject creates a project plus its implicit "default" env in
// one transaction. Name must satisfy ValidateProjectName.
func (s *Store) CreateProject(ctx context.Context, name string) error {
	if err := ValidateProjectName(name); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := nowUnix()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO projects (name, created_at, updated_at) VALUES (?, ?, ?)`,
		name, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrProjectExists
		}
		return err
	}
	projectID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO envs (project_id, name, is_default, created_at, updated_at)
		 VALUES (?, ?, 1, ?, ?)`,
		projectID, DefaultEnvName, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ListProjects returns all projects in name order.
func (s *Store) ListProjects(ctx context.Context) ([]ProjectInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, created_at, updated_at FROM projects ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []ProjectInfo
	for rows.Next() {
		var info ProjectInfo
		var createdNs, updatedNs int64
		if err := rows.Scan(&info.Name, &createdNs, &updatedNs); err != nil {
			return nil, err
		}
		info.CreatedAt = time.Unix(createdNs, 0).UTC()
		info.UpdatedAt = time.Unix(updatedNs, 0).UTC()
		out = append(out, info)
	}
	return out, rows.Err()
}

// DeleteProject removes a project and cascades to its envs + entries
// + entry_versions. A vault with zero projects is a valid state —
// callers can still create a new project later.
func (s *Store) DeleteProject(ctx context.Context, name string) error {
	if err := ValidateProjectName(name); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE name = ?`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrProjectNotFound
	}
	return nil
}

// RenameProject changes a project's name. Returns ErrProjectNotFound
// if oldName doesn't exist, ErrProjectExists if newName is taken.
func (s *Store) RenameProject(ctx context.Context, oldName, newName string) error {
	if err := ValidateProjectName(oldName); err != nil {
		return err
	}
	if err := ValidateProjectName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE projects SET name = ?, updated_at = ? WHERE name = ?`,
		newName, nowUnix(), oldName)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrProjectExists
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrProjectNotFound
	}
	return nil
}

// ---- Env CRUD -----------------------------------------------------------

// CreateEnv creates a non-default env in the named project.
func (s *Store) CreateEnv(ctx context.Context, project, name string) error {
	if err := ValidateProjectName(project); err != nil {
		return err
	}
	if err := ValidateEnvName(name); err != nil {
		return err
	}
	if name == DefaultEnvName {
		return ErrEnvExists // default is implicit and always present
	}
	projectID, err := s.projectIDByName(ctx, project)
	if err != nil {
		return err
	}
	now := nowUnix()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO envs (project_id, name, is_default, created_at, updated_at)
		 VALUES (?, ?, 0, ?, ?)`,
		projectID, name, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrEnvExists
		}
		return err
	}
	return nil
}

// ListEnvs returns envs for a project in (default-first, then name)
// order. Useful for the TUI's env switcher.
func (s *Store) ListEnvs(ctx context.Context, project string) ([]EnvInfo, error) {
	if err := ValidateProjectName(project); err != nil {
		return nil, err
	}
	projectID, err := s.projectIDByName(ctx, project)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, is_default, created_at, updated_at FROM envs
		 WHERE project_id = ?
		 ORDER BY is_default DESC, name`,
		projectID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []EnvInfo
	for rows.Next() {
		var info EnvInfo
		var isDefault int
		var createdNs, updatedNs int64
		if err := rows.Scan(&info.Name, &isDefault, &createdNs, &updatedNs); err != nil {
			return nil, err
		}
		info.IsDefault = isDefault == 1
		info.CreatedAt = time.Unix(createdNs, 0).UTC()
		info.UpdatedAt = time.Unix(updatedNs, 0).UTC()
		out = append(out, info)
	}
	return out, rows.Err()
}

// DeleteEnv removes a non-default env (and its entries) from a
// project. The default env is protected.
func (s *Store) DeleteEnv(ctx context.Context, project, name string) error {
	if err := ValidateProjectName(project); err != nil {
		return err
	}
	if err := ValidateEnvName(name); err != nil {
		return err
	}
	if name == DefaultEnvName {
		return ErrEnvProtected
	}
	projectID, err := s.projectIDByName(ctx, project)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM envs WHERE project_id = ? AND name = ? AND is_default = 0`,
		projectID, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrEnvNotFound
	}
	return nil
}

// RenameEnv changes an env's name within its project. Refuses to
// rename the default env, and refuses if the destination name is
// taken.
func (s *Store) RenameEnv(ctx context.Context, project, oldName, newName string) error {
	if err := ValidateProjectName(project); err != nil {
		return err
	}
	if err := ValidateEnvName(oldName); err != nil {
		return err
	}
	if err := ValidateEnvName(newName); err != nil {
		return err
	}
	if oldName == DefaultEnvName || newName == DefaultEnvName {
		return ErrEnvProtected
	}
	if oldName == newName {
		return nil
	}
	projectID, err := s.projectIDByName(ctx, project)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE envs SET name = ?, updated_at = ? WHERE project_id = ? AND name = ? AND is_default = 0`,
		newName, nowUnix(), projectID, oldName)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrEnvExists
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrEnvNotFound
	}
	return nil
}

// ---- Env-var CRUD (with inheritance) -----------------------------------

// PutEnvVar stores or updates an env_var entry in scope. Requires
// unlock.
func (s *Store) PutEnvVar(ctx context.Context, scope Scope, name string, value []byte, opt PutOpt) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateEntryName(name); err != nil {
		return err
	}
	if len(value) > MaxValueLen {
		return fmt.Errorf("vault: value too large (%d > %d)", len(value), MaxValueLen)
	}

	key := s.snapshotVaultKey()
	if key == nil {
		return ErrLocked
	}
	defer zero(key)

	aad := s.entryAAD(kindAADEnvVar, name)
	ct, err := vcrypto.EncryptWithAAD(key, value, aad)
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}

	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return err
	}

	now := nowUnix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if opt.CreateOnly {
		var exists int
		switch err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM entries WHERE project_id = ? AND env_id = ? AND name = ?`,
			projectID, envID, name).Scan(&exists); {
		case err == nil:
			return ErrExists
		case errors.Is(err, sql.ErrNoRows):
			// proceed
		default:
			return err
		}
	}

	// Upsert preserving created_at if a row already exists for this
	// scope+name.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO entries (project_id, env_id, kind, name, value, aad_version, created_at, updated_at)
		 VALUES (?, ?, 'env_var', ?, ?, 1, ?, ?)
		 ON CONFLICT(project_id, env_id, name) DO UPDATE SET
			value=excluded.value, aad_version=excluded.aad_version, updated_at=excluded.updated_at`,
		projectID, envID, name, ct, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

// GetEnvVar returns the decrypted value of name in scope. Applies
// inheritance: when scope.Env != "default" and no override exists,
// falls back to the default env. Requires unlock.
func (s *Store) GetEnvVar(ctx context.Context, scope Scope, name string) (Entry, error) {
	if err := scope.Validate(); err != nil {
		return Entry{}, err
	}
	if err := validateEntryName(name); err != nil {
		return Entry{}, err
	}
	key := s.snapshotVaultKey()
	if key == nil {
		return Entry{}, ErrLocked
	}
	defer zero(key)

	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return Entry{}, err
	}

	// First look in the requested env.
	entry, ok, err := s.fetchEntry(ctx, projectID, envID, "env_var", name)
	if err != nil {
		return Entry{}, err
	}
	if ok {
		return s.decryptEntry(key, entry, SourceScope)
	}
	// Fall back to default env if we weren't already in it.
	if scope.Env == DefaultEnvName {
		return Entry{}, ErrNotFound
	}
	defaultEnvID, err := s.envIDByName(ctx, projectID, DefaultEnvName)
	if err != nil {
		return Entry{}, err
	}
	entry, ok, err = s.fetchEntry(ctx, projectID, defaultEnvID, "env_var", name)
	if err != nil {
		return Entry{}, err
	}
	if !ok {
		return Entry{}, ErrNotFound
	}
	return s.decryptEntry(key, entry, SourceDefault)
}

// ListEnvVars lists env_var entries for scope, merging with the
// default env. Each row's Source field reports whether the value is
// the requested env's own override or inherited from default. Does
// NOT require unlock — the index is always browseable.
func (s *Store) ListEnvVars(ctx context.Context, scope Scope) ([]EntryInfo, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return nil, err
	}
	// If we're in the default env, the merged set is just the env
	// itself with everything labeled SourceScope.
	if scope.Env == DefaultEnvName {
		return s.listEntriesForEnv(ctx, projectID, envID, SourceScope)
	}
	defaultEnvID, err := s.envIDByName(ctx, projectID, DefaultEnvName)
	if err != nil {
		return nil, err
	}
	// Combine env-specific entries (preferred) with default entries
	// (fallback for unshadowed names).
	rows, err := s.db.QueryContext(ctx,
		`WITH scope_entries AS (
			SELECT name, kind, created_at, updated_at, 'scope' AS source
			FROM entries WHERE project_id = ? AND env_id = ? AND kind = 'env_var'
		), default_entries AS (
			SELECT name, kind, created_at, updated_at, 'default' AS source
			FROM entries WHERE project_id = ? AND env_id = ? AND kind = 'env_var'
		)
		SELECT name, kind, created_at, updated_at, source FROM scope_entries
		UNION ALL
		SELECT name, kind, created_at, updated_at, source FROM default_entries
		WHERE name NOT IN (SELECT name FROM scope_entries)
		ORDER BY name`,
		projectID, envID, projectID, defaultEnvID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanEntryInfos(rows)
}

// DeleteEnvVar removes an env_var entry from scope. Refuses to
// inherit-and-delete: the row must exist in the requested env. Does
// NOT require unlock.
func (s *Store) DeleteEnvVar(ctx context.Context, scope Scope, name string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateEntryName(name); err != nil {
		return err
	}
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM entries WHERE project_id = ? AND env_id = ? AND kind = 'env_var' AND name = ?`,
		projectID, envID, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RenameEnvVar renames an entry within scope. Requires the entry to
// exist in the requested env (no rename via inheritance). Refuses if
// the destination name is taken in the same scope.
func (s *Store) RenameEnvVar(ctx context.Context, scope Scope, oldName, newName string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateEntryName(oldName); err != nil {
		return err
	}
	if err := validateEntryName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return err
	}

	key := s.snapshotVaultKey()
	if key == nil {
		// Rename re-encrypts because the AAD is bound to the name.
		// Requires unlock.
		return ErrLocked
	}
	defer zero(key)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Destination must not exist in the same scope.
	var exists int
	switch err := tx.QueryRowContext(ctx,
		`SELECT 1 FROM entries WHERE project_id = ? AND env_id = ? AND name = ?`,
		projectID, envID, newName).Scan(&exists); {
	case err == nil:
		return ErrExists
	case errors.Is(err, sql.ErrNoRows):
		// proceed
	default:
		return err
	}

	// Read the existing ciphertext, decrypt under the OLD AAD,
	// re-encrypt under the NEW AAD, then write back. The crypto
	// transformation is bound by the same DB transaction so a crash
	// can't leave half-renamed state.
	var ctOld []byte
	err = tx.QueryRowContext(ctx,
		`SELECT value FROM entries WHERE project_id = ? AND env_id = ? AND kind = 'env_var' AND name = ?`,
		projectID, envID, oldName).Scan(&ctOld)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	pt, err := vcrypto.DecryptWithAAD(key, ctOld, s.entryAAD(kindAADEnvVar, oldName))
	if err != nil {
		return fmt.Errorf("vault: decrypt during rename: %w", err)
	}
	ctNew, err := vcrypto.EncryptWithAAD(key, pt, s.entryAAD(kindAADEnvVar, newName))
	if err != nil {
		zero(pt)
		return fmt.Errorf("vault: encrypt during rename: %w", err)
	}
	zero(pt)
	if _, err := tx.ExecContext(ctx,
		`UPDATE entries SET name = ?, value = ?, updated_at = ?
		 WHERE project_id = ? AND env_id = ? AND kind = 'env_var' AND name = ?`,
		newName, ctNew, nowUnix(), projectID, envID, oldName); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- internal helpers --------------------------------------------------

// entryAAD constructs the AAD bytes bound to an entry's ciphertext.
// Layout: vault_id || 0x1F || kind || 0x1F || name. The 0x1F (Unit
// Separator) is unlikely in any user-supplied input and survives
// across renames as long as the underlying encoding is consistent.
func (s *Store) entryAAD(kind, name string) []byte {
	const sep = 0x1F
	aad := make([]byte, 0, len(s.vaultID)+1+len(kind)+1+len(name))
	aad = append(aad, s.vaultID...)
	aad = append(aad, sep)
	aad = append(aad, kind...)
	aad = append(aad, sep)
	aad = append(aad, name...)
	return aad
}

// scopeIDs resolves the (project, env) string scope to numeric IDs in
// the DB. Returns ErrProjectNotFound / ErrEnvNotFound as appropriate.
func (s *Store) scopeIDs(ctx context.Context, scope Scope) (projectID, envID int64, err error) {
	projectID, err = s.projectIDByName(ctx, scope.Project)
	if err != nil {
		return 0, 0, err
	}
	envID, err = s.envIDByName(ctx, projectID, scope.Env)
	if err != nil {
		return 0, 0, err
	}
	return projectID, envID, nil
}

func (s *Store) projectIDByName(ctx context.Context, name string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM projects WHERE name = ?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrProjectNotFound
	}
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) envIDByName(ctx context.Context, projectID int64, name string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM envs WHERE project_id = ? AND name = ?`, projectID, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrEnvNotFound
	}
	if err != nil {
		return 0, err
	}
	return id, nil
}

// entryRow is the result of a single-entry fetch before decryption.
type entryRow struct {
	Name       string
	Kind       string
	Value      []byte
	AADVersion int
	CreatedAt  int64
	UpdatedAt  int64
}

func (s *Store) fetchEntry(ctx context.Context, projectID, envID int64, kind, name string) (entryRow, bool, error) {
	var r entryRow
	err := s.db.QueryRowContext(ctx,
		`SELECT name, kind, value, aad_version, created_at, updated_at
		 FROM entries WHERE project_id = ? AND env_id = ? AND kind = ? AND name = ?`,
		projectID, envID, kind, name).Scan(&r.Name, &r.Kind, &r.Value, &r.AADVersion, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	return r, true, nil
}

// decryptEntry returns a fully-populated Entry from an entryRow read
// out of the DB. Validates AAD; AAD-mismatch returns a decrypt error
// the caller surfaces verbatim (callers above this layer don't see
// the raw AEAD).
func (s *Store) decryptEntry(key []byte, r entryRow, source Source) (Entry, error) {
	if r.AADVersion != 1 {
		// Pre-1.0: no legacy versions exist. Any other value =
		// corruption / out-of-band tampering.
		return Entry{}, fmt.Errorf("vault: unknown aad_version=%d for %q", r.AADVersion, r.Name)
	}
	pt, err := vcrypto.DecryptWithAAD(key, r.Value, s.entryAAD(r.Kind, r.Name))
	if err != nil {
		return Entry{}, fmt.Errorf("vault: decrypt %q: %w", r.Name, err)
	}
	return Entry{
		Name:      r.Name,
		Value:     pt,
		Kind:      r.Kind,
		Source:    source,
		CreatedAt: time.Unix(r.CreatedAt, 0).UTC(),
		UpdatedAt: time.Unix(r.UpdatedAt, 0).UTC(),
	}, nil
}

// listEntriesForEnv returns metadata for every entry in (project, env)
// matching kind='env_var'. Source is uniform across all rows.
func (s *Store) listEntriesForEnv(ctx context.Context, projectID, envID int64, source Source) ([]EntryInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, kind, created_at, updated_at FROM entries
		 WHERE project_id = ? AND env_id = ? AND kind = 'env_var'
		 ORDER BY name`,
		projectID, envID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []EntryInfo
	for rows.Next() {
		var info EntryInfo
		var createdNs, updatedNs int64
		if err := rows.Scan(&info.Name, &info.Kind, &createdNs, &updatedNs); err != nil {
			return nil, err
		}
		info.Source = source
		info.CreatedAt = time.Unix(createdNs, 0).UTC()
		info.UpdatedAt = time.Unix(updatedNs, 0).UTC()
		out = append(out, info)
	}
	return out, rows.Err()
}

func scanEntryInfos(rows *sql.Rows) ([]EntryInfo, error) {
	var out []EntryInfo
	for rows.Next() {
		var info EntryInfo
		var createdNs, updatedNs int64
		var source string
		if err := rows.Scan(&info.Name, &info.Kind, &createdNs, &updatedNs, &source); err != nil {
			return nil, err
		}
		info.CreatedAt = time.Unix(createdNs, 0).UTC()
		info.UpdatedAt = time.Unix(updatedNs, 0).UTC()
		if source == "default" {
			info.Source = SourceDefault
		}
		out = append(out, info)
	}
	return out, rows.Err()
}

// ---- name validation ----------------------------------------------------

// projectNameRegex matches the same pattern as the daemon-level rules
// (lowercase alphanum, _, - after first char). Centralized so callers
// share the same answer.
var (
	projectNameRegex = vaultNameRegex // reuse — same rules
	envNameRegex     = vaultNameRegex
)

// ValidateProjectName / ValidateEnvName mirror the project/env name
// rules. Exported for daemon-side checks pre-IPC.
func ValidateProjectName(name string) error {
	if !projectNameRegex.MatchString(name) {
		return ErrBadProjectName
	}
	return nil
}

// ValidateEnvName returns nil if name is acceptable as an env name.
func ValidateEnvName(name string) error {
	if !envNameRegex.MatchString(name) {
		return ErrBadEnvName
	}
	return nil
}

// validateEntryName checks env-var / file entry names: 1..MaxNameLen
// chars, no NUL bytes. We do NOT enforce the project/env regex on
// entry names — env_var names need to allow upper-case (AWS_KEY) and
// shell-friendly characters.
func validateEntryName(name string) error {
	if name == "" {
		return ErrBadName
	}
	if len(name) > MaxNameLen {
		return ErrBadName
	}
	for i := 0; i < len(name); i++ {
		if name[i] == 0 {
			return ErrBadName
		}
	}
	return nil
}

// isUniqueViolation tells whether a SQLite error is a unique-index
// conflict. modernc.org/sqlite wraps native errors; the message is
// stable enough to match on.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// "UNIQUE constraint failed: ..." is the canonical SQLite message.
	for i := 0; i+6 <= len(msg); i++ {
		if msg[i:i+6] == "UNIQUE" {
			return true
		}
	}
	return false
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
