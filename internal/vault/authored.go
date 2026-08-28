package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// Writing to a locked vault.
//
// A locked vault holds no vault key, so it cannot encrypt — which meant `byn
// put` needed a password whenever the vault was locked, and an agent working
// alone had exactly one way forward: leave the vault unlocked. That is a worse
// trade than the one it solves. An unlocked vault exposes every secret in it;
// what an agent actually needs is to store the values it invents and read them
// back.
//
// So a scope has a second key. K_auth is derived from the vault key like K_env
// is, but with its own domain, and it is sealed into a trusted .byn's exec
// capability under the machine key — so a locked daemon can unseal it, write
// new entries with it, and open them again later. It can open nothing else:
// every entry that existed before derives from K_env, and K_auth never yields
// it.
//
// The honest statement of the trade: a value an agent writes while the vault is
// locked is protected by this machine rather than by the master password.
// Everything that was already in the vault keeps the master password as its
// only key. That is strictly better than the alternative it replaces, where
// leaving the vault unlocked put every secret in the same position.

// AuthoredKey returns the self-authored key for one (project, env) scope,
// derived from the vault key.
func (s *Store) AuthoredKey(vaultKey []byte, projectID, envID int64) ([]byte, error) {
	return vcrypto.DeriveAuthoredKey(vaultKey, s.scopeAAD(projectID, envID))
}

// authoredRowKey derives one entry's key from an already-unsealed authored key.
// The scope is bound by the authored key itself, so only the row identity is
// mixed in here — the same shape as the K_env scheme one level up.
func authoredRowKey(authoredKey []byte, kind, name string) ([]byte, error) {
	return vcrypto.DeriveRowKeyFromAuthoredKey(authoredKey, rowAAD(kind, name))
}

// CaptureAuthoredKey returns the scope's authored key, for sealing into a
// trusted .byn's exec capability. Requires the vault to be unlocked, which is
// the point: granting trust is when a human is present, and it is the moment
// the machine is handed the ability to write on their behalf afterwards.
func (s *Store) CaptureAuthoredKey(ctx context.Context, scope Scope) ([]byte, error) {
	vk := s.snapshotVaultKey()
	if vk == nil {
		return nil, ErrLocked
	}
	defer zero(vk)
	return s.authoredKeyForScope(ctx, vk, scope)
}

// CaptureAuthoredKeyWithPassword is CaptureAuthoredKey for a locked vault,
// verifying the master password to obtain the vault key without unlocking it.
func (s *Store) CaptureAuthoredKeyWithPassword(ctx context.Context, password []byte, scope Scope) ([]byte, error) {
	wrapped, err := os.ReadFile(filepath.Join(s.dir, wrappedFilename)) // #nosec G304 -- path is store-configured
	if err != nil {
		return nil, fmt.Errorf("vault: read wrapped key: %w", err)
	}
	vk, err := vcrypto.Unwrap(password, wrapped)
	if err != nil {
		return nil, err
	}
	defer zero(vk)
	return s.authoredKeyForScope(ctx, vk, scope)
}

func (s *Store) authoredKeyForScope(ctx context.Context, vaultKey []byte, scope Scope) ([]byte, error) {
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return nil, err
	}
	return s.AuthoredKey(vaultKey, projectID, envID)
}

// PutEnvVarAuthored stores name in scope using an unsealed authored key,
// without the vault key — so it works while the vault is locked.
//
// opt.CreateOnly is honoured exactly as PutEnvVar honours it, so a caller can
// still distinguish creating a value from overwriting one; that distinction is
// what authorization upstream is built on.
func (s *Store) PutEnvVarAuthored(ctx context.Context, scope Scope, name string, value, authoredKey []byte, opt PutOpt) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateEntryName(name); err != nil {
		return err
	}
	if len(value) > MaxValueLen {
		return fmt.Errorf("vault: value too large (%d > %d)", len(value), MaxValueLen)
	}
	if len(authoredKey) == 0 {
		return ErrLocked
	}

	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return err
	}
	krow, err := authoredRowKey(authoredKey, kindAADEnvVar, name)
	if err != nil {
		return err
	}
	defer zero(krow)
	ct, err := vcrypto.EncryptWithAAD(krow, value, s.entryAADV3(projectID, envID, kindAADEnvVar, name))
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
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

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO entries (project_id, env_id, kind, name, value, aad_version, created_at, updated_at)
		 VALUES (?, ?, 'env_var', ?, ?, ?, ?, ?)
		 ON CONFLICT(project_id, env_id, name) DO UPDATE SET
			value=excluded.value, aad_version=excluded.aad_version, updated_at=excluded.updated_at`,
		projectID, envID, name, ct, aadVersionAuthoredKey, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

// OpenEnvVarAuthored decrypts an entry written with the authored key, without
// the vault key.
//
// It refuses any row on another scheme rather than reporting it missing: a
// caller holding only the authored key must be told that the value exists and
// is not theirs to read, not misled into thinking the vault is empty.
func (s *Store) OpenEnvVarAuthored(ctx context.Context, scope Scope, name string, authoredKey []byte) ([]byte, error) {
	if len(authoredKey) == 0 {
		return nil, ErrLocked
	}
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return nil, err
	}
	r, rowEnvID, found, err := s.fetchEnvVarInherited(ctx, projectID, envID, scope.Env, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	if r.AADVersion != aadVersionAuthoredKey {
		return nil, errAuthoredKeyUnsupported
	}
	// An inherited row lives in the project's default env and derives from that
	// env's authored key, not the caller's. Refuse rather than derive with the
	// wrong key and report corruption.
	if rowEnvID != envID {
		return nil, errAuthoredKeyUnsupported
	}
	krow, err := authoredRowKey(authoredKey, kindAADEnvVar, name)
	if err != nil {
		return nil, err
	}
	defer zero(krow)
	return vcrypto.DecryptWithAAD(krow, r.Value, s.entryAADV3(projectID, envID, kindAADEnvVar, name))
}

// errAuthoredKeyUnsupported means the row is not one the authored key can open.
var errAuthoredKeyUnsupported = errors.New("vault: entry was not written with the authored key")

// IsAuthoredEntry reports whether name in scope is stored under the authored
// scheme — that is, whether it was written while the vault was locked.
func (s *Store) IsAuthoredEntry(ctx context.Context, scope Scope, name string) (bool, error) {
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return false, err
	}
	r, rowEnvID, found, err := s.fetchEnvVarInherited(ctx, projectID, envID, scope.Env, name)
	if err != nil || !found || rowEnvID != envID {
		return false, err
	}
	return r.AADVersion == aadVersionAuthoredKey, nil
}
