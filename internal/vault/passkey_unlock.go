package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// WrapVaultKey AEAD-wraps the in-memory vault key under kek (the HKDF-derived
// passkey KEK), binding the ciphertext to aad. Requires the vault unlocked.
// Used by passkey enrollment to store a second, PRF-recoverable copy of the key
// — the password-wrapped copy is untouched, so vault data is never re-encrypted.
// The raw vault key never leaves the Store.
func (s *Store) WrapVaultKey(kek, aad []byte) ([]byte, error) {
	vk := s.snapshotVaultKey()
	if vk == nil {
		return nil, ErrLocked
	}
	defer zero(vk)
	return vcrypto.EncryptWithAAD(kek, vk, aad)
}

// UnlockWithKEK unwraps a passkey-wrapped vault key with kek and, on success,
// installs it as the in-memory key — the passkey-unlock path. A wrong KEK,
// tampered ciphertext, or mismatched aad fails closed (AEAD authentication
// error), leaving the vault locked.
func (s *Store) UnlockWithKEK(kek, wrapped, aad []byte) error {
	vk, err := vcrypto.DecryptWithAAD(kek, wrapped, aad)
	if err != nil {
		return err
	}
	s.mu.Lock()
	zero(s.vaultKey)
	s.vaultKey = vk
	s.mu.Unlock()
	return nil
}

// PasskeyUnlock is the PRF-derived second wrapping of the vault key for one
// credential (A-auth.2). All fields are non-secret: the KEK that unwraps
// WrappedVaultKey is HKDF(prfOut), computed in the browser and never stored —
// security rests on possession of the authenticator plus user verification.
type PasskeyUnlock struct {
	CredentialID    []byte    // the WebAuthn credential this unlock binds to
	PRFSalt         []byte    // 32-byte PRF eval salt (stable per credential)
	WrappedVaultKey []byte    // AEAD(KEK, vault_key): nonce ‖ ct ‖ tag
	HKDFInfoVersion int       // info-string version for KEK derivation
	AEADAlg         string    // wrapping AEAD (e.g. "xchacha20poly1305")
	Label           string    // human label
	CreatedAt       time.Time // enrollment time
}

// AddPasskeyUnlock stores a PRF-unlock record. The credential_id must already
// exist in the passkey table (FK); enrollment registers the credential first.
func (s *Store) AddPasskeyUnlock(ctx context.Context, rec PasskeyUnlock) error {
	if len(rec.CredentialID) == 0 || len(rec.PRFSalt) == 0 || len(rec.WrappedVaultKey) == 0 {
		return fmt.Errorf("vault: passkey_unlock requires credential_id, prf_salt and wrapped_vault_key")
	}
	alg := rec.AEADAlg
	if alg == "" {
		alg = "xchacha20poly1305"
	}
	ver := rec.HKDFInfoVersion
	if ver == 0 {
		ver = 1
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO passkey_unlock (credential_id, prf_salt, wrapped_vault_key, hkdf_info_version, aead_alg, label, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rec.CredentialID, rec.PRFSalt, rec.WrappedVaultKey, int64(ver), alg, rec.Label, nowUnix()); err != nil {
		return fmt.Errorf("vault: add passkey_unlock: %w", err)
	}
	return nil
}

// PasskeyUnlockByCredentialID returns the PRF-unlock record for credID, or
// ErrNotFound when the credential has no unlock path (session-only passkey).
func (s *Store) PasskeyUnlockByCredentialID(ctx context.Context, credID []byte) (PasskeyUnlock, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT credential_id, prf_salt, wrapped_vault_key, hkdf_info_version, aead_alg, label, created_at
		 FROM passkey_unlock WHERE credential_id = ?`, credID)
	rec, err := scanPasskeyUnlock(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PasskeyUnlock{}, ErrNotFound
	}
	return rec, err
}

// PasskeyUnlocks lists every PRF-unlock record (newest first). Used to build
// the per-credential PRF eval salts for an assertion's evalByCredential map.
func (s *Store) PasskeyUnlocks(ctx context.Context) ([]PasskeyUnlock, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT credential_id, prf_salt, wrapped_vault_key, hkdf_info_version, aead_alg, label, created_at
		 FROM passkey_unlock ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PasskeyUnlock
	for rows.Next() {
		rec, serr := scanPasskeyUnlock(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// DeletePasskeyUnlock removes a credential's unlock path without removing the
// credential itself (downgrade to session-only). Revoking the credential
// (DeletePasskey) cascades to this row automatically.
func (s *Store) DeletePasskeyUnlock(ctx context.Context, credID []byte) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkey_unlock WHERE credential_id = ?`, credID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func scanPasskeyUnlock(sc interface{ Scan(...any) error }) (PasskeyUnlock, error) {
	var r PasskeyUnlock
	var ver, createdSec int64
	if err := sc.Scan(&r.CredentialID, &r.PRFSalt, &r.WrappedVaultKey, &ver, &r.AEADAlg, &r.Label, &createdSec); err != nil {
		return PasskeyUnlock{}, err
	}
	r.HKDFInfoVersion = int(ver)
	r.CreatedAt = time.Unix(createdSec, 0).UTC()
	return r, nil
}
