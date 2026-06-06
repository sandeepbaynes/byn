package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrVaultExists is returned by RenameVault when the destination name is
// already an initialized vault.
var ErrVaultExists = errors.New("vault: a vault with that name already exists")

// RenameVault moves <root>/vaults/<old>/ to <root>/vaults/<new>/ and updates
// the name recorded in meta.json. It refuses to rename the default vault or
// to overwrite an existing vault, and validates both names. The caller MUST
// close/evict any open Store for the old name first — an open SQLite handle
// pins the original path (sqlite derives its journal path from the filename
// it was opened with).
//
// The vault key and ciphertext are untouched: the AEAD AAD binds to the
// vault_id (a UUID), not the name, so a rename needs no re-encryption or
// re-wrap.
func RenameVault(root, oldName, newName string) error {
	if err := ValidateVaultName(oldName); err != nil {
		return err
	}
	if err := ValidateVaultName(newName); err != nil {
		return err
	}
	if oldName == DefaultVaultName {
		return ErrProtectedVault
	}
	if newName == DefaultVaultName {
		return ErrVaultExists // the default name is reserved
	}
	if oldName == newName {
		return nil
	}
	oldDir := Dir(root, oldName)
	newDir := Dir(root, newName)
	if !fileExists(filepath.Join(oldDir, MetaFilename)) {
		return ErrNotInit
	}
	if _, err := os.Stat(newDir); err == nil {
		return ErrVaultExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("vault: stat %s: %w", newDir, err)
	}

	// Update meta.json's recorded name first, so the on-disk record matches
	// the directory once the move completes. Read meta against the wrapped
	// key (this validates the fingerprint before we touch anything).
	metaPath := filepath.Join(oldDir, MetaFilename)
	wrapped, err := os.ReadFile(filepath.Join(oldDir, wrappedFilename)) // #nosec G304 -- caller-resolved path
	if err != nil {
		return fmt.Errorf("vault: read wrapped key: %w", err)
	}
	meta, err := readMeta(metaPath, wrapped)
	if err != nil {
		return err
	}
	meta.Name = newName
	if err := writeMeta(metaPath, meta); err != nil {
		return fmt.Errorf("vault: update meta: %w", err)
	}
	if err := os.Rename(oldDir, newDir); err != nil {
		return fmt.Errorf("vault: rename %s → %s: %w", oldDir, newDir, err)
	}
	return nil
}
