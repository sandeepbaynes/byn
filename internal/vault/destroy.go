package vault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrProtectedVault is returned by Destroy when asked to remove the
// default vault, which must always exist.
var ErrProtectedVault = errors.New("vault: refusing to delete the default vault")

// Destroy securely removes a vault's on-disk data. It first overwrites the
// wrapped-key blob with random bytes — so the Argon2id-wrapped vault key
// cannot be recovered from disk forensics even if the directory removal is
// later undeleted — and then removes the vault directory
// <root>/vaults/<name>/ in full.
//
// It refuses to destroy the default vault (ErrProtectedVault) and returns
// ErrNotInit when the vault directory does not exist. The caller MUST
// close/evict any open Store for this vault before calling Destroy.
//
// Audit logs (<root>/audit/<name>/) are intentionally left in place: they
// are a forensic record of the vault's lifetime, kept outside the vault
// directory precisely so a delete cannot erase the trail.
func Destroy(root, name string) error {
	if err := ValidateVaultName(name); err != nil {
		return err
	}
	if name == DefaultVaultName {
		return ErrProtectedVault
	}
	dir := Dir(root, name)
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotInit
		}
		return fmt.Errorf("vault: stat %s: %w", dir, err)
	}
	// Best-effort secure wipe of the wrapped key before removal. A failure
	// here (e.g. the file was already gone) must not block the directory
	// removal — the RemoveAll below is what actually reclaims the space.
	_ = overwriteWithRandom(filepath.Join(dir, wrappedFilename))
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("vault: remove %s: %w", dir, err)
	}
	return nil
}

// overwriteWithRandom overwrites the file at path in place with as many
// random bytes as its current size, then fsyncs. Returns an error if the
// file is missing or cannot be written.
func overwriteWithRandom(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	buf := make([]byte, info.Size())
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600) // #nosec G304 -- caller-resolved vault path
	if err != nil {
		return err
	}
	if _, werr := f.Write(buf); werr != nil {
		_ = f.Close()
		return werr
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return serr
	}
	return f.Close()
}
