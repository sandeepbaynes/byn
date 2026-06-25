package migrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/vault"
)

// Options carries the knobs both migrate modes share: the target owner uid/gid
// the adopted tree is chowned to (the _byn service account's, resolved by the
// caller — never hardcoded), Force to replace a non-empty destination, and an
// injected Chowner so the core is unit-testable without root (a negative
// uid/gid additionally skips the chown — os.Chown semantics). It is the
// mode-level analogue of [AdoptOptions]; Relocate/Import translate it into the
// AdoptOptions the verify/atomic/fail-safe core consumes.
type Options struct {
	UID     int
	GID     int
	Force   bool
	Chowner Chowner
}

// Relocate performs the legacy same-machine upgrade: it adopts the byn data
// tree at legacyDir (typically ~/.byn) into systemDir, then — only after a
// fully-successful adopt — removes legacyDir. This is MOVE semantics for a
// single machine, so the trust store and passkey enrollments are KEPT (same
// machine, same authenticators, same trusted .byn paths) — no Transform.
//
// Fail-safe: the source is removed ONLY after [Adopt] has verified, chowned, and
// atomically committed the destination. Any error before that leaves both
// legacyDir and systemDir exactly as they were (Adopt cleans its own staging).
// A remove failure after a successful adopt is surfaced but does not unwind the
// adopt — the data is already safely at systemDir; the stale legacyDir is a
// cleanup nuisance, not a data-loss event.
func Relocate(legacyDir, systemDir string, opts Options) error {
	if legacyDir == "" || systemDir == "" {
		return errors.New("migrate: relocate requires both a legacy and a system dir")
	}
	legacyDir = filepath.Clean(legacyDir)
	systemDir = filepath.Clean(systemDir)
	if legacyDir == systemDir {
		return fmt.Errorf("migrate: relocate source and destination are the same dir (%s)", systemDir)
	}

	src := NewLocalSource(legacyDir)
	rels, err := src.List()
	if err != nil {
		return err
	}
	if len(rels) == 0 {
		// The legacy dir exists but holds only daemon runtime ephemera (socket,
		// pidfile, log). This happens when the user ran `byn start` on a fresh
		// install before running `sudo byn setup`. There is no vault to migrate;
		// proceed as a clean fresh install.
		return nil
	}
	if err := Adopt(src, systemDir, AdoptOptions{
		UID:     opts.UID,
		GID:     opts.GID,
		Force:   opts.Force,
		Chowner: opts.Chowner,
		// No Transform: a same-machine relocate keeps trust + passkeys.
	}); err != nil {
		return err
	}

	// Adopt committed the destination; now drop the old tree. After this point a
	// failure does not endanger the vault (it already lives at systemDir).
	if err := os.RemoveAll(legacyDir); err != nil {
		return fmt.Errorf("migrate: relocated to %s but could not remove the old data dir %s: %w (remove it by hand)", systemDir, legacyDir, err)
	}
	return nil
}

// Import copies an EXTERNAL byn vault (a backup, a mounted disk, a synced dir —
// anything exposed via an [ImportSource]) into systemDir, and DROPS the trust
// store + passkey enrollments (spec §6.2 D1). The source is NEVER deleted; a
// non-empty destination is refused unless opts.Force is set.
//
// Trust is never silently carried across a source boundary: an import brings
// vault DATA only, so the owner must re-trust their .byn files and re-enroll
// passkeys on this machine. The drop is implemented as an [AdoptOptions.Transform]
// that runs on the VERIFIED staged copy before the atomic commit, so:
//   - verification (which rejects a malformed/hostile vault) runs on the
//     ORIGINAL artifacts, before anything is dropped;
//   - the adopted destination NEVER contains trusted_byn.json or any passkey
//     enrollment — there is no window where a half-dropped tree is live.
//
// The trust store is a separate file (trusted_byn.json) and is simply removed
// from the staged tree. Passkey enrollments are NOT files — they are the
// `passkey`/`passkey_unlock` tables inside each vault.db — so they are dropped
// by emptying those tables in every staged vault (vault.ClearPasskeyEnrollments).
func Import(src ImportSource, systemDir string, opts Options) error {
	if src == nil {
		return errors.New("migrate: nil import source")
	}
	if systemDir == "" {
		return errors.New("migrate: import requires a system dir")
	}
	return Adopt(src, filepath.Clean(systemDir), AdoptOptions{
		UID:       opts.UID,
		GID:       opts.GID,
		Force:     opts.Force,
		Chowner:   opts.Chowner,
		Transform: dropTrustAndPasskeys,
	})
}

// dropTrustAndPasskeys is Import's [AdoptOptions.Transform]: it removes the
// root-level trust store and empties the passkey tables of every staged vault.
// It runs on the verified staged copy before chown+commit (see [Import]).
func dropTrustAndPasskeys(stagedRoot string) error {
	// 1. Drop the trust store (a root-level file). Absent is fine — a source
	//    may simply have no trust store.
	trustPath := filepath.Join(stagedRoot, TrustStoreFilename)
	if err := os.Remove(trustPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("drop trust store: %w", err)
	}

	// 2. Empty the passkey tables in every staged vault.db. Enrollments live in
	//    the per-vault `passkey`/`passkey_unlock` tables, not as files.
	names, err := stagedVaultNames(stagedRoot)
	if err != nil {
		return err
	}
	ctx := context.Background()
	for _, name := range names {
		if err := clearVaultPasskeys(ctx, stagedRoot, name); err != nil {
			return err
		}
	}
	return nil
}

// clearVaultPasskeys opens one staged vault (password-free) and empties its
// passkey + passkey_unlock tables, then closes it so the file is fully flushed
// before the atomic commit moves it into place.
func clearVaultPasskeys(ctx context.Context, root, name string) error {
	st, err := vault.Open(ctx, root, name)
	if err != nil {
		return fmt.Errorf("drop passkeys: open vault %q: %w", name, err)
	}
	defer func() { _ = st.Close() }()
	if err := st.ClearPasskeyEnrollments(ctx); err != nil {
		return fmt.Errorf("drop passkeys: vault %q: %w", name, err)
	}
	return nil
}
