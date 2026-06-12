package migrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Chowner sets ownership on a path. It is injected via [AdoptOptions] so the
// adopt core is unit-testable without root: tests pass a recording stub, while
// production passes [OSChown] (a thin os.Chown wrapper). The signature mirrors
// os.Chown (a -1 uid/gid leaves that field unchanged).
type Chowner func(path string, uid, gid int) error

// OSChown is the production [Chowner]: a direct os.Chown. It is the default when
// [AdoptOptions.Chowner] is nil.
func OSChown(path string, uid, gid int) error { return os.Chown(path, uid, gid) }

// AdoptOptions configures [Adopt]. UID/GID are the target owner the staged tree
// is chowned to (Task 10 passes the `_byn` service account's); they are supplied
// by the caller and never hardcoded. A negative UID or GID skips the chown for
// that field (os.Chown semantics) so a non-root unit test can adopt without
// changing ownership.
type AdoptOptions struct {
	// UID is the target owner uid for the adopted tree (e.g. _byn's). A
	// negative value leaves ownership unchanged (os.Chown semantics).
	UID int
	// GID is the target owner gid for the adopted tree (e.g. _byn's). A
	// negative value leaves ownership unchanged.
	GID int
	// Force permits replacing a non-empty destDir. Without it, a non-empty
	// destDir is refused so a migrate never clobbers an existing vault.
	Force bool
	// Chowner injects the ownership-setting call so the core is testable
	// without root. nil defaults to [OSChown].
	Chowner Chowner
}

// stagedDirMode is the permission the staged (and therefore adopted) tree gets:
// owner-only, matching the daemon's private state dir. The whole tree is forced
// to this so a hostile source can't smuggle a group/other-readable artifact in.
const stagedDirMode = 0o700

// Adopt copies every artifact a source exposes into destDir, but only after
// verifying — WITHOUT the vault password — that the staged copy is a well-formed
// byn data tree. A malformed, truncated, or hostile artifact set is rejected and
// destDir is left untouched.
//
// The flow, in order:
//
//  1. Stage every artifact from src.List() into a FRESH temp dir on the SAME
//     filesystem as destDir, preserving the relative layout, so the final
//     commit is an atomic rename (not a cross-device copy).
//  2. Verify the staged copy: every vaults/<name> opens as a well-formed,
//     correctly-versioned SQLite vault whose wrapped.key/meta.json fingerprint
//     matches, and whose audit chain (if present) is intact. Verification uses
//     the same password-free checks the daemon uses on open; it NEVER unlocks.
//  3. chmod 0700 + chown the staged tree to the target uid/gid via the injected
//     [Chowner].
//  4. Refuse to clobber a non-empty destDir unless opts.Force is set.
//  5. Atomically adopt: os.Rename(staged, destDir). With Force, the old destDir
//     is moved aside first and only removed AFTER the new tree is in place — so
//     the user is never left with no vault.
//
// On ANY error the temp dir is removed and destDir is left exactly as it was,
// with an actionable error. Adopt is idempotent / re-runnable.
//
// Adopt copies ciphertext + wrap only. It never derives or holds a vault key.
func Adopt(src ImportSource, destDir string, opts AdoptOptions) (err error) {
	if src == nil {
		return errors.New("migrate: nil import source")
	}
	if destDir == "" {
		return errors.New("migrate: empty destination dir")
	}
	chown := opts.Chowner
	if chown == nil {
		chown = OSChown
	}

	rels, err := src.List()
	if err != nil {
		return fmt.Errorf("migrate: list source: %w", err)
	}
	if len(rels) == 0 {
		return errors.New("migrate: source has no byn state artifacts to adopt")
	}

	// Stage into a sibling temp dir of destDir so the final rename is on the
	// same filesystem (atomic, not a cross-device copy). The parent of destDir
	// must exist; we do NOT create destDir itself (Adopt's rename creates it).
	destDir = filepath.Clean(destDir)
	parent := filepath.Dir(destDir)
	if err := os.MkdirAll(parent, stagedDirMode); err != nil {
		return fmt.Errorf("migrate: prepare destination parent %s: %w", parent, err)
	}
	staged, err := os.MkdirTemp(parent, ".byn-migrate-stage-*")
	if err != nil {
		return fmt.Errorf("migrate: create staging dir: %w", err)
	}
	// From here on, any failure must clean up the staging dir and leave destDir
	// untouched. A deferred cleanup runs unless we explicitly disarm it after a
	// successful commit.
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staged)
		}
	}()

	if err := stageArtifacts(src, rels, staged); err != nil {
		return err
	}
	if err := verifyStaged(staged); err != nil {
		return err
	}
	if err := applyOwnership(staged, opts.UID, opts.GID, chown); err != nil {
		return err
	}
	if err := commitAdopt(staged, destDir, opts.Force); err != nil {
		return err
	}
	committed = true
	return nil
}

// stageArtifacts copies each listed artifact from the source into staged,
// recreating the relative directory layout. Paths are re-validated against
// escape here even though a well-behaved source already confines them — the
// adopt core must not trust the source to be honest about its own paths.
func stageArtifacts(src ImportSource, rels []string, staged string) error {
	for _, rel := range rels {
		if !isSafeRel(rel) {
			return fmt.Errorf("migrate: source returned unsafe artifact path %q", rel)
		}
		dst := filepath.Join(staged, filepath.FromSlash(rel))
		// Confirm the join stayed inside staged (defence in depth).
		if !withinDir(staged, dst) {
			return fmt.Errorf("migrate: artifact path %q escapes staging dir", rel)
		}
		if err := os.MkdirAll(filepath.Dir(dst), stagedDirMode); err != nil {
			return fmt.Errorf("migrate: stage mkdir for %q: %w", rel, err)
		}
		if err := copyArtifact(src, rel, dst); err != nil {
			return err
		}
	}
	return nil
}

// copyArtifact streams one artifact from the source to dst with 0600 perms.
func copyArtifact(src ImportSource, rel, dst string) error {
	rc, err := src.Open(rel)
	if err != nil {
		return fmt.Errorf("migrate: open source artifact %q: %w", rel, err)
	}
	defer func() { _ = rc.Close() }()

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- dst confined to staged by withinDir
	if err != nil {
		return fmt.Errorf("migrate: create staged %q: %w", rel, err)
	}
	if _, err := io.Copy(f, rc); err != nil {
		_ = f.Close()
		return fmt.Errorf("migrate: copy artifact %q: %w", rel, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("migrate: finalize staged %q: %w", rel, err)
	}
	return nil
}

// verifyStaged confirms the staged tree is a well-formed byn data root WITHOUT
// the vault password. For every vaults/<name> it runs the same password-free
// checks the daemon runs on open — wrapped.key/meta.json present and
// fingerprint-matched, vault.db opens as SQLite with a supported schema_version
// — and, if the vault has audit logs, verifies the HMAC chain (the chain seed
// lives in the vault's meta table, readable while locked). It NEVER unlocks.
//
// A tree with zero vaults is rejected: adopting an artifact set with no vault is
// almost certainly a truncated or wrong source, and silently accepting it would
// hand the user an empty data root.
func verifyStaged(staged string) error {
	names, err := stagedVaultNames(staged)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return errors.New("migrate: staged source contains no vault — refusing to adopt an empty data root")
	}
	ctx := context.Background()
	for _, name := range names {
		if err := verifyOneVault(ctx, staged, name); err != nil {
			return err
		}
	}
	return nil
}

// verifyOneVault opens vault <name> under root (password-free) and verifies its
// audit chain. vault.Open does the heavy lifting: it rejects a missing/partial
// triplet, a wrapped.key/meta.json fingerprint mismatch, a truncated/garbage
// vault.db (fails to open or ping as SQLite), and an unsupported schema_version.
func verifyOneVault(ctx context.Context, root, name string) error {
	st, err := vault.Open(ctx, root, name)
	if err != nil {
		return fmt.Errorf("migrate: verify vault %q: %w", name, err)
	}
	defer func() { _ = st.Close() }()

	// Audit-chain integrity is verifiable without the vault key: the HMAC seed
	// is stored in the (unencrypted) meta table, so a locked Store can drive the
	// verifier. A missing audit dir verifies as intact (no events yet).
	logger, err := audit.New(ctx, root, st.VaultID(), name, st)
	if err != nil {
		return fmt.Errorf("migrate: verify vault %q audit: %w", name, err)
	}
	badIndex, _, err := logger.VerifyChain(ctx)
	if err != nil {
		return fmt.Errorf("migrate: verify vault %q audit chain: %w", name, err)
	}
	if badIndex >= 0 {
		return fmt.Errorf("migrate: vault %q audit chain broken at event %d — refusing to adopt a tampered audit log", name, badIndex)
	}
	return nil
}

// stagedVaultNames lists the vault subdirectories under staged/vaults that have
// a vault.db (so a stray empty dir doesn't count as a vault). Names are
// validated so a hostile source can't sneak a path-shaped vault name through.
func stagedVaultNames(staged string) ([]string, error) {
	vaultsRoot := filepath.Join(staged, VaultsSubdir)
	entries, err := os.ReadDir(vaultsRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("migrate: read staged vaults dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if err := vault.ValidateVaultName(name); err != nil {
			return nil, fmt.Errorf("migrate: staged vault dir %q has an invalid name: %w", name, err)
		}
		if _, statErr := os.Stat(filepath.Join(vaultsRoot, name, "vault.db")); statErr != nil {
			// A vault subdir without a vault.db is a partial/garbage entry —
			// vault.Open would reject it; surface it as a verify failure rather
			// than silently skipping.
			return nil, fmt.Errorf("migrate: staged vault %q is missing vault.db (partial source)", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// applyOwnership forces the whole staged tree to stagedDirMode and chowns every
// path to uid/gid via the injected chowner. chmod runs before chown so a hostile
// source-supplied permission bit never survives into the adopted tree, and so
// the tree is never momentarily group/other-accessible after the chown.
//
// The mode change goes through an os.Root scoped to the staging dir so it is
// symlink-traversal-safe (TOCTOU-hardened): any symlink in the staged tree is
// rejected outright (byn artifacts are plain files — a symlink is a hostile
// source trying to redirect the chmod/chown outside the tree). The injected
// chowner keeps the absolute path so the production OSChown is a plain os.Chown.
func applyOwnership(staged string, uid, gid int, chown Chowner) error {
	root, err := os.OpenRoot(staged)
	if err != nil {
		return fmt.Errorf("migrate: open staged root: %w", err)
	}
	defer func() { _ = root.Close() }()

	return filepath.WalkDir(staged, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("migrate: walk staged tree: %w", walkErr)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("migrate: refusing symlink in staged tree: %s", path)
		}
		rel, rerr := filepath.Rel(staged, path)
		if rerr != nil {
			return fmt.Errorf("migrate: relativize staged path %s: %w", path, rerr)
		}
		if rel == "." {
			// os.Root cannot chmod its own root via "."; do the root dir directly.
			if err := os.Chmod(staged, stagedDirMode); err != nil { // #nosec G302,G304 -- staged dir we just created
				return fmt.Errorf("migrate: chmod staged root %s: %w", staged, err)
			}
		} else if err := root.Chmod(rel, stagedDirMode); err != nil {
			return fmt.Errorf("migrate: chmod staged %s: %w", path, err)
		}
		if err := chown(path, uid, gid); err != nil {
			return fmt.Errorf("migrate: chown staged %s to %d:%d: %w", path, uid, gid, err)
		}
		return nil
	})
}

// commitAdopt makes the staged tree the destination in a single atomic step.
// When destDir does not exist, it is one rename. When destDir exists, Force
// must be set (else a clear refusal): the existing tree is moved aside, the new
// one is renamed into place, and only THEN is the old one removed — so an
// interruption never leaves the user with no vault.
func commitAdopt(staged, destDir string, force bool) error {
	nonEmpty, err := dirHasEntries(destDir)
	if err != nil {
		return err
	}
	if nonEmpty && !force {
		return fmt.Errorf("migrate: destination %s is not empty — refusing to overwrite an existing vault; pass --force to replace it", destDir)
	}

	if !nonEmpty {
		// destDir is absent or empty. Remove an empty-but-present dir so the
		// rename target is clear, then commit in one rename.
		if err := os.Remove(destDir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("migrate: clear empty destination %s: %w", destDir, err)
		}
		if err := os.Rename(staged, destDir); err != nil {
			return fmt.Errorf("migrate: adopt into %s: %w", destDir, err)
		}
		return nil
	}

	// Force replace: stage the old tree aside, swap in the new one, then drop
	// the old. The window between the two renames is the only non-atomic gap;
	// it leaves the OLD vault in place (under backup) if we crash, never none.
	backup := destDir + ".byn-migrate-old"
	_ = os.RemoveAll(backup) // clear a leftover from a previous interrupted run
	if err := os.Rename(destDir, backup); err != nil {
		return fmt.Errorf("migrate: move existing destination aside: %w", err)
	}
	if err := os.Rename(staged, destDir); err != nil {
		// Roll the old tree back so the user keeps their vault.
		if rbErr := os.Rename(backup, destDir); rbErr != nil {
			return fmt.Errorf("migrate: adopt into %s failed (%v) AND rollback failed (%v) — old vault is at %s", destDir, err, rbErr, backup)
		}
		return fmt.Errorf("migrate: adopt into %s: %w", destDir, err)
	}
	if err := os.RemoveAll(backup); err != nil {
		// The adopt succeeded; only the old-tree cleanup failed. Don't fail the
		// whole migrate for a leftover backup dir — surface it as a soft note by
		// returning nil (the new vault is live). Best-effort retry once.
		_ = os.RemoveAll(backup)
	}
	return nil
}

// dirHasEntries reports whether destDir exists and contains at least one entry.
// A missing dir is treated as empty (not an error). The staging backup name is
// not special-cased here — it lives beside destDir, not inside it.
func dirHasEntries(destDir string) (bool, error) {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("migrate: inspect destination %s: %w", destDir, err)
	}
	return len(entries) > 0, nil
}

// isSafeRel reports whether a source-relative artifact path is safe to stage:
// non-empty, slash-relative, not absolute, and not escaping via "..". This is
// the adopt core's own gate — it does not delegate trust to the source.
func isSafeRel(rel string) bool {
	clean := normalizeRel(rel)
	if clean == "" {
		return false
	}
	if filepath.IsAbs(rel) || filepath.IsAbs(filepath.FromSlash(rel)) {
		return false
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	return true
}

// withinDir reports whether path is dir itself or lies inside it, after
// cleaning. Used as defence-in-depth on the staged write target.
func withinDir(dir, path string) bool {
	dir = filepath.Clean(dir)
	path = filepath.Clean(path)
	if path == dir {
		return true
	}
	return strings.HasPrefix(path, dir+string(os.PathSeparator))
}
