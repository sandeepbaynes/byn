package migrate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/vault"
	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// TestMain lowers the vault KDF cost so the real vault fixtures these tests
// build (via vault.Init) don't each pay the ~1s production Argon2 cost, which
// would blow the -race timeout. The fixtures are still REAL vaults — only the
// wrap cost is reduced — so "well-formed" verification is genuine.
func TestMain(m *testing.M) {
	vault.SetKDFParamsForTesting(vcrypto.TestArgon2Params)
	os.Exit(m.Run())
}

// buildRealVaultTree initialises a genuine byn data root in a fresh tempdir
// with one real vault (vault.Init writes vault.db + wrapped.key + meta.json and
// seeds the audit chain). It optionally writes an audit log entry so the
// audit-chain verify has something to walk. Returns the root.
func buildRealVaultTree(t *testing.T, vaultName string, withAuditEvent bool) string {
	t.Helper()
	root := t.TempDir()
	ctx := context.Background()

	st, err := vault.Init(ctx, root, vaultName, []byte("correct horse battery staple"))
	require.NoError(t, err)
	defer func() { _ = st.Close() }()

	if withAuditEvent {
		logger, err := audit.New(ctx, root, st.VaultID(), vaultName, st)
		require.NoError(t, err)
		_, err = logger.Append(ctx, audit.Event{Op: "put", Outcome: audit.OutcomeOK})
		require.NoError(t, err)
	}
	return root
}

// recordingChowner is a test [Chowner] that records every call and can be set to
// fail on the Nth invocation to exercise the chown-failure path.
type recordingChowner struct {
	mu       sync.Mutex
	calls    []chownCall
	failAt   int // 1-based; 0 = never fail
	failWith error
}

type chownCall struct {
	path     string
	uid, gid int
}

func (c *recordingChowner) chown(path string, uid, gid int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, chownCall{path, uid, gid})
	if c.failAt > 0 && len(c.calls) == c.failAt {
		return c.failWith
	}
	return nil
}

func (c *recordingChowner) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

// dirEntries returns the sorted relative paths of every file under dir.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		require.NoError(t, rerr)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	require.NoError(t, err)
	return out
}

func TestAdoptGoodTreeIntoEmptyDest(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", true)
	src := NewLocalSource(srcRoot)
	wantArtifacts, err := src.List()
	require.NoError(t, err)
	require.NotEmpty(t, wantArtifacts)

	dest := filepath.Join(t.TempDir(), "data")
	ch := &recordingChowner{}
	const uid, gid = 4242, 4343

	err = Adopt(src, dest, AdoptOptions{UID: uid, GID: gid, Chowner: ch.chown})
	require.NoError(t, err)

	// Dest holds exactly the source's state artifacts.
	got := dirEntries(t, dest)
	assert.ElementsMatch(t, wantArtifacts, got, "adopted tree must match source artifacts")

	// The adopted tree is 0700 (every dir and file forced).
	require.NoError(t, filepath.WalkDir(dest, func(p string, _ os.DirEntry, err error) error {
		require.NoError(t, err)
		info, serr := os.Stat(p)
		require.NoError(t, serr)
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "path %s should be 0700", p)
		return nil
	}))

	// The injected chowner was called with the passed uid/gid for every path.
	assert.Positive(t, ch.count(), "chowner must have been called")
	ch.mu.Lock()
	for _, c := range ch.calls {
		assert.Equal(t, uid, c.uid)
		assert.Equal(t, gid, c.gid)
	}
	ch.mu.Unlock()

	// The adopted vault still opens (password-free) — proof it is well-formed.
	st, err := vault.Open(context.Background(), dest, "default")
	require.NoError(t, err)
	_ = st.Close()
}

func TestAdoptDefaultChownerWhenNil(t *testing.T) {
	// With a negative uid/gid the default OSChown is a no-op (os.Chown(-1,-1)),
	// so this exercises the nil-Chowner default branch without needing root.
	srcRoot := buildRealVaultTree(t, "default", false)
	dest := filepath.Join(t.TempDir(), "data")

	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: -1, GID: -1})
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(dest, "vaults", "default", "vault.db"))
}

func TestAdoptRejectsTruncatedVaultDB(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	// Corrupt vault.db AFTER init so the wrapped/meta fingerprint still matches
	// but the DB no longer opens as SQLite.
	dbPath := filepath.Join(srcRoot, "vaults", "default", "vault.db")
	require.NoError(t, os.WriteFile(dbPath, []byte("this is not a sqlite database"), 0o600))

	dest := filepath.Join(t.TempDir(), "data")
	ch := &recordingChowner{}
	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: 1, GID: 1, Chowner: ch.chown})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify vault")

	// Dest must be UNTOUCHED (never created) and the staging dir cleaned up.
	assert.NoDirExists(t, dest)
	assertNoStagingLeftover(t, dest)
}

func TestAdoptRejectsGarbageVaultDBAndPreservesOldDest(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	dbPath := filepath.Join(srcRoot, "vaults", "default", "vault.db")
	require.NoError(t, os.Truncate(dbPath, 16)) // truncate to a torn header

	// Pre-populate dest with existing content; a rejected adopt must leave it.
	dest := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.MkdirAll(dest, 0o700))
	sentinel := filepath.Join(dest, "i-was-here.txt")
	require.NoError(t, os.WriteFile(sentinel, []byte("old vault"), 0o600))

	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: 1, GID: 1, Force: true})
	require.Error(t, err)

	// Old dest content survives verbatim.
	body, rerr := os.ReadFile(sentinel)
	require.NoError(t, rerr)
	assert.Equal(t, "old vault", string(body))
	assertNoStagingLeftover(t, dest)
}

func TestAdoptRejectsMissingWrappedKey(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	require.NoError(t, os.Remove(filepath.Join(srcRoot, "vaults", "default", "wrapped.key")))

	dest := filepath.Join(t.TempDir(), "data")
	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: 1, GID: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify vault")
	assert.NoDirExists(t, dest)
	assertNoStagingLeftover(t, dest)
}

func TestAdoptRejectsMissingMeta(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	require.NoError(t, os.Remove(filepath.Join(srcRoot, "vaults", "default", "meta.json")))

	dest := filepath.Join(t.TempDir(), "data")
	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: 1, GID: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify vault")
	assert.NoDirExists(t, dest)
}

func TestAdoptRejectsTamperedMeta(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	// Rewriting meta.json breaks the wrapped-key fingerprint match → vault.Open
	// fails verification without ever needing the password.
	metaPath := filepath.Join(srcRoot, "vaults", "default", "meta.json")
	require.NoError(t, os.WriteFile(metaPath, []byte(`{"schema_version":1,"name":"default","vault_id":"x","created_at":1,"fingerprint":"deadbeef","fingerprint_alg":"sha256-v1"}`), 0o600))

	dest := filepath.Join(t.TempDir(), "data")
	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: 1, GID: 1})
	require.Error(t, err)
	assert.NoDirExists(t, dest)
}

func TestAdoptRejectsTamperedAuditChain(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", true)
	// Forge an extra audit line: its hmac_chain won't reproduce, so VerifyChain
	// reports a break and Adopt must refuse — all without the vault password.
	// Find the single month log file the seeded event created.
	auditDir := filepath.Join(srcRoot, "audit", "default")
	entries, err := os.ReadDir(auditDir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	logPath := filepath.Join(auditDir, entries[0].Name())
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString(`{"ts":1,"vault_id":"x","vault_name":"default","op":"put","outcome":"ok","hmac_chain":"00"}` + "\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	dest := filepath.Join(t.TempDir(), "data")
	err = Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: 1, GID: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit chain")
	assert.NoDirExists(t, dest)
}

func TestAdoptRefusesNonEmptyDestWithoutForce(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	dest := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.MkdirAll(dest, 0o700))
	existing := filepath.Join(dest, "existing.txt")
	require.NoError(t, os.WriteFile(existing, []byte("keep me"), 0o600))

	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: -1, GID: -1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")

	// Untouched: the existing file is still there, the vault was NOT adopted.
	assert.FileExists(t, existing)
	assert.NoFileExists(t, filepath.Join(dest, "vaults", "default", "vault.db"))
	assertNoStagingLeftover(t, dest)
}

func TestAdoptForceReplacesNonEmptyDest(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	dest := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.MkdirAll(filepath.Join(dest, "old"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "old", "stale.txt"), []byte("stale"), 0o600))

	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: -1, GID: -1, Force: true})
	require.NoError(t, err)

	// New vault is present; the old content is gone.
	assert.FileExists(t, filepath.Join(dest, "vaults", "default", "vault.db"))
	assert.NoFileExists(t, filepath.Join(dest, "old", "stale.txt"))
	assertNoStagingLeftover(t, dest)
}

func TestAdoptChownFailureLeavesDestUntouched(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	dest := filepath.Join(t.TempDir(), "data")
	ch := &recordingChowner{failAt: 1, failWith: errors.New("chown boom")}

	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: 1, GID: 1, Chowner: ch.chown})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chown")

	assert.NoDirExists(t, dest)
	assertNoStagingLeftover(t, dest)
}

func TestAdoptIdempotentRerun(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", true)
	dest := filepath.Join(t.TempDir(), "data")

	// First run into an empty dest.
	require.NoError(t, Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: -1, GID: -1}))
	first := dirEntries(t, dest)

	// Re-run with Force → same result, no leftover, vault still opens.
	require.NoError(t, Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: -1, GID: -1, Force: true}))
	second := dirEntries(t, dest)
	assert.ElementsMatch(t, first, second, "idempotent re-run must yield the same tree")
	assertNoStagingLeftover(t, dest)

	st, err := vault.Open(context.Background(), dest, "default")
	require.NoError(t, err)
	_ = st.Close()
}

func TestAdoptNilSourceAndEmptyDest(t *testing.T) {
	require.Error(t, Adopt(nil, t.TempDir(), AdoptOptions{}))
	require.Error(t, Adopt(NewLocalSource(t.TempDir()), "", AdoptOptions{}))
}

func TestAdoptEmptySourceRejected(t *testing.T) {
	// An empty source dir has no state artifacts → refused before staging.
	err := Adopt(NewLocalSource(t.TempDir()), filepath.Join(t.TempDir(), "data"), AdoptOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no byn state artifacts")
}

func TestAdoptMultiVaultAllVerified(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	for _, name := range []string{"default", "work"} {
		st, err := vault.Init(ctx, root, name, []byte("pw-"+name))
		require.NoError(t, err)
		require.NoError(t, st.Close())
	}
	dest := filepath.Join(t.TempDir(), "data")
	require.NoError(t, Adopt(NewLocalSource(root), dest, AdoptOptions{UID: -1, GID: -1}))
	assert.FileExists(t, filepath.Join(dest, "vaults", "default", "vault.db"))
	assert.FileExists(t, filepath.Join(dest, "vaults", "work", "vault.db"))
}

func TestAdoptTransformRunsAfterVerifyBeforeCommit(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	dest := filepath.Join(t.TempDir(), "data")

	// The transform plants a marker AND drops a file in the staged tree; both
	// must survive into the committed destination (proving it ran on the staged
	// copy before the atomic rename).
	called := false
	transform := func(stagedRoot string) error {
		called = true
		// vault.db must already exist + verify (transform runs after verify).
		assert.FileExists(t, filepath.Join(stagedRoot, "vaults", "default", "vault.db"))
		return os.WriteFile(filepath.Join(stagedRoot, "TRANSFORM_RAN"), []byte("yes"), 0o600)
	}

	require.NoError(t, Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: -1, GID: -1, Transform: transform}))
	assert.True(t, called, "transform must have been invoked")
	assert.FileExists(t, filepath.Join(dest, "TRANSFORM_RAN"), "transform output must reach the committed dest")
}

func TestAdoptTransformErrorAbortsAndLeavesDestUntouched(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	dest := filepath.Join(t.TempDir(), "data")

	transform := func(string) error { return errors.New("transform boom") }
	err := Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: -1, GID: -1, Transform: transform})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transform")

	assert.NoDirExists(t, dest, "a transform error must leave the dest uncreated")
	assertNoStagingLeftover(t, dest)
}

// assertNoStagingLeftover confirms no `.byn-migrate-stage-*` or
// `*.byn-migrate-old` residue is left beside dest after a (possibly failed)
// Adopt — the fail-safe must clean up.
func assertNoStagingLeftover(t *testing.T, dest string) {
	t.Helper()
	parent := filepath.Dir(dest)
	entries, err := os.ReadDir(parent)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	require.NoError(t, err)
	for _, e := range entries {
		name := e.Name()
		assert.NotContains(t, name, "byn-migrate-stage", "staging dir leaked: %s", name)
		assert.NotContains(t, name, "byn-migrate-old", "backup dir leaked: %s", name)
	}
}
