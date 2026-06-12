package migrate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sandeepbaynes/byn/internal/vault"
)

// enrollFakePasskey adds a passkey credential + a PRF-unlock row to the named
// vault under root, so an import test can prove the tables are emptied (and a
// relocate test can prove they survive). The vault is opened password-free.
func enrollFakePasskey(t *testing.T, root, name string) {
	t.Helper()
	ctx := context.Background()
	st, err := vault.Open(ctx, root, name)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()

	credID := []byte("cred-" + name)
	require.NoError(t, st.AddPasskey(ctx, vault.Passkey{
		CredentialID: credID,
		PublicKey:    []byte("pub"),
		Label:        "fake-" + name,
	}))
	require.NoError(t, st.AddPasskeyUnlock(ctx, vault.PasskeyUnlock{
		CredentialID:    credID,
		PRFSalt:         make([]byte, 32),
		WrappedVaultKey: []byte("wrapped"),
	}))
}

// passkeyCounts returns how many passkey + passkey_unlock rows the named vault
// under root has, opened password-free.
func passkeyCounts(t *testing.T, root, name string) (passkeys, unlocks int) {
	t.Helper()
	ctx := context.Background()
	st, err := vault.Open(ctx, root, name)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	pks, err := st.Passkeys(ctx)
	require.NoError(t, err)
	uls, err := st.PasskeyUnlocks(ctx)
	require.NoError(t, err)
	return len(pks), len(uls)
}

// --- Relocate ---------------------------------------------------------------

func TestRelocateMovesKeepsTrustAndPasskeysRemovesSource(t *testing.T) {
	legacy := buildRealVaultTree(t, "default", true)
	// Add a trust store + an enrolled passkey; relocate must KEEP both.
	require.NoError(t, os.WriteFile(filepath.Join(legacy, TrustStoreFilename), []byte(`{"trusted":[]}`), 0o600))
	enrollFakePasskey(t, legacy, "default")

	system := filepath.Join(t.TempDir(), "system")
	require.NoError(t, Relocate(legacy, system, Options{UID: -1, GID: -1}))

	// Source is gone (MOVE semantics).
	assert.NoDirExists(t, legacy, "relocate must remove the legacy dir on success")

	// Destination has the trust store (KEPT).
	assert.FileExists(t, filepath.Join(system, TrustStoreFilename))

	// Destination vault still has its passkey enrollments (KEPT).
	pk, ul := passkeyCounts(t, system, "default")
	assert.Equal(t, 1, pk, "relocate must keep passkey rows")
	assert.Equal(t, 1, ul, "relocate must keep passkey_unlock rows")

	// And the vault still opens (data intact).
	st, err := vault.Open(context.Background(), system, "default")
	require.NoError(t, err)
	_ = st.Close()
}

func TestRelocateSameDirRejected(t *testing.T) {
	dir := buildRealVaultTree(t, "default", false)
	err := Relocate(dir, dir, Options{UID: -1, GID: -1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same dir")
}

func TestRelocateEmptyArgsRejected(t *testing.T) {
	require.Error(t, Relocate("", "/tmp/x", Options{}))
	require.Error(t, Relocate("/tmp/x", "", Options{}))
}

func TestRelocateVerifyFailureLeavesSourceAndDestUntouched(t *testing.T) {
	legacy := buildRealVaultTree(t, "default", false)
	// Corrupt the vault.db so verify rejects it — relocate must NOT remove the
	// source and must NOT create the destination.
	dbPath := filepath.Join(legacy, "vaults", "default", "vault.db")
	require.NoError(t, os.WriteFile(dbPath, []byte("not a sqlite db"), 0o600))

	system := filepath.Join(t.TempDir(), "system")
	err := Relocate(legacy, system, Options{UID: -1, GID: -1})
	require.Error(t, err)

	// Source survives; destination never created.
	assert.DirExists(t, legacy, "a rejected relocate must not remove the source")
	assert.FileExists(t, dbPath)
	assert.NoDirExists(t, system)
}

// --- Import -----------------------------------------------------------------

func TestImportDropsTrustAndEmptiesPasskeysKeepsData(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", true)
	// The source carries a trust store AND an enrolled passkey — import drops both.
	require.NoError(t, os.WriteFile(filepath.Join(srcRoot, TrustStoreFilename), []byte(`{"trusted":["/some/path"]}`), 0o600))
	enrollFakePasskey(t, srcRoot, "default")

	// Sanity: the source genuinely has the passkey rows before import.
	pk, ul := passkeyCounts(t, srcRoot, "default")
	require.Equal(t, 1, pk)
	require.Equal(t, 1, ul)

	system := filepath.Join(t.TempDir(), "system")
	require.NoError(t, Import(NewLocalSource(srcRoot), system, Options{UID: -1, GID: -1}))

	// Source is left untouched (copy semantics) — trust file + passkeys still there.
	assert.FileExists(t, filepath.Join(srcRoot, TrustStoreFilename))
	spk, sul := passkeyCounts(t, srcRoot, "default")
	assert.Equal(t, 1, spk, "import must not mutate the source")
	assert.Equal(t, 1, sul, "import must not mutate the source")

	// Destination: trust store DROPPED.
	assert.NoFileExists(t, filepath.Join(system, TrustStoreFilename), "import must drop the trust store")

	// Destination: passkey tables EMPTIED.
	dpk, dul := passkeyCounts(t, system, "default")
	assert.Equal(t, 0, dpk, "import must empty the passkey table")
	assert.Equal(t, 0, dul, "import must empty the passkey_unlock table")

	// Destination: vault data + audit survive (the entries/chain are intact).
	st, err := vault.Open(context.Background(), system, "default")
	require.NoError(t, err)
	_ = st.Close()
	// Audit log file carried across.
	assert.DirExists(t, filepath.Join(system, "audit", "default"))
}

func TestImportMultiVaultEmptiesAllPasskeyTables(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	for _, name := range []string{"default", "work"} {
		st, err := vault.Init(ctx, root, name, []byte("pw-"+name))
		require.NoError(t, err)
		require.NoError(t, st.Close())
		enrollFakePasskey(t, root, name)
	}

	system := filepath.Join(t.TempDir(), "system")
	require.NoError(t, Import(NewLocalSource(root), system, Options{UID: -1, GID: -1}))

	for _, name := range []string{"default", "work"} {
		pk, ul := passkeyCounts(t, system, name)
		assert.Equalf(t, 0, pk, "vault %q passkey table must be empty", name)
		assert.Equalf(t, 0, ul, "vault %q passkey_unlock table must be empty", name)
	}
}

// TestImportVerifyBeforeDropRejectsHostileSource is the ordering guarantee:
// verification runs on the ORIGINAL artifacts BEFORE the drop, so a malformed
// import is rejected and the destination is never created — the drop never runs.
func TestImportVerifyBeforeDropRejectsHostileSource(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	require.NoError(t, os.WriteFile(filepath.Join(srcRoot, TrustStoreFilename), []byte(`{}`), 0o600))
	// Tamper the DB so verify fails. If the drop ran before verify, it would
	// have opened this DB (and failed differently); proving rejection leaves the
	// dest untouched proves verify gated the whole adopt.
	dbPath := filepath.Join(srcRoot, "vaults", "default", "vault.db")
	require.NoError(t, os.Truncate(dbPath, 16))

	system := filepath.Join(t.TempDir(), "system")
	err := Import(NewLocalSource(srcRoot), system, Options{UID: -1, GID: -1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify vault")

	// Destination never created → the drop never ran on a committed tree.
	assert.NoDirExists(t, system)
	assertNoStagingLeftover(t, system)
}

func TestImportRefusesNonEmptyDestWithoutForce(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	system := filepath.Join(t.TempDir(), "system")
	require.NoError(t, os.MkdirAll(system, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(system, "keep.txt"), []byte("existing"), 0o600))

	err := Import(NewLocalSource(srcRoot), system, Options{UID: -1, GID: -1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")
	assert.FileExists(t, filepath.Join(system, "keep.txt"), "refused import must not clobber the dest")
}

func TestImportForceReplacesNonEmptyDest(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false)
	enrollFakePasskey(t, srcRoot, "default")
	system := filepath.Join(t.TempDir(), "system")
	require.NoError(t, os.MkdirAll(filepath.Join(system, "old"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(system, "old", "stale.txt"), []byte("stale"), 0o600))

	require.NoError(t, Import(NewLocalSource(srcRoot), system, Options{UID: -1, GID: -1, Force: true}))

	assert.NoFileExists(t, filepath.Join(system, "old", "stale.txt"), "force must replace the old tree")
	pk, ul := passkeyCounts(t, system, "default")
	assert.Equal(t, 0, pk)
	assert.Equal(t, 0, ul)
}

func TestImportNilSourceAndEmptyDest(t *testing.T) {
	require.Error(t, Import(nil, t.TempDir(), Options{}))
	require.Error(t, Import(NewLocalSource(t.TempDir()), "", Options{}))
}

// TestImportNoTrustStoreInSourceIsFine proves dropping an absent trust store is
// a no-op (the source simply had none).
func TestImportNoTrustStoreInSourceIsFine(t *testing.T) {
	srcRoot := buildRealVaultTree(t, "default", false) // no trust store written
	system := filepath.Join(t.TempDir(), "system")
	require.NoError(t, Import(NewLocalSource(srcRoot), system, Options{UID: -1, GID: -1}))
	assert.NoFileExists(t, filepath.Join(system, TrustStoreFilename))
	st, err := vault.Open(context.Background(), system, "default")
	require.NoError(t, err)
	_ = st.Close()
}

// TestDropTrustAndPasskeysDirectly exercises the transform on a staged tree
// directly (covers the helper without routing through Adopt's commit), so the
// "trust file removed + passkey tables cleared" unit is pinned in isolation.
func TestDropTrustAndPasskeysDirectly(t *testing.T) {
	staged := buildRealVaultTree(t, "default", false)
	require.NoError(t, os.WriteFile(filepath.Join(staged, TrustStoreFilename), []byte(`{}`), 0o600))
	enrollFakePasskey(t, staged, "default")

	require.NoError(t, dropTrustAndPasskeys(staged))

	assert.NoFileExists(t, filepath.Join(staged, TrustStoreFilename))
	pk, ul := passkeyCounts(t, staged, "default")
	assert.Equal(t, 0, pk)
	assert.Equal(t, 0, ul)
}
