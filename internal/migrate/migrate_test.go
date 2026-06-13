package migrate

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedRealisticTree lays out a tempdir mirroring a real byn data root: a
// two-vault tree (each with vault.db / wrapped.key / meta.json), audit logs,
// the root-level trust store + config, AND the ephemera a running daemon leaves
// behind (socket, pidfile, log, portal token, rate-limiter state, owner record,
// a per-tty session, and an atomic-write temp file). It returns the root and
// the set of relative paths that are state artifacts (slash form).
func seedRealisticTree(t *testing.T) (root string, wantState []string) {
	t.Helper()
	root = t.TempDir()

	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}

	// --- State artifacts (must be carried) ---
	state := []string{
		"vaults/default/vault.db",
		"vaults/default/wrapped.key",
		"vaults/default/meta.json",
		"vaults/work/vault.db",
		"vaults/work/wrapped.key",
		"vaults/work/meta.json",
		"audit/default/2026-06.log",
		"audit/default/2026-05.log",
		"audit/work/2026-06.log",
		"trusted_byn.json",
		"config",
	}
	for _, rel := range state {
		write(rel, "STATE:"+rel)
	}

	// --- Ephemera (must be skipped) ---
	for _, rel := range []string{
		"daemon.sock", // stand-in regular file for the Unix socket
		"daemon.pid",
		"daemon.log",
		"portal.token",
		"auth-state.json",
		"owner",
		"sessions/tty3-default.json",
		".portal.token.tmp1234", // atomic-write temp leftover
	} {
		write(rel, "EPHEMERA:"+rel)
	}

	sort.Strings(state)
	return root, state
}

func TestLocalSourceListReturnsExactlyStateArtifacts(t *testing.T) {
	root, want := seedRealisticTree(t)

	got, err := NewLocalSource(root).List()
	require.NoError(t, err)
	sort.Strings(got)

	assert.Equal(t, want, got, "List must return exactly the state artifacts")

	// Belt-and-suspenders: no ephemera basename leaks into the result.
	for _, rel := range got {
		assert.False(t, IsEphemeral(rel), "ephemeral path leaked into List: %s", rel)
		assert.True(t, IsStateArtifact(rel), "non-state path in List: %s", rel)
	}
	// And the known ephemera are genuinely absent.
	for _, bad := range []string{"daemon.sock", "daemon.pid", "daemon.log", "portal.token", "auth-state.json", "owner", "sessions/tty3-default.json"} {
		assert.NotContains(t, got, bad)
	}
}

func TestLocalSourceListEmptyAndMissingRoot(t *testing.T) {
	// Empty dir → empty list, no error.
	got, err := NewLocalSource(t.TempDir()).List()
	require.NoError(t, err)
	assert.Empty(t, got)

	// Missing root → error (surfaced from the walk).
	_, err = NewLocalSource(filepath.Join(t.TempDir(), "does-not-exist")).List()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list")
}

func TestLocalSourceOpenStreamsBytes(t *testing.T) {
	root, _ := seedRealisticTree(t)
	src := NewLocalSource(root)

	rc, err := src.Open("vaults/default/vault.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = rc.Close() })

	body, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "STATE:vaults/default/vault.db", string(body))

	// A root-level artifact opens too.
	rc2, err := src.Open("config")
	require.NoError(t, err)
	defer func() { _ = rc2.Close() }()
	body2, err := io.ReadAll(rc2)
	require.NoError(t, err)
	assert.Equal(t, "STATE:config", string(body2))
}

func TestLocalSourceOpenMissingArtifact(t *testing.T) {
	root, _ := seedRealisticTree(t)
	_, err := NewLocalSource(root).Open("vaults/ghost/vault.db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open")
	assert.True(t, os.IsNotExist(unwrap(err)), "missing artifact should be a not-exist error")
}

func TestLocalSourceOpenRejectsPathEscape(t *testing.T) {
	root, _ := seedRealisticTree(t)
	// Plant a secret OUTSIDE the root that an escape would otherwise reach.
	parent := filepath.Dir(root)
	secret := filepath.Join(parent, "secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte("TOP SECRET"), 0o600))
	t.Cleanup(func() { _ = os.Remove(secret) })

	escapes := []string{
		"../secret.txt",
		"../" + filepath.Base(secret),
		"vaults/../../secret.txt",
		"..",
		"a/b/../../../secret.txt",
	}
	for _, rel := range escapes {
		rc, err := NewLocalSource(root).Open(rel)
		require.Errorf(t, err, "escape %q must be rejected", rel)
		assert.Nil(t, rc)
		assert.NotContains(t, err.Error(), "TOP SECRET")
	}
}

func TestLocalSourceOpenRejectsAbsolutePath(t *testing.T) {
	root, _ := seedRealisticTree(t)
	secret := filepath.Join(filepath.Dir(root), "abs-secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte("ABS SECRET"), 0o600))
	t.Cleanup(func() { _ = os.Remove(secret) })

	abs := []string{secret, filepath.Join(root, "config")} // even an in-root absolute path is refused
	if runtime.GOOS == "windows" {
		abs = append(abs, `C:\Windows\System32\drivers\etc\hosts`)
	}
	for _, p := range abs {
		rc, err := NewLocalSource(root).Open(p)
		require.Errorf(t, err, "absolute path %q must be rejected", p)
		assert.Nil(t, rc)
		assert.Contains(t, err.Error(), "absolute")
	}
}

func TestLocalSourceOpenRejectsEmptyPath(t *testing.T) {
	root, _ := seedRealisticTree(t)
	for _, rel := range []string{"", ".", "./"} {
		_, err := NewLocalSource(root).Open(rel)
		require.Errorf(t, err, "empty path %q must be rejected", rel)
	}
}

func TestIsEphemeral(t *testing.T) {
	ephem := []string{
		"daemon.sock", "daemon.pid", "daemon.log", "portal.token",
		"auth-state.json", "owner",
		"sessions", "sessions/tty1-default.json",
		".portal.token.tmp987", ".owner.tmp42",
	}
	for _, rel := range ephem {
		assert.Truef(t, IsEphemeral(rel), "%q should be ephemeral", rel)
	}
	notEphem := []string{
		"config", "trusted_byn.json",
		"vaults/default/vault.db", "audit/work/2026-06.log",
		"sessionsfoo", // not the sessions/ subtree
		"",
	}
	for _, rel := range notEphem {
		assert.Falsef(t, IsEphemeral(rel), "%q should NOT be ephemeral", rel)
	}
}

func TestIsStateArtifact(t *testing.T) {
	state := []string{
		"config", "trusted_byn.json",
		"vaults/default/vault.db", "vaults/default/wrapped.key",
		"vaults/default/meta.json", "audit/default/2026-06.log",
	}
	for _, rel := range state {
		assert.Truef(t, IsStateArtifact(rel), "%q should be a state artifact", rel)
	}
	notState := []string{
		"daemon.sock", "portal.token", "owner", "auth-state.json",
		"sessions/tty1.json",
		"random.txt", // unknown root-level file is NOT state
		"daemon.log", // ephemeral even though it sits at root
		"",           // empty
		"vaults",     // a bare dir name is not an artifact (dirs aren't listed)
		"../escape",  // escape is never state
	}
	for _, rel := range notState {
		assert.Falsef(t, IsStateArtifact(rel), "%q should NOT be a state artifact", rel)
	}
}

func TestNormalizeRel(t *testing.T) {
	cases := map[string]string{
		"config":           "config",
		"./config":         "config",
		"vaults/./default": "vaults/default",
		"a/b/../c":         "a/c",
		".":                "",
		"":                 "",
		"../x":             "../x", // escape preserved for resolve() to reject
		"vaults/../../x":   "../x",
	}
	for in, want := range cases {
		assert.Equalf(t, want, normalizeRel(in), "normalizeRel(%q)", in)
	}
}

// unwrap peels one layer of fmt.Errorf %w wrapping so os.IsNotExist can see the
// underlying syscall error.
func unwrap(err error) error {
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		if inner := u.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}

func TestListUsesRealArtifactNamesNotInvented(t *testing.T) {
	// Guard against drift: the basenames this package classifies as state must
	// be the real on-disk names. A pure-string check, no filesystem.
	assert.Equal(t, "trusted_byn.json", TrustStoreFilename)
	assert.Equal(t, "config", ConfigFilename)
	assert.Equal(t, "vaults", VaultsSubdir)
	assert.Equal(t, "audit", AuditSubdir)
	assert.Equal(t, "sessions", SessionsSubdir)
	// And the ephemera set carries no state name.
	for s := range rootStateFiles {
		_, clash := ephemera[s]
		assert.Falsef(t, clash, "%q is in both state and ephemera", s)
	}
	assert.False(t, strings.HasPrefix(TrustStoreFilename, "."))
}
