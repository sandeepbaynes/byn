//go:build unix

package migrate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdoptRealChownRoot exercises the production OSChown against a real uid/gid
// to confirm the wiring. It is root-gated (chown to an arbitrary uid requires
// CAP_CHOWN) and skips cleanly off-root, like the other privsep tests. Unix-only
// because it reads the on-disk owner via *syscall.Stat_t.
func TestAdoptRealChownRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root (euid == 0) to chown to an arbitrary uid")
	}
	srcRoot := buildRealVaultTree(t, "default", false)
	dest := filepath.Join(t.TempDir(), "data")

	const uid, gid = 1, 1 // daemon/bin — present on every unix
	require.NoError(t, Adopt(NewLocalSource(srcRoot), dest, AdoptOptions{UID: uid, GID: gid}))

	info, err := os.Stat(filepath.Join(dest, "vaults", "default", "vault.db"))
	require.NoError(t, err)
	st, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok, "expected *syscall.Stat_t")
	assert.Equal(t, uint32(uid), st.Uid)
	assert.Equal(t, uint32(gid), st.Gid)
}
