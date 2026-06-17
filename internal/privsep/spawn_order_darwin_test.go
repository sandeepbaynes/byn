//go:build darwin

package privsep

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSandboxCommand_HelperRunsBeforeSandbox locks in the macOS spawn order: the
// SETUID helper is exec'd DIRECTLY (argv[0]), and sandbox-exec wraps the
// NON-setuid target only AFTER the helper drops privileges. macOS refuses to
// exec a setuid binary while sandboxed ("execvp() ... Operation not permitted"),
// so the old order (sandbox-exec wrapping the helper) was broken.
//
// It also locks in that the profile is passed INLINE (-p <profile>), not as a
// -f temp file: after the drop, sandbox-exec runs as _byn-exec, which cannot
// read a profile file written into the daemon's (_byn) 0700 $TMPDIR — that
// regressed with "sandbox-exec: <file>: Permission denied".
func TestSandboxCommand_HelperRunsBeforeSandbox(t *testing.T) {
	s := &darwinSpawner{cfg: Config{
		HelperPath: "/usr/local/libexec/byn-exec-helper",
		StateDir:   "/Library/Application Support/byn", // non-empty → sandbox branch
	}}
	req := SpawnReq{Argv: []string{"/usr/bin/printenv", "TEST"}}

	cmd, cleanup, err := s.sandboxCommand(req, append([]string{"--"}, req.Argv...))
	require.NoError(t, err)
	defer cleanup()

	// The setuid helper runs FIRST, directly — not under sandbox-exec.
	assert.Equal(t, s.cfg.HelperPath, cmd.Path, "the setuid helper must be the exec'd binary")
	require.GreaterOrEqual(t, len(cmd.Args), 6)
	assert.Equal(t, s.cfg.HelperPath, cmd.Args[0])
	assert.Equal(t, "--", cmd.Args[1])
	assert.Equal(t, sandboxExecPath, cmd.Args[2], "the target is wrapped in sandbox-exec AFTER the drop")
	assert.Equal(t, "-p", cmd.Args[3], "the profile must be passed INLINE, not via a -f temp file")
	assert.Contains(t, cmd.Args[4], "(version 1)", "args[4] must be the inline SBPL profile string")
	assert.Contains(t, cmd.Args[4], s.cfg.StateDir, "the inline profile must carry the state-dir deny")
	assert.Equal(t, "/usr/bin/printenv", cmd.Args[5], "the real target follows the inline profile")

	// Guard the regressions: the SETUID helper must NOT be wrapped in sandbox-exec,
	// and no profile temp-file path may appear on argv (inline only).
	assert.NotEqual(t, sandboxExecPath, cmd.Args[0], "must not run sandbox-exec on the setuid helper")
	for _, a := range cmd.Args {
		assert.NotContains(t, a, "byn-sb-", "no temp profile file may be referenced; profile is inline")
	}
}
