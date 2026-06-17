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
	require.GreaterOrEqual(t, len(cmd.Args), 5)
	assert.Equal(t, s.cfg.HelperPath, cmd.Args[0])
	assert.Equal(t, "--", cmd.Args[1])
	assert.Equal(t, sandboxExecPath, cmd.Args[2], "the target is wrapped in sandbox-exec AFTER the drop")
	assert.Equal(t, "-f", cmd.Args[3])
	assert.Contains(t, cmd.Args, "/usr/bin/printenv", "the real target must be passed through")

	// Guard the regression: the SETUID helper must NOT be wrapped in sandbox-exec.
	assert.NotEqual(t, sandboxExecPath, cmd.Args[0], "must not run sandbox-exec on the setuid helper")
}
