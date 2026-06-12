//go:build linux || darwin

package privsep

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireRootAndProvisioned skips the test unless:
//   - running as root (euid == 0),
//   - the _byn-exec service user is provisioned (LookupState.Provisioned),
//   - BYN_TEST_HELPER env var is set to the path of an installed byn-exec-helper.
//
// This mirrors the SO_PEERCRED skip pattern used in scm_test.go: root-gated
// integration paths skip cleanly in normal CI; they only run in a privileged
// integration environment.
func requireRootAndProvisioned(t *testing.T) (helperPath string, st State) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root (euid == 0)")
	}
	var err error
	st, err = LookupState()
	if err != nil || !st.Provisioned {
		t.Skipf("skipping: privsep not provisioned (LookupState: %v, err: %v)", st, err)
	}
	helperPath = os.Getenv("BYN_TEST_HELPER")
	if helperPath == "" {
		t.Skip("skipping: BYN_TEST_HELPER not set (path to installed byn-exec-helper required)")
	}
	return helperPath, st
}

// mustAtoiTrim parses a decimal-integer string (possibly with trailing
// whitespace / newline) into an int. Used to interpret the output of `id -u`.
func mustAtoiTrim(t *testing.T, s string) int {
	t.Helper()
	s = strings.TrimSpace(s)
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatalf("mustAtoiTrim: cannot parse %q as int: %v", s, err)
	}
	return n
}

// TestSpawnRejectsRelativeTarget verifies that Spawn returns an error when
// argv[0] is a relative (non-absolute) path. This test does NOT require root
// and runs everywhere because it exercises the in-process guard only.
func TestSpawnRejectsRelativeTarget(t *testing.T) {
	// Use a dummy Config — the helper is never invoked, so HelperPath need not
	// exist. We exercise only the argv[0] absolute-path guard.
	s := NewSpawner(Config{
		HelperPath: "/nonexistent/byn-exec-helper",
	})
	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	defer stdinR.Close()
	defer stdinW.Close()
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	defer stdoutR.Close()
	defer stdoutW.Close()

	code, err := s.Spawn(SpawnReq{
		Argv:   []string{"id"}, // relative — no leading /
		Env:    []string{},
		Stdin:  int(stdinR.Fd()),
		Stdout: int(stdoutW.Fd()),
		Stderr: int(stdoutW.Fd()),
	})
	require.Error(t, err, "expected an error for relative argv[0]")
	assert.Equal(t, -1, code)
	assert.Contains(t, err.Error(), "not an absolute path")
}

// TestSpawnRejectsEmptyArgv verifies that Spawn returns an error when argv is
// empty. Does not require root.
func TestSpawnRejectsEmptyArgv(t *testing.T) {
	s := NewSpawner(Config{HelperPath: "/nonexistent/byn-exec-helper"})
	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	defer stdinR.Close()
	defer stdinW.Close()

	code, err := s.Spawn(SpawnReq{
		Argv:   []string{},
		Stdin:  int(stdinR.Fd()),
		Stdout: int(stdinR.Fd()),
		Stderr: int(stdinR.Fd()),
	})
	require.Error(t, err)
	assert.Equal(t, -1, code)
}

// TestSpawnRejectsNULInEnv verifies that Spawn returns an error when any env
// entry contains a NUL byte. The NUL check is performed before any dup/pipe/
// spawn, so this test does NOT require root and runs everywhere.
func TestSpawnRejectsNULInEnv(t *testing.T) {
	s := NewSpawner(Config{HelperPath: "/nonexistent/byn-exec-helper"})
	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	defer stdinR.Close()
	defer stdinW.Close()
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	defer stdoutR.Close()
	defer stdoutW.Close()

	code, err := s.Spawn(SpawnReq{
		Argv:   []string{"/bin/true"},
		Env:    []string{"K=a\x00b"},
		Stdin:  int(stdinR.Fd()),
		Stdout: int(stdoutW.Fd()),
		Stderr: int(stdoutW.Fd()),
	})
	require.Error(t, err, "expected an error for NUL byte in env entry")
	assert.Equal(t, -1, code)
	assert.Contains(t, err.Error(), "NUL")
}

// TestSpawnRunsAsExecUser verifies that the child process is spawned as
// the _byn-exec user (ExecUID). Requires root + provisioned + BYN_TEST_HELPER.
func TestSpawnRunsAsExecUser(t *testing.T) {
	helperPath, st := requireRootAndProvisioned(t)

	// stdout pipe: we capture the output of `id -u`.
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	defer stdoutR.Close()
	defer stdoutW.Close()

	// stdin: /dev/null (no input needed).
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer devNull.Close()

	s := NewSpawner(Config{
		HelperPath: helperPath,
		Exec:       st,
	})

	exitCode, err := s.Spawn(SpawnReq{
		Argv:   []string{"/usr/bin/id", "-u"},
		Env:    []string{},
		Stdin:  int(devNull.Fd()),
		Stdout: int(stdoutW.Fd()),
		Stderr: int(stdoutW.Fd()),
	})
	require.NoError(t, err, "Spawn must not return an error for a successful child")

	// Close the write end so the reader sees EOF.
	stdoutW.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, stdoutR)
	require.NoError(t, err)

	assert.Equal(t, 0, exitCode, "id -u should exit 0")

	gotUID := mustAtoiTrim(t, buf.String())
	assert.Equal(t, st.ExecUID, gotUID,
		"child must run as ExecUID %d, got %d", st.ExecUID, gotUID)
}

// TestSpawnPassesEnv verifies that the full env written to fd 3 is visible in
// the child. Requires root + provisioned + BYN_TEST_HELPER.
func TestSpawnPassesEnv(t *testing.T) {
	helperPath, st := requireRootAndProvisioned(t)

	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	defer stdoutR.Close()
	defer stdoutW.Close()

	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer devNull.Close()

	s := NewSpawner(Config{
		HelperPath: helperPath,
		Exec:       st,
	})

	exitCode, err := s.Spawn(SpawnReq{
		Argv:   []string{"/usr/bin/printenv", "FOO"},
		Env:    []string{"FOO=bar", "PATH=/usr/bin:/bin"},
		Stdin:  int(devNull.Fd()),
		Stdout: int(stdoutW.Fd()),
		Stderr: int(stdoutW.Fd()),
	})
	require.NoError(t, err)

	stdoutW.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, stdoutR)
	require.NoError(t, err)

	assert.Equal(t, 0, exitCode, "printenv FOO should exit 0")
	assert.Contains(t, buf.String(), "bar", "child env must contain FOO=bar")
}
