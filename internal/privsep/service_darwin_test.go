//go:build darwin

package privsep

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordRunner returns a runner that records each invocation as "cmd arg arg…".
func recordRunner(into *[]string) runner {
	return func(cmd string, args ...string) error {
		*into = append(*into, strings.TrimSpace(cmd+" "+strings.Join(args, " ")))
		return nil
	}
}

func TestLaunchDaemonPlistContents(t *testing.T) {
	const execPath = "/usr/local/bin/byn"
	plist := launchDaemonPlist(execPath)

	// Service identity: runs as _byn (the privsep boundary), labelled with the
	// shared bundle id.
	assert.Contains(t, plist, "<key>UserName</key>")
	assert.Contains(t, plist, "<string>"+DaemonUser+"</string>")
	assert.Contains(t, plist, "<string>_byn</string>")
	assert.Contains(t, plist, "<key>Label</key>")
	assert.Contains(t, plist, "<string>"+launchDaemonLabel+"</string>")
	assert.Contains(t, plist, "<string>com.sandeepbaynes.byn</string>")

	// ProgramArguments = [<execPath>, daemon, start].
	assert.Contains(t, plist, "<key>ProgramArguments</key>")
	assert.Contains(t, plist, "<string>"+execPath+"</string>")
	assert.Contains(t, plist, "<string>daemon</string>")
	assert.Contains(t, plist, "<string>start</string>")

	// Auto-start at boot + restart on crash.
	assert.Contains(t, plist, "<key>RunAtLoad</key>")
	assert.Contains(t, plist, "<key>KeepAlive</key>")

	// State lives under the fixed system data dir.
	assert.Contains(t, plist, paths.SystemDataDir())

	// Valid plist XML preamble.
	assert.True(t, strings.HasPrefix(plist, `<?xml version="1.0" encoding="UTF-8"?>`),
		"plist must start with the XML declaration")
	assert.Contains(t, plist, `<!DOCTYPE plist PUBLIC`)
}

func TestLaunchDaemonPlistUsesAbsoluteExecPath(t *testing.T) {
	plist := launchDaemonPlist("/opt/byn/bin/byn")
	assert.Contains(t, plist, "<string>/opt/byn/bin/byn</string>")
	// The default-install path must not leak when a different path is supplied.
	assert.NotContains(t, plist, "<string>/usr/local/bin/byn</string>")
}

// TestLaunchDaemonPlistLintsClean writes the generated plist to a temp file and
// shells out to plutil -lint (always present on macOS). This guards against XML
// typos the string assertions cannot catch, and asserts launchd-meaningful keys
// survive the parse (UserName, Label, ProgramArguments, RunAtLoad).
func TestLaunchDaemonPlistLintsClean(t *testing.T) {
	plutil, err := exec.LookPath("plutil")
	require.NoError(t, err, "plutil must be available on macOS")

	dir := t.TempDir()
	plistPath := dir + "/" + launchDaemonLabel + ".plist"
	require.NoError(t, os.WriteFile(plistPath, []byte(launchDaemonPlist("/usr/local/bin/byn")), 0o644))

	out, lerr := exec.Command(plutil, "-lint", plistPath).CombinedOutput() //nolint:gosec // fixed args, test-only
	require.NoError(t, lerr, "plutil -lint failed:\n%s", out)
	assert.Contains(t, string(out), "OK", "plutil -lint should report OK:\n%s", out)

	// Cross-check the parsed values via `plutil -extract` so we know the keys are
	// not just present as text but structurally valid.
	for _, kv := range []struct{ key, want string }{
		{"UserName", DaemonUser},
		{"Label", launchDaemonLabel},
		{"RunAtLoad", "true"},
	} {
		got, eerr := exec.Command(plutil, "-extract", kv.key, "raw", "-o", "-", plistPath).CombinedOutput() //nolint:gosec // fixed args, test-only
		require.NoError(t, eerr, "extract %s failed:\n%s", kv.key, got)
		assert.Equal(t, kv.want, strings.TrimSpace(string(got)), "plist key %s", kv.key)
	}
	// ProgramArguments first element is the exec path.
	args0, eerr := exec.Command(plutil, "-extract", "ProgramArguments.0", "raw", "-o", "-", plistPath).CombinedOutput() //nolint:gosec // fixed args, test-only
	require.NoError(t, eerr, "extract ProgramArguments.0 failed:\n%s", args0)
	assert.Equal(t, "/usr/local/bin/byn", strings.TrimSpace(string(args0)))
	args1, eerr := exec.Command(plutil, "-extract", "ProgramArguments.1", "raw", "-o", "-", plistPath).CombinedOutput() //nolint:gosec // fixed args, test-only
	require.NoError(t, eerr, "extract ProgramArguments.1 failed:\n%s", args1)
	assert.Equal(t, "daemon", strings.TrimSpace(string(args1)))
}

func TestHideServiceAccountsSequence(t *testing.T) {
	var ran []string
	require.NoError(t, hideServiceAccounts(recordRunner(&ran)))

	require.Len(t, ran, 2)
	assert.Equal(t, "dscl . -create /Users/"+DaemonUser+" IsHidden 1", ran[0])
	assert.Equal(t, "dscl . -create /Users/"+ExecUser+" IsHidden 1", ran[1])
}

func TestHideServiceAccountsErrorPaths(t *testing.T) {
	sentinel := errors.New("boom")
	for failAt := 0; failAt < 2; failAt++ {
		failAt := failAt
		t.Run("fail_at_"+string(rune('0'+failAt)), func(t *testing.T) {
			call := 0
			err := hideServiceAccounts(func(string, ...string) error {
				defer func() { call++ }()
				if call == failAt {
					return sentinel
				}
				return nil
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, sentinel)
		})
	}
}

func TestInstallServiceSequence(t *testing.T) {
	var ran []string
	require.NoError(t, InstallService(recordRunner(&ran), "/usr/local/bin/byn"))

	// provisionUsers (users absent in CI/dev) creates both accounts → 2
	// sysadminctl calls; then 2 dscl IsHidden; then the plist write; then
	// bootstrap. When the accounts already exist provisionUsers is a no-op, so
	// assert by content rather than a fixed length.
	require.NotEmpty(t, ran)

	joined := strings.Join(ran, "\n")
	// The plist is written root:wheel 0644 to the canonical path with the exec
	// path baked in.
	assert.Contains(t, joined, launchDaemonPlistPath)
	assert.Contains(t, joined, "chown root:wheel")
	assert.Contains(t, joined, "chmod 0644")
	assert.Contains(t, joined, "/usr/local/bin/byn")
	// The IsHidden step ran for both accounts.
	assert.Contains(t, joined, "dscl . -create /Users/"+DaemonUser+" IsHidden 1")
	assert.Contains(t, joined, "dscl . -create /Users/"+ExecUser+" IsHidden 1")

	// bootstrap is the LAST call and loads the system domain from the plist.
	assert.Equal(t, "launchctl bootstrap system "+launchDaemonPlistPath, ran[len(ran)-1])

	// Ordering: every dscl/plist-write precedes the bootstrap.
	bootstrapIdx := len(ran) - 1
	for i, c := range ran {
		if strings.HasPrefix(c, "launchctl bootstrap") {
			assert.Equal(t, bootstrapIdx, i, "bootstrap must be the final step")
		}
	}
}

func TestInstallServiceErrorPaths(t *testing.T) {
	sentinel := errors.New("boom")
	// Worst case (accounts absent) is 6 side-effecting calls: 2 sysadminctl,
	// 2 dscl, 1 plist write, 1 bootstrap. Fail at each and require the error
	// propagates.
	for failAt := 0; failAt < 6; failAt++ {
		failAt := failAt
		t.Run("fail_at_"+string(rune('0'+failAt)), func(t *testing.T) {
			call := 0
			err := InstallService(func(string, ...string) error {
				defer func() { call++ }()
				if call == failAt {
					return sentinel
				}
				return nil
			}, "/usr/local/bin/byn")
			require.Error(t, err)
			assert.ErrorIs(t, err, sentinel)
		})
	}
}

func TestUninstallServiceSequence(t *testing.T) {
	var ran []string
	require.NoError(t, UninstallService(recordRunner(&ran)))

	require.Len(t, ran, 2)
	assert.Equal(t, "launchctl bootout system "+launchDaemonPlistPath, ran[0])
	assert.Equal(t, "rm -f "+launchDaemonPlistPath, ran[1])

	// Uninstall must NOT touch accounts or state (that is a --purge concern).
	for _, c := range ran {
		assert.NotContains(t, c, "sysadminctl")
		assert.NotContains(t, c, "dscl")
		assert.NotContains(t, c, paths.SystemDataDir())
	}
}

func TestUninstallServiceErrorPaths(t *testing.T) {
	sentinel := errors.New("boom")
	for failAt := 0; failAt < 2; failAt++ {
		failAt := failAt
		t.Run("fail_at_"+string(rune('0'+failAt)), func(t *testing.T) {
			call := 0
			err := UninstallService(func(string, ...string) error {
				defer func() { call++ }()
				if call == failAt {
					return sentinel
				}
				return nil
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, sentinel)
		})
	}
}
