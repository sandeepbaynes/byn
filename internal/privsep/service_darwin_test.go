//go:build darwin

package privsep

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShSingleQuote(t *testing.T) {
	assert.Equal(t, `'abc'`, shSingleQuote("abc"))
	assert.Equal(t, `'a'\''b'`, shSingleQuote("a'b"))

	// Round-trips through `sh -c`: printf '%s' <quoted> echoes the original
	// byte-for-byte, including newlines and double-quotes.
	in := "line1\nline2 with \"quotes\" and 'apostrophe'"
	out, err := exec.Command("sh", "-c", "printf '%s' "+shSingleQuote(in)).CombinedOutput()
	require.NoError(t, err)
	assert.Equal(t, in, string(out))
}

func TestLaunchDaemonWriteCmdSingleQuotesContent(t *testing.T) {
	cmd := launchDaemonWriteCmd(launchDaemonPlist("/usr/local/bin/byn"), launchDaemonPlistPath)
	// Content is single-quoted (printf '%s' '...'), NOT %q double-quoted.
	assert.Contains(t, cmd, "printf '%s' '<?xml")
	assert.Contains(t, cmd, "chown root:wheel")
	assert.Contains(t, cmd, "chmod 0644")
	assert.Contains(t, cmd, launchDaemonPlistPath)
}

// TestLaunchDaemonPlistWriteProducesValidPlist executes the actual write step and
// lints the file — the coverage that was missing and let the %q quoting bug ship
// (the written plist had literal \n escapes and launchd rejected it).
func TestLaunchDaemonPlistWriteProducesValidPlist(t *testing.T) {
	if _, err := exec.LookPath("plutil"); err != nil {
		t.Skip("plutil not available")
	}
	path := filepath.Join(t.TempDir(), "com.test.byn.plist")
	plist := launchDaemonPlist("/usr/local/bin/byn")

	// The production write minus the root-only chown/chmod: printf '%s' <plist> > <path>.
	writeCmd := "printf '%s' " + shSingleQuote(plist) + " > " + shSingleQuote(path)
	if out, err := exec.Command("sh", "-c", writeCmd).CombinedOutput(); err != nil {
		t.Fatalf("write: %v: %s", err, out)
	}

	if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint rejected the written plist: %v\n%s", err, out)
	}
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `\n`, "written plist has literal backslash-n (the quoting bug)")
	assert.Contains(t, string(data), "<key>UserName</key>")
	assert.Contains(t, string(data), "<string>_byn</string>")
}

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

	// ProgramArguments = [<execPath>, daemon, start, --foreground]. --foreground is
	// load-bearing: launchd supervises the process, so the daemon must not detach.
	assert.Contains(t, plist, "<key>ProgramArguments</key>")
	assert.Contains(t, plist, "<string>"+execPath+"</string>")
	assert.Contains(t, plist, "<string>daemon</string>")
	assert.Contains(t, plist, "<string>start</string>")
	assert.Contains(t, plist, "<string>--foreground</string>")

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

	// provisionUsers (users absent in CI/dev) creates both accounts via dscl;
	// then hideServiceAccounts re-asserts IsHidden; then the plist write; then
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

	// Idempotent re-run: a best-effort bootout precedes the bootstrap so a second
	// setup does not fail with "service already loaded".
	bootoutIdx := -1
	for i, c := range ran {
		if c == "launchctl bootout system/"+launchDaemonLabel {
			bootoutIdx = i
		}
	}
	require.GreaterOrEqual(t, bootoutIdx, 0, "expected a launchctl bootout before bootstrap")
	assert.Less(t, bootoutIdx, bootstrapIdx, "bootout must run before bootstrap")
}

func TestInstallServiceErrorPaths(t *testing.T) {
	sentinel := errors.New("boom")
	// provisionUsers now issues a variable number of dscl steps, so fail by
	// matching the command rather than a brittle call index. This keeps coverage
	// of each meaningful boundary: account provisioning, the plist write, and the
	// launchctl bootstrap.
	cases := []struct {
		name  string
		match func(cmd string, args []string) bool
	}{
		{"provision account (dscl)", func(cmd string, _ []string) bool { return cmd == "dscl" }},
		{"write plist (sh)", func(cmd string, _ []string) bool { return cmd == "sh" }},
		{"bootstrap (launchctl)", func(cmd string, args []string) bool {
			return cmd == "launchctl" && len(args) > 0 && args[0] == "bootstrap"
		}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			err := InstallService(func(cmd string, args ...string) error {
				if c.match(cmd, args) {
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
