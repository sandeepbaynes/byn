//go:build linux

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

func TestSystemdUnitContents(t *testing.T) {
	const execPath = "/usr/local/bin/byn"
	unit := systemdUnit(execPath)

	// Core service identity + entry point.
	assert.Contains(t, unit, "User="+DaemonUser)
	assert.Contains(t, unit, "User=_byn")
	assert.Contains(t, unit, "ExecStart="+execPath+" daemon start")
	assert.Contains(t, unit, "StateDirectory=byn")
	assert.Contains(t, unit, "Restart=on-failure")

	// The load-bearing NoNewPrivileges gotcha. Anchor the active directive with
	// newlines — the explanatory comment legitimately contains the string
	// "NoNewPrivileges=yes" while documenting why the directive must stay off, so a
	// bare substring check would falsely trip on the comment.
	assert.Contains(t, unit, "\nNoNewPrivileges=no\n")
	assert.NotContains(t, unit, "\nNoNewPrivileges=yes\n")
	// And it must explain WHY (the cap_setuid strip), not just set it.
	assert.Contains(t, unit, "cap_setuid",
		"unit must document why NoNewPrivileges stays off")
	assert.Contains(t, unit, ExecUser,
		"unit comment should reference the exec service user")

	// Hardening directives (spec §5).
	for _, want := range []string{
		"ProtectSystem=strict",
		"ProtectProc=invisible",
		"ProcSubset=pid",
		"RestrictAddressFamilies=AF_UNIX",
		"SystemCallFilter=@system-service",
		"MemoryDenyWriteExecute=yes",
		"RuntimeDirectory=byn",
	} {
		assert.Contains(t, unit, want, "missing hardening directive %q", want)
	}

	// ReadWritePaths must cover both the state dir and the runtime socket dir.
	assert.Contains(t, unit, "ReadWritePaths="+paths.SystemDataDir()+" /run/byn")

	// [Install] section so `systemctl enable` has a target.
	assert.Contains(t, unit, "[Install]")
	assert.Contains(t, unit, "WantedBy=multi-user.target")
}

func TestSystemdUnitUsesAbsoluteExecPath(t *testing.T) {
	unit := systemdUnit("/opt/byn/bin/byn")
	assert.Contains(t, unit, "ExecStart=/opt/byn/bin/byn daemon start")
	// A relative ExecStart is invalid for systemd; ensure we passed through the
	// caller's absolute path verbatim.
	assert.NotContains(t, unit, "ExecStart=byn ")
}

func TestApplySysusersSequence(t *testing.T) {
	var ran []string
	require.NoError(t, applySysusers(recordRunner(&ran)))
	require.Len(t, ran, 2)
	// First writes the canonical conf path; second invokes systemd-sysusers on it.
	assert.Contains(t, ran[0], sysusersConfPath)
	assert.True(t, strings.HasPrefix(ran[1], "systemd-sysusers "+sysusersConfPath),
		"want systemd-sysusers applied to %s, got %q", sysusersConfPath, ran[1])
}

func TestApplySysusersErrorPaths(t *testing.T) {
	sentinel := errors.New("boom")
	for failAt := 0; failAt < 2; failAt++ {
		failAt := failAt
		t.Run([]string{"write conf", "systemd-sysusers"}[failAt], func(t *testing.T) {
			call := 0
			err := applySysusers(func(string, ...string) error {
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

	require.Len(t, ran, 5)
	// 1+2: sysusers.d write then systemd-sysusers.
	assert.Contains(t, ran[0], sysusersConfPath)
	assert.True(t, strings.HasPrefix(ran[1], "systemd-sysusers"))
	// 3: unit write to the canonical unit path with the exec path baked in.
	assert.Contains(t, ran[2], systemUnitPath)
	assert.Contains(t, ran[2], "/usr/local/bin/byn daemon start")
	// 4: daemon-reload before enable.
	assert.Equal(t, "systemctl daemon-reload", ran[3])
	// 5: enable --now.
	assert.Equal(t, "systemctl enable --now byn.service", ran[4])
}

func TestInstallServiceErrorPaths(t *testing.T) {
	sentinel := errors.New("boom")
	// 5 side-effecting calls: write conf, systemd-sysusers, write unit,
	// daemon-reload, enable.
	for failAt := 0; failAt < 5; failAt++ {
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

	require.Len(t, ran, 3)
	assert.Equal(t, "systemctl disable --now byn.service", ran[0])
	assert.Equal(t, "rm -f "+systemUnitPath, ran[1])
	assert.Equal(t, "systemctl daemon-reload", ran[2])

	// Uninstall must NOT touch sysusers/users/state (that is a --purge concern).
	for _, c := range ran {
		assert.NotContains(t, c, "systemd-sysusers")
		assert.NotContains(t, c, sysusersConfPath)
		assert.NotContains(t, c, paths.SystemDataDir())
	}
}

func TestUninstallServiceErrorPaths(t *testing.T) {
	sentinel := errors.New("boom")
	for failAt := 0; failAt < 3; failAt++ {
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

// TestSystemdUnitValidatesWithAnalyze does a real systemd-analyze verify on the
// generated unit when systemd is present. It needs no root (analyze verify reads
// a unit file), but skips cleanly where systemd-analyze is unavailable (CI
// containers, macOS dev). This guards against directive typos the string
// assertions cannot catch.
func TestSystemdUnitValidatesWithAnalyze(t *testing.T) {
	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not available; skipping real unit validation")
	}

	dir := t.TempDir()
	unitPath := dir + "/byn.service"
	require.NoError(t, os.WriteFile(unitPath, []byte(systemdUnit("/usr/local/bin/byn")), 0o644))

	out, verr := exec.Command(analyze, "verify", unitPath).CombinedOutput() //nolint:gosec // fixed args, test-only
	// `verify` warns about a not-yet-installed unit's dependencies; we only fail
	// on hard parse errors. Treat a clean exit OR pure-warning output as a pass.
	if verr != nil && strings.Contains(string(out), "Failed") &&
		!strings.Contains(string(out), "Failed to load environment files") {
		// Allow benign "directory ... does not exist" warnings (ReadWritePaths
		// points at /var/lib/byn which is absent in the test sandbox).
		filtered := stripBenignAnalyzeWarnings(string(out))
		if strings.TrimSpace(filtered) != "" {
			t.Fatalf("systemd-analyze verify reported errors:\n%s", out)
		}
	}
}

// stripBenignAnalyzeWarnings drops lines that are expected when verifying an
// uninstalled unit on a host without /var/lib/byn provisioned.
func stripBenignAnalyzeWarnings(s string) string {
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if strings.Contains(l, "does not exist") ||
			strings.Contains(l, "Unit configured to use KillMode=none") ||
			strings.Contains(l, "ReadWritePaths") {
			continue
		}
		kept = append(kept, l)
	}
	return strings.Join(kept, "\n")
}
