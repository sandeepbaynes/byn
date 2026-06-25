//go:build linux

package privsep

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxCreateUserCommands(t *testing.T) {
	conf := sysusersConf()
	// sysusersConf is column-aligned, so the user names are followed by
	// padding whitespace — match the name-as-a-field, not a single space.
	assert.Contains(t, conf, "_byn ")
	assert.Contains(t, conf, "_byn-exec ")
	assert.Contains(t, conf, "/usr/sbin/nologin")
}

func TestProvisionIsNoOpWhenPresent(t *testing.T) {
	done, err := provisionUsers(func(name string) (int, int, error) {
		return 411, 411, nil // both present
	}, func(cmd string, args ...string) error {
		t.Fatalf("should not run %q when users present", cmd)
		return nil
	})
	assert.NoError(t, err)
	assert.True(t, done.AlreadyProvisioned)
}

func TestProvisionRunsCommandWhenUsersAbsent(t *testing.T) {
	var ran []string
	_, err := provisionUsers(func(name string) (int, int, error) {
		return 0, 0, errUserNotFound
	}, func(cmd string, args ...string) error {
		ran = append(ran, cmd)
		return nil
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, ran, "should have run at least one command to create users")
}

func TestHelperConfigPath_Linux(t *testing.T) {
	got := HelperConfigPath()
	assert.Equal(t, "/usr/local/libexec/byn-exec-helper.conf", got)
}

func TestInstallHelperWritesConfig(t *testing.T) {
	var cmds []string
	err := installHelper(func(cmd string, args ...string) error {
		cmds = append(cmds, cmd)
		return nil
	}, "/src/byn-exec-helper", "/usr/local/libexec/byn-exec-helper",
		"/usr/local/libexec/byn-exec-helper.conf", 411, 411)
	assert.NoError(t, err)
	// Should call: install -d (helper dir), install (binary), setcap, chcon
	// (SELinux — best-effort, error ignored), install -d (state dir), sh (config).
	assert.GreaterOrEqual(t, len(cmds), 6)
	assert.Equal(t, "install", cmds[0], "first must create the helper's parent dir")
	assert.Equal(t, "install", cmds[1], "second must install the helper binary")
	assert.Equal(t, "setcap", cmds[2], "third must set file caps")
	assert.Equal(t, "chcon", cmds[3], "fourth must set SELinux context (best-effort)")
	assert.Equal(t, "install", cmds[4], "fifth must create the state dir")
	assert.Equal(t, "sh", cmds[5], "sixth must write the config")
}

func TestInstallHelperErrorPaths(t *testing.T) {
	sentinel := errors.New("injected error")

	type step struct {
		name       string
		failAtCall int // zero-based index of the call to fail
	}
	steps := []step{
		{"create helper dir", 0},
		{"install binary", 1},
		{"setcap", 2},
		// call 3 is chcon (SELinux, best-effort) — failing it is a no-op, skip
		{"create state dir", 4},
		{"write config", 5},
	}
	for _, s := range steps {
		s := s
		t.Run(s.name, func(t *testing.T) {
			call := 0
			err := installHelper(func(cmd string, args ...string) error {
				defer func() { call++ }()
				if call == s.failAtCall {
					return sentinel
				}
				return nil
			}, "/src/byn-exec-helper", "/usr/local/libexec/byn-exec-helper",
				"/usr/local/libexec/byn-exec-helper.conf", 411, 411)
			require.Error(t, err)
			assert.ErrorIs(t, err, sentinel)
		})
	}
}
