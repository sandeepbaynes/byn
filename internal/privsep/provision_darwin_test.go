//go:build darwin

package privsep

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	// On darwin both users are created via sysadminctl.
	for _, c := range ran {
		assert.Equal(t, "sysadminctl", c)
	}
}

func TestInstallHelperWritesConfig(t *testing.T) {
	var cmds []string
	err := installHelper(func(cmd string, args ...string) error {
		cmds = append(cmds, cmd)
		return nil
	}, "/src/byn-exec-helper", helperDestPathDarwin,
		helperConfigPathDarwin, 411, 411)
	assert.NoError(t, err)
	// Should call: install (binary), install (state dir), sh (config write)
	assert.GreaterOrEqual(t, len(cmds), 3)
	assert.Equal(t, "install", cmds[0], "first command must install the binary with 4755")
	assert.Equal(t, "install", cmds[1], "second command must create the support dir")
	assert.Equal(t, "sh", cmds[2], "third command must write the config via sh")
}

func TestInstallHelperErrorPaths(t *testing.T) {
	sentinel := errors.New("injected error")

	type step struct {
		name       string
		failAtCall int // zero-based index of the call to fail
	}
	steps := []step{
		{"install binary", 0},
		{"create state dir", 1},
		{"write config", 2},
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
			}, "/src/byn-exec-helper", helperDestPathDarwin,
				helperConfigPathDarwin, 411, 411)
			require.Error(t, err)
			assert.ErrorIs(t, err, sentinel)
		})
	}
}

func TestHelperConfigPath_Darwin(t *testing.T) {
	got := HelperConfigPath()
	assert.Equal(t, "/Library/Application Support/byn/exec-helper.conf", got)
}
