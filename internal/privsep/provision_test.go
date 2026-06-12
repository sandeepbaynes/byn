//go:build linux

package privsep

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinuxCreateUserCommands(t *testing.T) {
	conf := sysusersConf()
	assert.Contains(t, conf, "u _byn ")
	assert.Contains(t, conf, "u _byn-exec ")
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
	assert.Equal(t, "/var/lib/byn/exec-helper.conf", got)
}

func TestInstallHelperWritesConfig(t *testing.T) {
	var cmds []string
	err := installHelper(func(cmd string, args ...string) error {
		cmds = append(cmds, cmd)
		return nil
	}, "/src/byn-exec-helper", "/usr/local/libexec/byn-exec-helper",
		"/var/lib/byn/exec-helper.conf", 411, 411)
	assert.NoError(t, err)
	// Should call install, setcap, install (state dir), sh (config write)
	assert.GreaterOrEqual(t, len(cmds), 3)
}
