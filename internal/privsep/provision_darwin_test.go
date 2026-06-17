//go:build darwin

package privsep

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// provisionFake records the dscl commands provisionUsers issues and answers
// lookups from a fixed set of pre-existing accounts.
type provisionFake struct {
	present map[string]bool
	calls   [][]string
}

func newProvisionFake(present ...string) *provisionFake {
	f := &provisionFake{present: map[string]bool{}}
	for _, n := range present {
		f.present[n] = true
	}
	return f
}

func (f *provisionFake) lookup(name string) (int, int, error) {
	if f.present[name] {
		return 411, 411, nil
	}
	return 0, 0, errUserNotFound
}

func (f *provisionFake) run(cmd string, args ...string) error {
	f.calls = append(f.calls, append([]string{cmd}, args...))
	return nil
}

// uniqueIDs extracts the UniqueID assigned to each /Users/<name> account from a
// recorded dscl command stream.
func uniqueIDs(t *testing.T, calls [][]string) map[string]int {
	t.Helper()
	ids := map[string]int{}
	for _, c := range calls {
		if len(c) == 6 && c[0] == "dscl" && c[2] == "-create" &&
			c[4] == "UniqueID" && strings.HasPrefix(c[3], "/Users/") {
			n, err := strconv.Atoi(c[5])
			require.NoError(t, err)
			ids[strings.TrimPrefix(c[3], "/Users/")] = n
		}
	}
	return ids
}

func hasUserAttr(calls [][]string, name, attr, val string) bool {
	path := "/Users/" + name
	for _, c := range calls {
		if len(c) == 6 && c[0] == "dscl" && c[1] == "." && c[2] == "-create" &&
			c[3] == path && c[4] == attr && c[5] == val {
			return true
		}
	}
	return false
}

func TestProvisionIsNoOpWhenPresent(t *testing.T) {
	f := newProvisionFake(DaemonUser, ExecUser)
	done, err := provisionUsers(f.lookup, func(cmd string, _ ...string) error {
		t.Fatalf("should not run %q when users present", cmd)
		return nil
	}, func(int) bool { return false })
	assert.NoError(t, err)
	assert.True(t, done.AlreadyProvisioned)
}

func TestProvisionCreatesBothAccountsViaDscl(t *testing.T) {
	f := newProvisionFake()
	_, err := provisionUsers(f.lookup, f.run, func(int) bool { return false })
	require.NoError(t, err)
	require.NotEmpty(t, f.calls)

	for _, c := range f.calls {
		assert.Equal(t, "dscl", c[0], "all provisioning goes through dscl, not sysadminctl")
	}

	ids := uniqueIDs(t, f.calls)
	require.Contains(t, ids, DaemonUser)
	require.Contains(t, ids, ExecUser)
	for name, id := range ids {
		assert.GreaterOrEqualf(t, id, darwinServiceIDMin, "%s uid below band", name)
		assert.LessOrEqualf(t, id, darwinServiceIDMax, "%s uid above band", name)
	}
	assert.NotEqual(t, ids[DaemonUser], ids[ExecUser], "accounts must get distinct ids")

	// Hardening attributes set on each account.
	for _, u := range []string{DaemonUser, ExecUser} {
		assert.Truef(t, hasUserAttr(f.calls, u, "UserShell", "/usr/bin/false"), "%s shell", u)
		assert.Truef(t, hasUserAttr(f.calls, u, "NFSHomeDirectory", "/var/empty"), "%s home", u)
		assert.Truef(t, hasUserAttr(f.calls, u, "Password", "*"), "%s password disabled", u)
		assert.Truef(t, hasUserAttr(f.calls, u, "IsHidden", "1"), "%s hidden", u)
	}
}

func TestProvisionCreatesOnlyMissingAccount(t *testing.T) {
	// _byn already exists; only _byn-exec should be created.
	f := newProvisionFake(DaemonUser)
	_, err := provisionUsers(f.lookup, f.run, func(int) bool { return false })
	require.NoError(t, err)
	ids := uniqueIDs(t, f.calls)
	assert.NotContains(t, ids, DaemonUser, "existing account must not be recreated")
	assert.Contains(t, ids, ExecUser)
}

func TestProvisionAllocatesDistinctFreeIDs(t *testing.T) {
	f := newProvisionFake()
	// 450 and 451 already taken in the OS directory.
	_, err := provisionUsers(f.lookup, f.run, func(id int) bool { return id == 450 || id == 451 })
	require.NoError(t, err)
	ids := uniqueIDs(t, f.calls)
	for name, id := range ids {
		assert.NotEqualf(t, 450, id, "%s got a taken id", name)
		assert.NotEqualf(t, 451, id, "%s got a taken id", name)
	}
	assert.NotEqual(t, ids[DaemonUser], ids[ExecUser])
}

func TestProvisionPropagatesRunError(t *testing.T) {
	sentinel := errors.New("dscl boom")
	f := newProvisionFake()
	_, err := provisionUsers(f.lookup, func(string, ...string) error { return sentinel },
		func(int) bool { return false })
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
	assert.Contains(t, err.Error(), "create "+DaemonUser)
}

func TestProvisionErrorsWhenBandExhausted(t *testing.T) {
	f := newProvisionFake()
	_, err := provisionUsers(f.lookup, f.run, func(int) bool { return true }) // every id taken
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no free service account id")
}

func TestChooseFreeID(t *testing.T) {
	none := func(int) bool { return false }

	id, err := chooseFreeID(450, 499, none, map[int]bool{})
	require.NoError(t, err)
	assert.Equal(t, 450, id)

	// 450 taken in the OS, 451 already allocated this run → 452.
	id, err = chooseFreeID(450, 499, func(i int) bool { return i == 450 }, map[int]bool{451: true})
	require.NoError(t, err)
	assert.Equal(t, 452, id)

	_, err = chooseFreeID(450, 451, func(int) bool { return true }, map[int]bool{})
	require.Error(t, err)
}

func TestInstallHelperWritesConfig(t *testing.T) {
	var cmds []string
	err := installHelper(func(cmd string, args ...string) error {
		cmds = append(cmds, cmd)
		return nil
	}, "/src/byn-exec-helper", helperDestPathDarwin,
		helperConfigPathDarwin, 411, 411)
	assert.NoError(t, err)
	// Should call: install -d (helper dir), install (binary 4755), sh (config).
	// The data dir is NOT created here — that is ensureDataDir's job (it needs the
	// _byn uid/gid, which installHelper does not have).
	assert.GreaterOrEqual(t, len(cmds), 3)
	assert.Equal(t, "install", cmds[0], "first command must create the helper's parent dir")
	assert.Equal(t, "install", cmds[1], "second command must install the binary with 4755")
	assert.Equal(t, "sh", cmds[2], "third command must write the config via sh")
}

func TestEnsureDataDirIsBynOwned0711(t *testing.T) {
	var got []string
	err := ensureDataDir(func(cmd string, args ...string) error {
		got = append([]string{cmd}, args...)
		return nil
	}, 450, 451)
	require.NoError(t, err)
	require.Equal(t, "install", got[0])
	assert.Contains(t, got, "-d")
	// 0711: owner can traverse to the in-dir socket but cannot read/list the vault.
	assert.Contains(t, got, "0711", "data dir must be 0711 so the owner can reach the socket")
	assert.NotContains(t, got, "0700", "0700 would block the owner from traversing to the socket")
	assert.Contains(t, got, "450", "owner must be the _byn uid")
	assert.Contains(t, got, "451", "group must be the _byn gid")
	assert.Equal(t, systemDataDirDarwin, got[len(got)-1], "target is the system data dir")
}

func TestEnsureDataDirPropagatesError(t *testing.T) {
	sentinel := errors.New("install boom")
	err := ensureDataDir(func(string, ...string) error { return sentinel }, 450, 450)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
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
	assert.Equal(t, "/usr/local/libexec/byn-exec-helper.conf", got)
}
