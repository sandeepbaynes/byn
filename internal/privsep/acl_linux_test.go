//go:build linux

package privsep

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestACLGrantCommands_Linux asserts the three expected setfacl invocations:
// recursive rwX on the project, a default (-d) rwX ACL on the project, and an
// execute-only (search) ACL on the home.
func TestACLGrantCommands_Linux(t *testing.T) {
	cmds := aclGrantCommands("/home/o/proj", "/home/o", "_byn-exec")
	require.Len(t, cmds, 3)

	assert.Equal(t,
		[]string{"setfacl", "-R", "-m", "u:_byn-exec:rwX", "/home/o/proj"},
		cmds[0], "recursive rwX on project")
	assert.Equal(t,
		[]string{"setfacl", "-R", "-d", "-m", "u:_byn-exec:rwX", "/home/o/proj"},
		cmds[1], "default rwX ACL on project")
	assert.Equal(t,
		[]string{"setfacl", "-m", "u:_byn-exec:x", "/home/o"},
		cmds[2], "execute-only on home (traverse, not list)")
}

// TestACLGrantCommands_Linux_HomeEqualsProject drops the home command when home
// == project (no separate traversal grant needed).
func TestACLGrantCommands_Linux_HomeEqualsProject(t *testing.T) {
	cmds := aclGrantCommands("/srv/p", "/srv/p", "_byn-exec")
	require.Len(t, cmds, 2)
	for _, c := range cmds {
		assert.Equal(t, "/srv/p", c[len(c)-1])
	}
}

// TestACLGrantCommands_Linux_EmptyHome drops the home command when home is "".
func TestACLGrantCommands_Linux_EmptyHome(t *testing.T) {
	cmds := aclGrantCommands("/srv/p", "", "_byn-exec")
	require.Len(t, cmds, 2)
}

// TestACLRevokeCommands_Linux asserts the two removals mirror the grant: -x on
// the project (recursive, which also clears the default entry) and -x on home.
func TestACLRevokeCommands_Linux(t *testing.T) {
	cmds := aclRevokeCommands("/home/o/proj", "/home/o", "_byn-exec")
	require.Len(t, cmds, 2)
	assert.Equal(t,
		[]string{"setfacl", "-R", "-x", "u:_byn-exec", "/home/o/proj"},
		cmds[0])
	assert.Equal(t,
		[]string{"setfacl", "-x", "u:_byn-exec", "/home/o"},
		cmds[1])
}

// TestACLRevokeCommands_Linux_HomeEqualsProject drops the home command.
func TestACLRevokeCommands_Linux_HomeEqualsProject(t *testing.T) {
	cmds := aclRevokeCommands("/srv/p", "/srv/p", "_byn-exec")
	require.Len(t, cmds, 1)
}

// TestGrantProjectACL_Linux_RunsAllAndUsesExecUser verifies the exported entry
// iterates every command and passes ExecUser, not an arbitrary string.
func TestGrantProjectACL_Linux_RunsAllAndUsesExecUser(t *testing.T) {
	var ran [][]string
	err := GrantProjectACL(func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}, "/home/o/proj", "/home/o")
	require.NoError(t, err)
	require.Len(t, ran, 3)
	for _, c := range ran {
		assert.Contains(t, c, "setfacl")
	}
	// rwX ACE names the service user.
	assert.Contains(t, ran[0], "u:_byn-exec:rwX")
}

// TestGrantProjectACL_Linux_StopsAtFirstError confirms best-effort short-circuit
// returns the first error.
func TestGrantProjectACL_Linux_StopsAtFirstError(t *testing.T) {
	sentinel := errors.New("boom")
	calls := 0
	err := GrantProjectACL(func(name string, args ...string) error {
		calls++
		return sentinel
	}, "/p", "/h")
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, calls, "should stop at the first failing command")
}

// TestRevokeProjectACL_Linux_RunsAll verifies the revoke entry iterates all.
func TestRevokeProjectACL_Linux_RunsAll(t *testing.T) {
	var ran [][]string
	err := RevokeProjectACL(func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}, "/home/o/proj", "/home/o")
	require.NoError(t, err)
	require.Len(t, ran, 2)
	assert.Contains(t, ran[0], "u:_byn-exec")
}

// TestRevokeProjectACL_Linux_StopsAtFirstError mirrors the grant short-circuit.
func TestRevokeProjectACL_Linux_StopsAtFirstError(t *testing.T) {
	sentinel := errors.New("boom")
	calls := 0
	err := RevokeProjectACL(func(name string, args ...string) error {
		calls++
		return sentinel
	}, "/p", "/h")
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, calls)
}
