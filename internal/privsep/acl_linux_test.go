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
		[]string{"setfacl", "-m", "u:_byn-exec:rwX", "/home/o/proj"},
		cmds[0], "recursive rwX on project")
	assert.Equal(t,
		[]string{"setfacl", "-d", "-m", "u:_byn-exec:rwX", "/home/o/proj"},
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

// TestACLRevokeCommands_Linux asserts two removals: -x on the project access ACL
// (recursive) and -x on the project default ACL (recursive). It LEAVES ancestor
// traversal entries — shared by sibling projects under the same home/Documents.
func TestACLRevokeCommands_Linux(t *testing.T) {
	cmds := aclRevokeCommands("/home/o/proj", "/home/o", "_byn-exec")
	require.Len(t, cmds, 2, "revoke must leave shared ancestor traversals")
	assert.Equal(t,
		[]string{"setfacl", "-x", "u:_byn-exec", "/home/o/proj"},
		cmds[0], "remove access ACL on project")
	assert.Equal(t,
		[]string{"setfacl", "-x", "d:u:_byn-exec", "/home/o/proj"},
		cmds[1], "remove default ACL on project")
	for _, c := range cmds {
		assert.NotEqual(t, "/home/o", c[len(c)-1], "home traversal must not be revoked")
	}
}

// TestACLGrantCommands_Linux_DeepPath grants the exec child a traverse entry on
// every intermediate dir up to home — the real-world 0700 ~/Documents case.
func TestACLGrantCommands_Linux_DeepPath(t *testing.T) {
	cmds := aclGrantCommands("/home/o/Documents/proj", "/home/o", "_byn-exec")
	// recursive access + default ACL + traverse on [/home/o/Documents, /home/o]
	require.Len(t, cmds, 4)
	targets := map[string]bool{}
	for _, c := range cmds[2:] {
		targets[c[len(c)-1]] = true
		assert.Equal(t, "u:_byn-exec:x", c[2], "ancestor entry must grant traverse only")
	}
	assert.True(t, targets["/home/o/Documents"], "intermediate must get a traverse entry; got %v", targets)
	assert.True(t, targets["/home/o"], "home must get a traverse entry")
}

// TestACLRevokeCommands_Linux_HomeEqualsProject drops the home command when
// home == project but still emits both project commands (access + default).
func TestACLRevokeCommands_Linux_HomeEqualsProject(t *testing.T) {
	cmds := aclRevokeCommands("/srv/p", "/srv/p", "_byn-exec")
	require.Len(t, cmds, 2)
	assert.Equal(t, "/srv/p", cmds[0][len(cmds[0])-1], "access ACL targets project")
	assert.Equal(t, "/srv/p", cmds[1][len(cmds[1])-1], "default ACL targets project")
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

// TestRevokeProjectACL_Linux_RunsAll verifies the revoke entry runs the two
// project-dir removals (access + default ACL); ancestor traversals are left.
func TestRevokeProjectACL_Linux_RunsAll(t *testing.T) {
	var ran [][]string
	err := RevokeProjectACL(func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}, "/home/o/proj", "/home/o")
	require.NoError(t, err)
	require.Len(t, ran, 2)
	assert.Contains(t, ran[0], "u:_byn-exec", "first cmd removes access ACL")
	assert.Contains(t, ran[1], "d:u:_byn-exec", "second cmd removes default ACL")
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

// ---- daemon-read ACL (_byn reads the .byn to validate) -------------------

// TestBynReadGrantCommands_Linux asserts three setfacl invocations: read on the
// FILE (u:_byn:r), and execute-only traversal on its DIR and on the home.
func TestBynReadGrantCommands_Linux(t *testing.T) {
	cmds := bynReadGrantCommands("/home/o/proj/.byn", "/home/o", "_byn")
	require.Len(t, cmds, 3)
	assert.Equal(t,
		[]string{"setfacl", "-m", "u:_byn:r", "/home/o/proj/.byn"},
		cmds[0], "read on the file")
	assert.Equal(t,
		[]string{"setfacl", "-m", "u:_byn:x", "/home/o/proj"},
		cmds[1], "traverse into the dir (no read = no listing)")
	assert.Equal(t,
		[]string{"setfacl", "-m", "u:_byn:x", "/home/o"},
		cmds[2], "traverse into home")
}

// TestBynReadGrantCommands_Linux_HomeEqualsDir drops the home command when the
// .byn lives directly in home.
func TestBynReadGrantCommands_Linux_HomeEqualsDir(t *testing.T) {
	cmds := bynReadGrantCommands("/home/o/.byn", "/home/o", "_byn")
	require.Len(t, cmds, 2)
	assert.Equal(t, "/home/o/.byn", cmds[0][len(cmds[0])-1])
	assert.Equal(t, "/home/o", cmds[1][len(cmds[1])-1])
}

// TestBynReadGrantCommands_Linux_DeepPath grants a traverse entry on EVERY
// intermediate dir up to home (a 0700 ancestor would otherwise block the open).
func TestBynReadGrantCommands_Linux_DeepPath(t *testing.T) {
	cmds := bynReadGrantCommands("/home/o/Documents/proj/.byn", "/home/o", "_byn")
	require.Len(t, cmds, 4)
	targets := map[string]bool{}
	for _, c := range cmds[1:] {
		targets[c[len(c)-1]] = true
		assert.Equal(t, "u:_byn:x", c[2], "ancestor entry must grant traverse only")
	}
	assert.True(t, targets["/home/o/Documents"], "intermediate must get a traverse entry; got %v", targets)
	assert.True(t, targets["/home/o/Documents/proj"], "project dir must get a traverse entry")
	assert.True(t, targets["/home/o"], "home must get a traverse entry")
}

// TestBynReadRevokeCommands_Linux removes the file read entry and the dir
// traversal entry but NOT the shared home traversal.
func TestBynReadRevokeCommands_Linux(t *testing.T) {
	cmds := bynReadRevokeCommands("/home/o/proj/.byn", "_byn")
	require.Len(t, cmds, 2, "revoke must NOT touch the shared home traversal")
	assert.Equal(t,
		[]string{"setfacl", "-x", "u:_byn", "/home/o/proj/.byn"},
		cmds[0], "remove read entry on the file")
	assert.Equal(t,
		[]string{"setfacl", "-x", "u:_byn", "/home/o/proj"},
		cmds[1], "remove traversal entry on the dir")
	for _, c := range cmds {
		assert.NotEqual(t, "/home/o", c[len(c)-1], "home must not be revoked")
	}
}

// TestGrantBynReadACL_Linux_UsesDaemonUser verifies the exported entry iterates
// every command and names the _byn daemon user.
func TestGrantBynReadACL_Linux_UsesDaemonUser(t *testing.T) {
	var ran [][]string
	err := GrantBynReadACL(func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}, "/home/o/proj/.byn", "/home/o")
	require.NoError(t, err)
	require.Len(t, ran, 3)
	assert.Contains(t, ran[0], "u:"+DaemonUser+":r")
}

// TestGrantBynReadACL_Linux_StopsAtFirstError confirms best-effort short-circuit.
func TestGrantBynReadACL_Linux_StopsAtFirstError(t *testing.T) {
	sentinel := errors.New("boom")
	calls := 0
	err := GrantBynReadACL(func(name string, args ...string) error {
		calls++
		return sentinel
	}, "/home/o/proj/.byn", "/home/o")
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, calls)
}

// TestRevokeBynReadACL_Linux_RunsAll verifies the revoke entry runs both
// commands and stops at the first error.
func TestRevokeBynReadACL_Linux_RunsAll(t *testing.T) {
	var ran [][]string
	err := RevokeBynReadACL(func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}, "/home/o/proj/.byn", "/home/o")
	require.NoError(t, err)
	require.Len(t, ran, 2)

	sentinel := errors.New("boom")
	calls := 0
	err = RevokeBynReadACL(func(name string, args ...string) error {
		calls++
		return sentinel
	}, "/home/o/proj/.byn", "/home/o")
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, calls)
}
