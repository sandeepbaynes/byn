//go:build darwin

package privsep

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestACLGrantCommands_Darwin asserts the chmod +a ACE strings carry the user,
// the `allow` keyword, and the inheritance flags on the project ACE; the home
// ACE grants only execute/search (traverse, not list).
func TestACLGrantCommands_Darwin(t *testing.T) {
	cmds := aclGrantCommands("/Users/o/proj", "/Users/o", "_byn-exec")
	require.Len(t, cmds, 2)

	// Project: chmod -R +a "<ace>" <dir>, ACE with inherit flags.
	assert.Equal(t, []string{"chmod", "-R", "+a"}, cmds[0][:3])
	projACE := cmds[0][3]
	assert.True(t, strings.HasPrefix(projACE, "_byn-exec allow "),
		"ACE must be '<name> allow <perms>'; got %q", projACE)
	assert.Contains(t, projACE, "allow")
	assert.Contains(t, projACE, "file_inherit")
	assert.Contains(t, projACE, "directory_inherit")
	assert.Contains(t, projACE, "read")
	assert.Contains(t, projACE, "write")
	assert.Contains(t, projACE, "add_file")
	assert.Contains(t, projACE, "add_subdirectory")
	assert.Equal(t, "/Users/o/proj", cmds[0][4])

	// Home: chmod +a "<ace>" <dir>, execute/search only (no read = can't list).
	assert.Equal(t, []string{"chmod", "+a"}, cmds[1][:2])
	homeACE := cmds[1][2]
	assert.Contains(t, homeACE, "_byn-exec allow ")
	assert.Contains(t, homeACE, "execute")
	assert.Contains(t, homeACE, "search")
	assert.NotContains(t, homeACE, "read", "home ACE must not allow listing")
	assert.Equal(t, "/Users/o", cmds[1][3])
}

// TestACLGrantCommands_Darwin_HomeEqualsProject drops the home command.
func TestACLGrantCommands_Darwin_HomeEqualsProject(t *testing.T) {
	cmds := aclGrantCommands("/p", "/p", "_byn-exec")
	require.Len(t, cmds, 1)
}

// TestACLGrantCommands_Darwin_EmptyHome drops the home command.
func TestACLGrantCommands_Darwin_EmptyHome(t *testing.T) {
	cmds := aclGrantCommands("/p", "", "_byn-exec")
	require.Len(t, cmds, 1)
}

// TestACLRevokeCommands_Darwin asserts revoke uses `-a` (delete) with the same
// ACE text it added, recursively on the project and once on the home.
func TestACLRevokeCommands_Darwin(t *testing.T) {
	cmds := aclRevokeCommands("/Users/o/proj", "/Users/o", "_byn-exec")
	require.Len(t, cmds, 2)

	assert.Equal(t, []string{"chmod", "-R", "-a"}, cmds[0][:3])
	assert.Contains(t, cmds[0][3], "_byn-exec allow ")
	assert.Contains(t, cmds[0][3], "file_inherit")
	assert.Equal(t, "/Users/o/proj", cmds[0][4])

	assert.Equal(t, []string{"chmod", "-a"}, cmds[1][:2])
	assert.Contains(t, cmds[1][2], "_byn-exec allow ")
	assert.Contains(t, cmds[1][2], "execute")
	assert.Equal(t, "/Users/o", cmds[1][3])
}

// TestACLRevokeCommands_Darwin_HomeEqualsProject drops the home command.
func TestACLRevokeCommands_Darwin_HomeEqualsProject(t *testing.T) {
	cmds := aclRevokeCommands("/p", "/p", "_byn-exec")
	require.Len(t, cmds, 1)
}

// TestGrantProjectACL_Darwin_RunsAllAndUsesExecUser verifies the exported entry
// iterates every command and uses ExecUser.
func TestGrantProjectACL_Darwin_RunsAllAndUsesExecUser(t *testing.T) {
	var ran [][]string
	err := GrantProjectACL(func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}, "/Users/o/proj", "/Users/o")
	require.NoError(t, err)
	require.Len(t, ran, 2)
	for _, c := range ran {
		assert.Equal(t, "chmod", c[0])
	}
	assert.Contains(t, strings.Join(ran[0], " "), "_byn-exec allow ")
}

// TestGrantProjectACL_Darwin_StopsAtFirstError confirms best-effort short-circuit.
func TestGrantProjectACL_Darwin_StopsAtFirstError(t *testing.T) {
	sentinel := errors.New("boom")
	calls := 0
	err := GrantProjectACL(func(name string, args ...string) error {
		calls++
		return sentinel
	}, "/p", "/h")
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, calls)
}

// TestRevokeProjectACL_Darwin_RunsAll verifies the revoke entry iterates all.
func TestRevokeProjectACL_Darwin_RunsAll(t *testing.T) {
	var ran [][]string
	err := RevokeProjectACL(func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}, "/Users/o/proj", "/Users/o")
	require.NoError(t, err)
	require.Len(t, ran, 2)
}

// TestRevokeProjectACL_Darwin_StopsAtFirstError mirrors the grant short-circuit.
func TestRevokeProjectACL_Darwin_StopsAtFirstError(t *testing.T) {
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

// TestBynReadGrantCommands_Darwin asserts three ACEs: read on the FILE, and
// execute/search traversal on its DIR and on the home — enough for the _byn
// daemon to open+hash the file, not to list anything.
func TestBynReadGrantCommands_Darwin(t *testing.T) {
	cmds := bynReadGrantCommands("/Users/o/proj/.byn", "/Users/o", "_byn")
	require.Len(t, cmds, 3)

	// File: chmod +a "_byn allow read" <file> — read only, no traverse flags.
	assert.Equal(t, []string{"chmod", "+a"}, cmds[0][:2])
	fileACE := cmds[0][2]
	assert.Equal(t, "_byn allow read", fileACE)
	assert.NotContains(t, fileACE, "write", "daemon read ACE must not grant write")
	assert.Equal(t, "/Users/o/proj/.byn", cmds[0][3])

	// Project dir: execute/search traversal only (no read = can't list the dir).
	dirACE := cmds[1][2]
	assert.Contains(t, dirACE, "_byn allow ")
	assert.Contains(t, dirACE, "execute")
	assert.Contains(t, dirACE, "search")
	assert.NotContains(t, dirACE, "read", "dir traverse ACE must not allow listing")
	assert.Equal(t, "/Users/o/proj", cmds[1][3])

	// Home: traversal only.
	assert.Contains(t, cmds[2][2], "_byn allow ")
	assert.Contains(t, cmds[2][2], "execute")
	assert.Equal(t, "/Users/o", cmds[2][3])
}

// TestBynReadGrantCommands_Darwin_HomeEqualsDir drops the home command when the
// .byn lives directly in home (its dir == home).
func TestBynReadGrantCommands_Darwin_HomeEqualsDir(t *testing.T) {
	cmds := bynReadGrantCommands("/Users/o/.byn", "/Users/o", "_byn")
	require.Len(t, cmds, 2)
	assert.Equal(t, "/Users/o/.byn", cmds[0][3])
	assert.Equal(t, "/Users/o", cmds[1][3])
}

// TestBynReadRevokeCommands_Darwin removes the file read ACE and the dir
// traversal ACE but NOT the shared home traversal (siblings still need it).
func TestBynReadRevokeCommands_Darwin(t *testing.T) {
	cmds := bynReadRevokeCommands("/Users/o/proj/.byn", "_byn")
	require.Len(t, cmds, 2, "revoke must NOT touch the shared home traversal")
	assert.Equal(t, []string{"chmod", "-a"}, cmds[0][:2])
	assert.Equal(t, "_byn allow read", cmds[0][2])
	assert.Equal(t, "/Users/o/proj/.byn", cmds[0][3])
	assert.Equal(t, "/Users/o/proj", cmds[1][3])
	for _, c := range cmds {
		assert.NotEqual(t, "/Users/o", c[len(c)-1], "home must not be revoked")
	}
}

// TestGrantBynReadACL_Darwin_UsesDaemonUser verifies the exported entry iterates
// every command and names the _byn daemon user (not _byn-exec).
func TestGrantBynReadACL_Darwin_UsesDaemonUser(t *testing.T) {
	var ran [][]string
	err := GrantBynReadACL(func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}, "/Users/o/proj/.byn", "/Users/o")
	require.NoError(t, err)
	require.Len(t, ran, 3)
	for _, c := range ran {
		assert.Equal(t, "chmod", c[0])
		assert.Contains(t, strings.Join(c, " "), DaemonUser+" allow ")
	}
}

// TestGrantBynReadACL_Darwin_StopsAtFirstError confirms best-effort short-circuit.
func TestGrantBynReadACL_Darwin_StopsAtFirstError(t *testing.T) {
	sentinel := errors.New("boom")
	calls := 0
	err := GrantBynReadACL(func(name string, args ...string) error {
		calls++
		return sentinel
	}, "/Users/o/proj/.byn", "/Users/o")
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, calls)
}

// TestRevokeBynReadACL_Darwin_RunsAll verifies the revoke entry runs both
// (file + dir) commands and stops at the first error.
func TestRevokeBynReadACL_Darwin_RunsAll(t *testing.T) {
	var ran [][]string
	err := RevokeBynReadACL(func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}, "/Users/o/proj/.byn", "/Users/o")
	require.NoError(t, err)
	require.Len(t, ran, 2)

	sentinel := errors.New("boom")
	calls := 0
	err = RevokeBynReadACL(func(name string, args ...string) error {
		calls++
		return sentinel
	}, "/Users/o/proj/.byn", "/Users/o")
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, calls)
}
