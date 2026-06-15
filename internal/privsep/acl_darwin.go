//go:build darwin

package privsep

import (
	"fmt"
	"path/filepath"
)

// macOS ACL entry (ACE) permission sets for `chmod +a`.
//
// projectACEPerms grants full read/write traversal on the project dir plus the
// directory-creation rights AND the inheritance flags (file_inherit +
// directory_inherit) so files/dirs the exec child creates under the project
// inherit the same access — the analog of the Linux default ACL.
//
// homeACEPerms grants only execute,search on the owner's home: enough to
// traverse INTO the project, NOT enough to list the home (no `read`).
//
// bynReadACEPerms grants read-only access to a single .byn FILE so the _byn
// daemon can open+hash it to validate the fingerprint. The daemon is the
// security authority: it reads the REAL file rather than trusting UI-supplied
// content, so the owner CLI grants it exactly this — read on the file, plus
// traverse (homeACEPerms) on the ancestors it must walk to reach it.
const (
	projectACEPerms = "read,write,execute,delete,add_file,add_subdirectory,file_inherit,directory_inherit"
	homeACEPerms    = "execute,search"
	bynReadACEPerms = "read"
)

// aceArg builds a single `chmod +a` ACE argument: "<name> allow <perms>".
func aceArg(user, perms string) string {
	return fmt.Sprintf("%s allow %s", user, perms)
}

// aclGrantCommands returns the chmod invocations to give `user` access to a
// project dir: a recursive `+a` ACE carrying the inherit flags on the project
// dir, and an execute/search-only `+a` ACE on the owner's home so `user` can
// traverse INTO the project without being able to LIST the home. Returns
// [][]string (each = a command + args for exec.Command).
func aclGrantCommands(projectDir, homeDir, user string) [][]string {
	cmds := [][]string{
		{"chmod", "-R", "+a", aceArg(user, projectACEPerms), projectDir},
	}
	if homeDir != "" && homeDir != projectDir {
		// execute,search on the home → traverse, not list. Not recursive.
		cmds = append(cmds, []string{"chmod", "+a", aceArg(user, homeACEPerms), homeDir})
	}
	return cmds
}

// aclRevokeCommands returns the chmod invocations that remove the ACEs added by
// aclGrantCommands. `chmod -a "<ace>"` deletes the matching entry; the ACE text
// must match what was added. Mirrors aclGrantCommands.
func aclRevokeCommands(projectDir, homeDir, user string) [][]string {
	cmds := [][]string{
		{"chmod", "-R", "-a", aceArg(user, projectACEPerms), projectDir},
	}
	if homeDir != "" && homeDir != projectDir {
		cmds = append(cmds, []string{"chmod", "-a", aceArg(user, homeACEPerms), homeDir})
	}
	return cmds
}

// GrantProjectACL grants the _byn-exec service user a full inheriting ACE on
// projectDir and execute/search traversal on homeDir via `chmod +a`. It runs
// the platform ACL commands via run and is best-effort: it returns the FIRST
// command error (the caller logs/audits a warning but does not fail the trust
// grant). Safe to call only when privsep is enabled.
//
// run executes a command WITHOUT a shell (exec.Command, not sh -c), so the
// project path — which may contain shell metacharacters — cannot inject.
func GrantProjectACL(run func(name string, args ...string) error, projectDir, homeDir string) error {
	for _, c := range aclGrantCommands(projectDir, homeDir, ExecUser) {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// RevokeProjectACL removes the _byn-exec ACEs added by GrantProjectACL.
// Best-effort: returns the first command error. See GrantProjectACL.
func RevokeProjectACL(run func(name string, args ...string) error, projectDir, homeDir string) error {
	for _, c := range aclRevokeCommands(projectDir, homeDir, ExecUser) {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// bynReadGrantCommands returns the chmod invocations that give the _byn daemon
// read access to a single .byn FILE plus execute/search traversal on the dir it
// lives in and on the owner's home. The daemon (running as _byn) needs this to
// open and hash the file at trust + exec time; the owner CLI runs these (it owns
// the file, so it can add the ACEs — the daemon cannot ACL a user-owned file).
//
// The home ACE is dropped when home == the project dir (the .byn sits directly
// in home) to avoid a redundant duplicate.
func bynReadGrantCommands(bynPath, homeDir, user string) [][]string {
	projectDir := filepath.Dir(bynPath)
	cmds := [][]string{
		{"chmod", "+a", aceArg(user, bynReadACEPerms), bynPath}, // read the file
		{"chmod", "+a", aceArg(user, homeACEPerms), projectDir}, // traverse into its dir
	}
	if homeDir != "" && homeDir != projectDir {
		cmds = append(cmds, []string{"chmod", "+a", aceArg(user, homeACEPerms), homeDir})
	}
	return cmds
}

// bynReadRevokeCommands returns the chmod invocations that remove the daemon's
// read ACE on the FILE and the traversal ACE on its DIR. It deliberately does
// NOT revoke the home-traversal ACE: a single home typically hosts many trusted
// .byn files, and dropping the shared `execute,search` ACE on untrust of one
// would break the daemon's access to every sibling project. The home ACE is
// idempotent (re-added on the next grant) and harmless (traverse, not list).
func bynReadRevokeCommands(bynPath, user string) [][]string {
	projectDir := filepath.Dir(bynPath)
	return [][]string{
		{"chmod", "-a", aceArg(user, bynReadACEPerms), bynPath},
		{"chmod", "-a", aceArg(user, homeACEPerms), projectDir},
	}
}

// GrantBynReadACL grants the _byn daemon read access to a single .byn file (and
// traversal to reach it) via `chmod +a`. Run by the OWNER CLI at trust time so
// the daemon can independently read+validate the file. Best-effort: returns the
// first command error. run executes without a shell (see GrantProjectACL).
func GrantBynReadACL(run func(name string, args ...string) error, bynPath, homeDir string) error {
	for _, c := range bynReadGrantCommands(bynPath, homeDir, DaemonUser) {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// RevokeBynReadACL removes the daemon's read ACE on the .byn and the traversal
// ACE on its dir (leaving the shared home traversal — see bynReadRevokeCommands).
// Best-effort: returns the first command error.
func RevokeBynReadACL(run func(name string, args ...string) error, bynPath, _ string) error {
	for _, c := range bynReadRevokeCommands(bynPath, DaemonUser) {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}
