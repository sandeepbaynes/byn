//go:build darwin

package privsep

import "fmt"

// macOS ACL entry (ACE) permission sets for `chmod +a`.
//
// projectACEPerms grants full read/write traversal on the project dir plus the
// directory-creation rights AND the inheritance flags (file_inherit +
// directory_inherit) so files/dirs the exec child creates under the project
// inherit the same access — the analog of the Linux default ACL.
//
// homeACEPerms grants only execute,search on the owner's home: enough to
// traverse INTO the project, NOT enough to list the home (no `read`).
const (
	projectACEPerms = "read,write,execute,delete,add_file,add_subdirectory,file_inherit,directory_inherit"
	homeACEPerms    = "execute,search"
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
