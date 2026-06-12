//go:build linux

package privsep

import "fmt"

// aclGrantCommands returns the setfacl invocations to give `user` access to a
// project dir: recursive rwX (+ a default ACL so newly-created files are
// reachable) on the project dir, and an execute-only (search) ACL on the
// owner's home so `user` can traverse INTO the project without being able to
// LIST the home. Returns [][]string (each = a command + args for exec.Command).
//
// X = +x only on dirs/already-exec files (not data files) — POSIX ACL X-flag.
func aclGrantCommands(projectDir, homeDir, user string) [][]string {
	cmds := [][]string{
		{"setfacl", "-R", "-m", fmt.Sprintf("u:%s:rwX", user), projectDir},
		{"setfacl", "-R", "-d", "-m", fmt.Sprintf("u:%s:rwX", user), projectDir},
	}
	if homeDir != "" && homeDir != projectDir {
		// execute-only on the home → traverse, not list.
		cmds = append(cmds, []string{"setfacl", "-m", fmt.Sprintf("u:%s:x", user), homeDir})
	}
	return cmds
}

// aclRevokeCommands returns the setfacl invocations that remove `user`'s entry
// from the project dir and the execute-only entry on the owner's home.
// Two commands target the project dir:
//  1. Remove the access ACL entry (-x u:<user>).
//  2. Remove the default ACL entry (-x d:u:<user>) that was set by the -d grant
//     so that newly-created files no longer inherit _byn-exec access.
//
// Mirrors aclGrantCommands.
func aclRevokeCommands(projectDir, homeDir, user string) [][]string {
	cmds := [][]string{
		{"setfacl", "-R", "-x", fmt.Sprintf("u:%s", user), projectDir},
		{"setfacl", "-R", "-x", fmt.Sprintf("d:u:%s", user), projectDir},
	}
	if homeDir != "" && homeDir != projectDir {
		cmds = append(cmds, []string{"setfacl", "-x", fmt.Sprintf("u:%s", user), homeDir})
	}
	return cmds
}

// GrantProjectACL grants the _byn-exec service user rwX on projectDir (+ a
// default ACL so files the child creates stay reachable) and execute-only
// traversal on homeDir. It runs the platform ACL commands via run and is
// best-effort: it returns the FIRST command error (the caller logs/audits a
// warning but does not fail the trust grant). Safe to call only when privsep
// is enabled.
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

// RevokeProjectACL removes the _byn-exec ACL entries added by GrantProjectACL.
// Best-effort: returns the first command error. See GrantProjectACL.
func RevokeProjectACL(run func(name string, args ...string) error, projectDir, homeDir string) error {
	for _, c := range aclRevokeCommands(projectDir, homeDir, ExecUser) {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}
