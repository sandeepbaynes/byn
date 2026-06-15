//go:build linux

package privsep

import (
	"fmt"
	"path/filepath"
)

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
	// Traverse (execute-only) every ancestor ABOVE the project dir up to home so
	// a restrictive intermediate (e.g. a 0700 ~/Documents) can't block the child
	// from reaching the project. projectDir itself is covered by the grant above.
	if homeDir != "" && homeDir != projectDir {
		for _, d := range traverseAncestors(filepath.Dir(projectDir), homeDir) {
			cmds = append(cmds, []string{"setfacl", "-m", fmt.Sprintf("u:%s:x", user), d})
		}
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
func aclRevokeCommands(projectDir, _, user string) [][]string {
	// Remove only the project-dir access + default ACL; LEAVE the ancestor
	// traversals. A home (or a 0700 ~/Documents) hosts many trusted projects, so
	// dropping a shared traverse entry on untrust of one would break the others.
	return [][]string{
		{"setfacl", "-R", "-x", fmt.Sprintf("u:%s", user), projectDir},
		{"setfacl", "-R", "-x", fmt.Sprintf("d:u:%s", user), projectDir},
	}
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

// bynReadGrantCommands returns the setfacl invocations that give the _byn daemon
// read access to a single .byn FILE (u:_byn:r) plus execute-only (search)
// traversal on the dir it lives in and on the owner's home, so the daemon can
// open and hash it to validate the fingerprint. The owner CLI runs these (it
// owns the file; the daemon cannot setfacl a user-owned file).
//
// The home entry is dropped when home == the project dir.
func bynReadGrantCommands(bynPath, homeDir, user string) [][]string {
	cmds := [][]string{
		{"setfacl", "-m", fmt.Sprintf("u:%s:r", user), bynPath}, // read the file
	}
	// Traverse EVERY ancestor from the .byn's own dir up to home — a single
	// restrictive intermediate (e.g. a 0700 ~/Documents) would otherwise block
	// the open even though the leaf file is readable.
	for _, d := range traverseAncestors(filepath.Dir(bynPath), homeDir) {
		cmds = append(cmds, []string{"setfacl", "-m", fmt.Sprintf("u:%s:x", user), d})
	}
	return cmds
}

// bynReadRevokeCommands removes the daemon's read entry on the FILE and the
// traversal entry on its DIR. It deliberately does NOT revoke the home entry: a
// single home hosts many trusted .byn files, so dropping the shared traversal on
// untrust of one would break the daemon's access to every sibling. The home
// entry is idempotent (re-added on the next grant) and harmless (x, not r).
func bynReadRevokeCommands(bynPath, user string) [][]string {
	projectDir := filepath.Dir(bynPath)
	return [][]string{
		{"setfacl", "-x", fmt.Sprintf("u:%s", user), bynPath},
		{"setfacl", "-x", fmt.Sprintf("u:%s", user), projectDir},
	}
}

// GrantBynReadACL grants the _byn daemon read access to a single .byn file (and
// traversal to reach it) via setfacl. Run by the OWNER CLI at trust time so the
// daemon can independently read+validate the file. Best-effort: returns the
// first command error. run executes without a shell (see GrantProjectACL).
func GrantBynReadACL(run func(name string, args ...string) error, bynPath, homeDir string) error {
	for _, c := range bynReadGrantCommands(bynPath, homeDir, DaemonUser) {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// RevokeBynReadACL removes the daemon's read entry on the .byn and the traversal
// entry on its dir (leaving the shared home traversal — see bynReadRevokeCommands).
// Best-effort: returns the first command error.
func RevokeBynReadACL(run func(name string, args ...string) error, bynPath, _ string) error {
	for _, c := range bynReadRevokeCommands(bynPath, DaemonUser) {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}
