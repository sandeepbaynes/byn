//go:build darwin

package privsep

import (
	"fmt"
	"os"
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
// project dir: a NON-recursive `+a` ACE carrying the inherit flags on the
// project dir (so the dir is accessible and files/dirs the child creates inherit
// access), and an execute/search-only `+a` ACE on each ancestor up to home so
// `user` can traverse INTO the project without being able to LIST it. Returns
// [][]string (each = a command + args for exec.Command).
//
// It is deliberately NON-recursive: a `chmod -R` over a real project would walk
// node_modules and hang for minutes. The inherit flags (file_inherit,
// directory_inherit in projectACEPerms) cover NEW files; existing files are
// reachable via their own world/group perms (typical for source trees). The
// trade-off — a pre-existing OWNER-ONLY file is not granted to the exec child —
// is accepted (see docs/security.md / threat-model.md AR-3 neighborhood).
func aclGrantCommands(projectDir, homeDir, user string) [][]string {
	cmds := [][]string{
		{"chmod", "+a", aceArg(user, projectACEPerms), projectDir},
	}
	// Traverse (not list) every ancestor ABOVE the project dir up to home, so a
	// restrictive intermediate (e.g. a 0700 ~/Documents) can't block the child
	// from reaching the project. execute,search = traverse, not list.
	if homeDir != "" && homeDir != projectDir {
		for _, d := range traverseAncestors(filepath.Dir(projectDir), homeDir) {
			cmds = append(cmds, []string{"chmod", "+a", aceArg(user, homeACEPerms), d})
		}
	}
	return cmds
}

// aclRevokeCommands returns the chmod invocations that remove the project-dir
// ACE added by aclGrantCommands (non-recursive, mirroring the grant). It LEAVES
// the ancestor traversals: a home (or a 0700 ~/Documents) hosts many trusted
// projects, so dropping a shared traverse ACE on untrust of one would break the
// others — harmless to leave (traverse, not list) and re-added on the next grant.
func aclRevokeCommands(projectDir, _, user string) [][]string {
	return [][]string{
		{"chmod", "-a", aceArg(user, projectACEPerms), projectDir},
	}
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
	return GrantProjectACLFor(run, projectDir, homeDir, "")
}

// GrantProjectACLFor is GrantProjectACL with the owner named, so files the exec
// child creates stay writable by the person who owns the project. Without it
// every build artifact belongs to the service user and the owner cannot delete
// it — removing a file needs write on its directory.
// GrantProjectACLForce exists for parity with Linux, where trust skips a costly
// recursive walk once the inheritable entry is present and `byn repair` forces
// it. Darwin sets an inheriting ACE on the project directory and never walks the
// tree, so there is nothing here to skip and nothing to force — the two are the
// same call.
func GrantProjectACLForce(run func(name string, args ...string) error, projectDir, homeDir, owner string) error {
	return GrantProjectACLFor(run, projectDir, homeDir, owner)
}

func GrantProjectACLFor(run func(name string, args ...string) error, projectDir, homeDir, owner string) error {
	for _, c := range aclGrantCommands(projectDir, homeDir, ExecUser) {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	// The owner's inherited ACE. projectACEPerms already carries the
	// file_inherit/directory_inherit flags, so new artifacts pick it up.
	if owner != "" && owner != ExecUser {
		if err := run("chmod", "+a", aceArg(owner, projectACEPerms), projectDir); err != nil {
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
	cmds := [][]string{
		{"chmod", "+a", aceArg(user, bynReadACEPerms), bynPath}, // read the file
	}
	// Traverse EVERY ancestor from the .byn's own dir up to home — a single
	// restrictive intermediate (e.g. a 0700 ~/Documents) would otherwise block
	// the open even though the leaf file is readable.
	for _, d := range traverseAncestors(filepath.Dir(bynPath), homeDir) {
		cmds = append(cmds, []string{"chmod", "+a", aceArg(user, homeACEPerms), d})
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

// GrantDaemonHomeAccess is a no-op on macOS — Full Disk Access (FDA) granted to
// the byn binary gives _byn filesystem access transparently, so no per-directory
// ACE is needed.
func GrantDaemonHomeAccess(_ func(name string, args ...string) error, _ string) error { return nil }

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

// GrantTraverseACL grants the exec service user the ability to reach INTO dir —
// traverse on it and on every ancestor up to home — without granting anything
// at the leaf. Directories that do not exist are skipped, so the chain is
// granted as far as it actually goes.
//
// It exists for the tool-state directory that is ABSENT at trust time. byn skips
// granting a path that is not there, and because the ancestor traversal was part
// of that same grant, skipping the leaf silently left the parent unreachable
// too. The visible cost is a tool asking about a config file it does not have
// and being told EACCES instead of ENOENT: pnpm warns on every single
// invocation about ~/Library/Preferences/pnpm/rc, a file that does not exist,
// because the child cannot traverse the 0700 directory to find that out.
//
// Traverse is the whole grant. The child still cannot list the directory or
// read anything in it, which is the correct authority for "let it discover that
// its config is absent".
func GrantTraverseACL(run func(name string, args ...string) error, dir, home string) error {
	for _, d := range traverseAncestors(dir, home) {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		if err := run("chmod", "+a", aceArg(ExecUser, homeACEPerms), d); err != nil {
			return err
		}
	}
	return nil
}
