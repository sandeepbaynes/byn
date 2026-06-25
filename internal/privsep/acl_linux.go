//go:build linux

package privsep

import (
	"fmt"
	"path/filepath"
)

// aclGrantCommands returns the setfacl invocations to give `user` access to a
// project dir: NON-recursive rwX on the project root, a default (-d) ACL so
// files the child CREATES under it inherit access, and rwX entries on each
// ancestor up to home. Returns [][]string (each = a command + args for
// exec.Command).
//
// Ancestors get rwX (not execute-only) for two reasons:
//  1. Monorepo tooling (pnpm workspace glob, cargo workspaces, etc.) lists
//     parent directories to enumerate sibling packages; execute-only breaks that.
//  2. When a directory is BOTH an ancestor of a nested project AND the root of a
//     parent project, a prior execute-only grant would downgrade the rwX that
//     parent trust set. rwX is idempotent regardless of trust order.
//
// The grant is deliberately NON-recursive here to ensure these commands always
// succeed, even when the project tree contains files or dirs owned by _byn-exec
// (created during previous runs). GrantProjectACL separately issues a best-
// effort setfacl -R that covers all user-owned subdirs at trust time; errors
// from that pass are silently ignored because _byn-exec-owned dirs are already
// writable by ownership and do not need an ACL.
//
// X = +x only on dirs/already-exec files (not data files) — POSIX ACL X-flag.
func aclGrantCommands(projectDir, homeDir, user string) [][]string {
	cmds := [][]string{
		{"setfacl", "-m", fmt.Sprintf("u:%s:rwX", user), projectDir},
		{"setfacl", "-d", "-m", fmt.Sprintf("u:%s:rwX", user), projectDir},
	}
	// rwX on every ancestor ABOVE the project dir up to home so a restrictive
	// intermediate (e.g. a 0700 ~/Documents) can't block the child from reaching
	// the project, and so workspace-enumerating tools (pnpm --filter, cargo)
	// can list these directories without extra manual grants.
	if homeDir != "" && homeDir != projectDir {
		for _, d := range traverseAncestors(filepath.Dir(projectDir), homeDir) {
			cmds = append(cmds, []string{"setfacl", "-m", fmt.Sprintf("u:%s:rwX", user), d})
		}
	}
	return cmds
}

// aclRevokeCommands returns the setfacl invocations that remove `user`'s access
// + default ACL entries from the project dir (non-recursive, mirroring the
// grant). It LEAVES the ancestor traversals: a home (or a 0700 ~/Documents)
// hosts many trusted projects, so dropping a shared traverse entry on untrust of
// one would break the others.
func aclRevokeCommands(projectDir, _, user string) [][]string {
	return [][]string{
		{"setfacl", "-x", fmt.Sprintf("u:%s", user), projectDir},
		{"setfacl", "-x", fmt.Sprintf("d:u:%s", user), projectDir},
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
//
// In addition to the non-recursive root grant (aclGrantCommands), a best-effort
// setfacl -R is issued on the project tree so pre-existing nested dirs like
// node_modules/.vite/ and .astro/ are reachable on the first exec. The error
// is silently ignored: dirs created by a previous _byn-exec run are already
// accessible by ownership and do not require an ACL; setfacl -R exits non-zero
// when it encounters such files, which is expected and harmless.
func GrantProjectACL(run func(name string, args ...string) error, projectDir, homeDir string) error {
	for _, c := range aclGrantCommands(projectDir, homeDir, ExecUser) {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	// Best-effort deep grant: covers existing nested dirs (node_modules/.vite,
	// .astro, etc.) that pnpm/Vite/Astro need to write to on first run. Ignored
	// on error — e.g. when _byn-exec-owned cache dirs are present in the tree.
	_ = run("setfacl", "-R", "-m", fmt.Sprintf("u:%s:rwX", ExecUser), projectDir)
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
// read access to a single .byn FILE (u:_byn:r) plus read+execute (rx) on the
// ancestor dirs up to home. rx rather than x-only lets the daemon list those
// directories, which is needed for the web portal's directory picker
// (handleListDir calls os.ReadDir starting from the owner's home — execute alone
// is not enough to enumerate). On macOS this is not needed because FDA grants the
// daemon full filesystem access; Linux has no equivalent, so the ACL must carry r.
//
// The home entry is dropped when home == the project dir.
func bynReadGrantCommands(bynPath, homeDir, user string) [][]string {
	cmds := [][]string{
		{"setfacl", "-m", fmt.Sprintf("u:%s:r", user), bynPath}, // read the file
	}
	// rx (not just x) on EVERY ancestor from the .byn's own dir up to home — r
	// is needed so the portal's directory picker can list each level; x alone only
	// allows traversal, not enumeration.
	for _, d := range traverseAncestors(filepath.Dir(bynPath), homeDir) {
		cmds = append(cmds, []string{"setfacl", "-m", fmt.Sprintf("u:%s:rx", user), d})
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

// GrantDaemonHomeAccess grants the _byn daemon read+execute (rx) on homeDir via
// setfacl, so the web portal's import file picker can enumerate the owner's
// home directory. On macOS, FDA grants this implicitly; Linux has no equivalent
// so the ACL must be set explicitly at setup time. Best-effort: the caller
// warns on failure but does not abort provisioning.
func GrantDaemonHomeAccess(run func(name string, args ...string) error, homeDir string) error {
	return run("setfacl", "-m", fmt.Sprintf("u:%s:rx", DaemonUser), homeDir)
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
