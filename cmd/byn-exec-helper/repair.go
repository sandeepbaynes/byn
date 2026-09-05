package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const repairOwnerFlag = "--repair-owner"

// repairOwnerRequested reports whether argv asks for an ownership repair, and
// for which directory and owner.
func repairOwnerRequested(args []string) (dir string, ok bool) {
	for i, a := range args {
		if a == repairOwnerFlag && i+1 < len(args) {
			dir = args[i+1]
			if dir == "" || !filepath.IsAbs(dir) {
				return "", false
			}
			return dir, true
		}
	}
	return "", false
}

// repairOwnerMain gives the owner back access to files the exec child created.
//
// A default ACL only reaches files made after it is set, so a project that has
// already been built under byn keeps a .next and a node_modules/.vite that
// belong to the service user and that the owner cannot delete — deleting a file
// needs write on its directory. Only the file's owner or root can change that,
// which is why the fix runs here, as the service user, rather than in the CLI.
//
// The repair only ever ADDS an entry for the owner. It does not chown, does not
// widen anyone else's access, and does not touch files the service user does not
// own — a run that finds nothing to fix changes nothing.
func repairOwnerMain(dir string) {
	// The owner is the CALLER, read from the kernel — never a name supplied in
	// argv. Taking it from the command line would let anyone who can run this
	// helper grant access to a user of their choosing, which is a wider
	// authority than the repair needs.
	callerUID := os.Getuid()
	// How this platform's ACL tool names the caller. macOS chmod cannot
	// translate a numeric id, so darwin resolves it to a username here — still
	// from the kernel's uid, never from argv. Resolved BEFORE privileges are
	// dropped, while the process can still be sure of who it is.
	owner, err := aclPrincipal(callerUID)
	if err != nil {
		fatal("resolving the calling user: %v", err)
	}
	// Fail once, loudly, when the ACL tool is missing. Discovering it per-file
	// meant the walk printed the same failure for every path and then reported
	// nothing repaired — which is how this stayed broken on macOS, where there
	// is no setfacl at all, while `byn repair` said "nothing to repair".
	if aerr := aclToolAvailable(); aerr != nil {
		fatal("%v", aerr)
	}
	uid, gid, err := readTargetIDs()
	if err != nil {
		fatal("reading target ids: %v", err)
	}
	if uid <= 0 || gid <= 0 {
		fatal("config has non-positive uid/gid (%d/%d)", uid, gid)
	}
	if uid == os.Getuid() {
		fatal("refusing: target uid %d equals caller uid", uid)
	}
	if err := dropTo(uid, gid); err != nil {
		fatal("dropping privileges: %v", err)
	}

	// setfacl -R adds the entry to everything the service user owns beneath the
	// directory. Files it does not own are refused and skipped, which is the
	// intended outcome rather than an error worth stopping for.
	fixed := 0
	// #nosec G703 -- dir is an absolute path from the caller; the walk only ever
	// ADDS an entry for that same caller on files the service user owns, so a
	// caller naming an unrelated directory gains nothing they did not have.
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil // unreadable subtree: nothing here we can repair
		}
		// Never set an ACL through a symlink. Both tools follow one to its
		// target, so a link the service user owns pointing outside the tree
		// would hand the caller access to whatever it names — authority the
		// repair has no reason to grant.
		if d != nil && d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !ownedByUID(path, uid) {
			return nil
		}
		cmd := aclOwnerCmd(path, owner, d != nil && d.IsDir())
		if out, cerr := cmd.CombinedOutput(); cerr != nil {
			fmt.Fprintf(os.Stderr, "byn-exec-helper: %s: %v: %s\n",
				path, cerr, strings.TrimSpace(string(out)))
			return nil
		}
		fixed++
		return nil
	})
	if err != nil {
		fatal("walking %s: %v", dir, err)
	}
	fmt.Printf("%d\n", fixed)
}

// ownedByUID reports whether path belongs to uid. Files owned by anyone else
// are left alone: the repair exists to undo what the exec child created, not to
// rewrite a project's permissions.
func ownedByUID(path string, uid int) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid
}
