package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	owner := strconv.Itoa(callerUID)
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
	err = filepath.WalkDir(dir, func(path string, _ os.DirEntry, werr error) error {
		if werr != nil {
			return nil // unreadable subtree: nothing here we can repair
		}
		if !ownedByUID(path, uid) {
			return nil
		}
		// Numeric uid, so nothing from argv reaches the command line, and the
		// path came from walking a directory this process just read.
		// #nosec G204 G702 -- fixed binary; both arguments are locally derived
		cmd := exec.Command("setfacl", "-m", "u:"+owner+":rwX", path)
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
