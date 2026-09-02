package privsep

import (
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// reconcileScanCap bounds how many entries one writable directory is examined
// for per exec.
//
// A declared writable path is usually small — ~/.aws, ~/.config/gh — but nothing
// stops one naming ~/.cache/pnpm with half a million entries, and this runs
// before every exec. Walking is cheap (a 330k-entry tree lists in under half a
// second) but it is not free, and a per-exec tax is exactly the shape of the
// problem this file exists to avoid repeating.
const reconcileScanCap = 50_000

// lockedDownMode reports whether a file's permissions shut out everyone but its
// owner, which is the state that breaks a shared file.
//
// It is a PREFILTER, not the decision: setfacl sets the ACL mask, which lands in
// the group bits, so a granted file reads 0660 and still matches this. What
// separates a file needing the grant from one that already has it is the ACL
// itself — see hasExecGrant, which the caller consults second.
//
// It is deliberately a mode test
// rather than an ACL read. Reading an ACL per entry is what makes a recursive
// pass cost minutes; a mode comes from the stat the walk already did. It also
// describes the actual failure: a tool that chmods its own credential file to
// 0600 after writing it, which strips whatever ACL was inherited.
func lockedDownMode(m fs.FileMode) bool {
	// The OTHER bit, not group-or-other. The exec service user is not a member
	// of the owner's group — byn never puts it there — so group permissions buy
	// it nothing, and a 0640 file shuts it out exactly as a 0600 one does.
	return m.Perm()&0o004 == 0
}

// ReconcileWritableACLs re-grants the exec service user access to files under
// the declared writable directories that have been locked down since last time.
//
// It exists because no permission scheme survives an explicit chmod. A tool that
// rewrites its own state file — the AWS CLI does this to its SSO cache — creates
// the file, then chmods it to 0600, discarding the inherited ACL. Whichever
// identity wrote last then owns a file the other cannot read: refresh the token
// as yourself and every exec child loses its credentials; let a child refresh it
// and you lose yours.
//
// Run by the OWNER, before spawning. That is not incidental: changing a file's
// ACL requires being its owner or root, so the owner's own byn is the only side
// that can repair a file the owner locked. The mirror case — a file the exec
// child locked, which the owner cannot read — is `byn repair`, which does its
// work through the privileged helper for the same reason.
//
// Best-effort throughout. Files it cannot touch are skipped rather than
// reported: this runs on the way to a command the caller asked for, and failing
// that command over a tool-state file it may never read would be the wrong
// trade. Returns how many entries it re-granted, for the caller to log.
func ReconcileWritableACLs(run func(name string, args ...string) error, dirs []string, execUser string) int {
	// Resolved once, not per file. A failed lookup means the grant check cannot
	// run, so every candidate is re-granted — the old behaviour, correct but
	// slow, which is the right way to be wrong.
	execUID := -1
	if u, err := user.Lookup(execUser); err == nil {
		if n, cerr := strconv.Atoi(u.Uid); cerr == nil {
			execUID = n
		}
	}
	fixed := 0
	for _, dir := range dirs {
		scanned := 0
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return nil // unreadable subtree: nothing here we can repair
			}
			if scanned++; scanned > reconcileScanCap {
				return filepath.SkipAll
			}
			if d.IsDir() {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil || !info.Mode().IsRegular() || !lockedDownMode(info.Mode()) {
				return nil
			}
			// Already granted: nothing to do, and saying so cheaply is what
			// makes running this before every exec affordable.
			if hasExecGrant(path, execUID) {
				return nil
			}
			// Files owned by the service user cannot be changed from here and
			// are not this direction's problem; setfacl simply refuses and the
			// error is dropped.
			if run("setfacl", "-m", "u:"+execUser+":rwX", path) == nil {
				fixed++
			}
			return nil
		})
	}
	return fixed
}

// WritableDirsExist filters a declared list down to what is actually present,
// so a .byn naming a directory the machine does not have costs nothing.
func WritableDirsExist(dirs []string) []string {
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			out = append(out, d)
		}
	}
	return out
}
