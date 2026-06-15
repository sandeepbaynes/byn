package main

import (
	"os/exec"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// ownerACLRun executes an ACL command (chmod on macOS, setfacl on Linux) as the
// OWNER, without a shell. Package var so tests can stub it. The owner CLI — not
// the _byn daemon — runs these: only the file's owner can change its ACL, and
// the daemon (running as _byn under privsep) cannot ACL a user-owned file. This
// is the owner-side half of the trust handshake: it lets the daemon, the
// security authority, independently read+validate the real .byn instead of
// trusting content the (possibly compromised) CLI sends.
var ownerACLRun = func(name string, args ...string) error {
	// #nosec G204 -- name is a fixed binary ("chmod"/"setfacl") chosen by the
	// privsep ACL code; args are file paths + fixed ACE strings, run via
	// exec.Command (no shell) so path metacharacters cannot inject.
	return exec.Command(name, args...).Run()
}

// grantTrustACLs gives the privsep service users access to a just-trusted .byn,
// addressed by its CANONICAL path (symlinks resolved) so the ACL lands on the
// real inode the daemon will open: the _byn daemon gets READ on the file (to
// independently read+validate the fingerprint at trust + exec) and _byn-exec
// gets rwX on the project dir (so shimmed commands can run). Returns the first
// error so the caller can roll the grant back if the daemon rejects the trust.
// Only call when the daemon reports privsep engaged (off → privsep funcs no-op).
func grantTrustACLs(canonBynPath, home string) error {
	if err := privsep.GrantBynReadACL(ownerACLRun, canonBynPath, home); err != nil {
		return err
	}
	return privsep.GrantProjectACL(ownerACLRun, filepath.Dir(canonBynPath), home)
}

// revokeTrustACLs removes what grantTrustACLs added (best-effort: an orphaned
// ACL is harmless — the daemon never acts on a .byn with no trust record — and
// is re-granted on the next trust). Used both for untrust and for rolling back a
// grant the daemon rejected. Addressed by the same CANONICAL path as the grant.
func revokeTrustACLs(canonBynPath, home string) {
	_ = privsep.RevokeBynReadACL(ownerACLRun, canonBynPath, home)
	_ = privsep.RevokeProjectACL(ownerACLRun, filepath.Dir(canonBynPath), home)
}
