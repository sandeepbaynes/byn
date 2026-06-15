package main

import (
	"os/exec"

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

// cliPrivsepProvisioned reports whether this machine is provisioned for privsep
// — i.e. the _byn service user exists, so the daemon runs as _byn and cannot
// read a user-owned .byn without the owner-granted ACL. Checked LOCALLY (not via
// the daemon's status) so the grant decision is correct regardless of the
// daemon's version or its [security] privsep config flag: the file-access
// problem is a property of the daemon's UID (provisioned), not that flag.
func cliPrivsepProvisioned() bool {
	_, _, err := privsep.LookupDaemonUser()
	return err == nil
}

// grantTrustACLs grants the _byn daemon READ access to a just-trusted .byn,
// addressed by its CANONICAL path (symlinks resolved) so the ACE lands on the
// real inode the daemon opens: read on the file + execute/search traversal on
// every ancestor up to home. This is exactly what the daemon needs to
// independently read+validate the fingerprint (at trust + exec). Returns the
// first error so the caller can roll the grant back if the daemon rejects.
//
// It deliberately does NOT grant the _byn-exec project-dir ACL here. That grant
// is recursive (chmod -R / setfacl -R) and only matters when [security] privsep
// is enabled (exec children drop to _byn-exec); running it on a real project
// would recurse through node_modules and hang. Exec-time file access is
// provisioned separately by the exec model — not at trust time.
func grantTrustACLs(canonBynPath, home string) error {
	return privsep.GrantBynReadACL(ownerACLRun, canonBynPath, home)
}

// revokeTrustACLs removes the daemon read ACE grantTrustACLs added (best-effort:
// an orphaned ACL is harmless — the daemon never acts on a .byn with no trust
// record — and is re-granted on the next trust). Used both for untrust and for
// rolling back a grant the daemon rejected. Same CANONICAL path as the grant.
func revokeTrustACLs(canonBynPath, home string) {
	_ = privsep.RevokeBynReadACL(ownerACLRun, canonBynPath, home)
}
