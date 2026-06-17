package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/bynfile"
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
// It ALSO grants the _byn-exec service user access to the project dir so a
// privsep exec child can run there. That grant is NON-recursive now (S4 — dir +
// inherit/default ACL, no node_modules walk, so no hang), so it's cheap and
// harmless when privsep exec is off (the ACL is simply unused). Granting it at
// trust time keeps the file-access setup in one place, owner-side.
func grantTrustACLs(canonBynPath, home string) error {
	if err := privsep.GrantBynReadACL(ownerACLRun, canonBynPath, home); err != nil {
		return err
	}
	if err := privsep.GrantProjectACL(ownerACLRun, filepath.Dir(canonBynPath), home); err != nil {
		return err
	}
	// Tool-state auto-grant (Hybrid): grant _byn-exec read/write on the curated
	// multi-language toolchain dirs that exist + any [exec] writable the .byn
	// declares. Best-effort — a tool-state hiccup must NOT fail trusting the .byn.
	if dirs := execWritableDirs(canonBynPath, home); len(dirs) > 0 {
		_ = privsep.GrantExecDirsACL(ownerACLRun, dirs, home)
	}
	return nil
}

// execWritableDirs resolves the absolute tool-state directories to grant the
// _byn-exec child read/write access at trust time: the curated multi-language
// defaults (ExecToolchainDefaults) PLUS the .byn's [exec] writable list. Entries
// are ~-expanded + validated UNDER home, and filtered to those that EXIST
// (chmod on a missing dir fails; a missing curated default is normal). A declared
// writable that is missing, escapes home, or names a credential dir is surfaced
// to the user (the grant is password-gated, so it proceeds, but visibly).
func execWritableDirs(canonBynPath, home string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(abs string, declared bool) {
		if abs == "" || seen[abs] {
			return
		}
		if _, err := os.Stat(abs); err != nil {
			if declared {
				fmt.Fprintf(os.Stderr, "  %s [exec] writable %q does not exist — skipping\n", yellow("!"), abs)
			}
			return
		}
		seen[abs] = true
		out = append(out, abs)
	}
	// Curated defaults (silently skip those that don't exist on this machine).
	for _, rel := range privsep.ExecToolchainDefaults {
		add(filepath.Join(home, rel), false)
	}
	// Declared [exec] writable from the .byn.
	body, err := os.ReadFile(canonBynPath) //nolint:gosec // owner-owned .byn the owner just trusted
	if err != nil {
		return out
	}
	f, perr := bynfile.Parse(body)
	if perr != nil {
		return out
	}
	for _, w := range f.Exec.Writable {
		abs, verr := privsep.ResolveWritableUnderHome(w, home)
		if verr != nil {
			fmt.Fprintf(os.Stderr, "  %s [exec] writable %q refused: %v\n", yellow("!"), w, verr)
			continue
		}
		if privsep.IsSensitiveHomeDir(abs, home) {
			fmt.Fprintf(os.Stderr, "  %s granting _byn-exec access to a credential dir (%s) — declared in [exec] writable\n", boldYellow("Warning:"), abs)
		}
		add(abs, true)
	}
	return out
}

// revokeTrustACLs removes the daemon-read ACE AND the _byn-exec project ACE that
// grantTrustACLs added (best-effort: an orphaned ACL is harmless — the daemon
// never acts on a .byn with no trust record — and is re-granted on the next
// trust). Used both for untrust and for rolling back a rejected grant. Same
// CANONICAL path as the grant.
func revokeTrustACLs(canonBynPath, home string) {
	_ = privsep.RevokeBynReadACL(ownerACLRun, canonBynPath, home)
	_ = privsep.RevokeProjectACL(ownerACLRun, filepath.Dir(canonBynPath), home)
}
