package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"

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
	// A recursive grant walks the whole project, and on a real one that means
	// node_modules: it has hung `byn trust` before (fixed in 4b233ba, then
	// reintroduced). Bounding it keeps the deep grant's benefit for pre-existing
	// nested cache dirs while making the hang impossible — trust returning
	// slightly under-granted is recoverable, trust never returning is not.
	timeout := aclTimeout
	for _, a := range args {
		if a == "-R" {
			timeout = recursiveACLTimeout
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- name is a fixed binary ("chmod"/"setfacl") chosen by the
	// privsep ACL code; args are file paths + fixed ACE strings, run via
	// exec.Command (no shell) so path metacharacters cannot inject.
	err := exec.CommandContext(ctx, name, args...).Run()
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Note:"),
			dim(fmt.Sprintf("%s took longer than %s and was stopped; deeply nested build caches may need `byn doctor --repair`", name, timeout)))
		return nil // best-effort: an incomplete deep grant must not fail the trust
	}
	return err
}

// ACL commands are quick on a single path and unbounded on a tree, so the
// recursive form gets its own, larger budget rather than sharing one.
const (
	aclTimeout          = 10 * time.Second
	recursiveACLTimeout = 20 * time.Second
)

// cliPrivsepProvisioned reports whether this machine is provisioned for privsep
// — i.e. the _byn service user exists, so the daemon runs as _byn and cannot
// read a user-owned .byn without the owner-granted ACL. Checked LOCALLY (not via
// the daemon's status) so the grant decision is correct regardless of the
// daemon's version or its [security] privsep config flag: the file-access
// problem is a property of the daemon's UID (provisioned), not that flag.
// The account existing is necessary and not sufficient: uninstall leaves the
// _byn accounts in place while removing everything they were for, and a machine
// in that state is not running a privsep daemon. It has to be judged by what
// setup installed, or byn tells a caller to bring up a service that is not
// there — see privsepArtifactsPresent.
func cliPrivsepProvisioned() bool {
	if forcedUnprovisioned() {
		return false
	}
	if _, _, err := privsep.LookupDaemonUser(); err != nil {
		return false
	}
	return privsepArtifactsPresent()
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
	// Name the owner so files the exec child creates inherit an entry for them.
	// Without it a build run under byn leaves .next and node_modules/.vite owned
	// by the service user and undeletable by the person who owns the project.
	owner := ""
	if u, uerr := user.Current(); uerr == nil {
		owner = u.Username
	}
	if err := privsep.GrantProjectACLFor(ownerACLRun, filepath.Dir(canonBynPath), home, owner); err != nil {
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
	return writableDirs(canonBynPath, home, true)
}

// execDeclaredWritableDirs is execWritableDirs without the curated defaults —
// only what the .byn actually asked for.
//
// The distinction matters because the two lists are maintained by different
// mechanisms. The curated defaults get a DEFAULT ACL once, at trust time, and
// inheritance keeps them correct for everything created afterwards. The declared
// list is where credential tools live, and those rewrite-then-chmod their own
// files, discarding the inherited entry — which is the only case needing a
// repeated pass.
//
// Walking the defaults per exec instead of just the declared paths cost 13.6s
// per exec on a real monorepo: ~/.cache, ~/go and ~/.local hold tens of
// thousands of 0600 files, none of them the credential file in ~/.aws that the
// pass exists for. `byn repair` still sweeps everything, because it is asked to.
func execDeclaredWritableDirs(canonBynPath, home string) []string {
	return writableDirs(canonBynPath, home, false)
}

func writableDirs(canonBynPath, home string, includeDefaults bool) []string {
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
	if includeDefaults {
		for _, rel := range privsep.ExecToolchainDefaults {
			add(filepath.Join(home, rel), false)
		}
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
