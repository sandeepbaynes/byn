// `.byn` discovery + TOFU trust model.
//
// Discovery walk: starting at CWD, walk parent directories looking for
// a `.byn` file. The first one found is the active scope source;
// the search stops at:
//
//   - the user's home directory (don't accidentally walk into shared
//     parents)
//   - the filesystem root
//   - an empty `.byn` file (per-project escape hatch — drop an
//     empty `.byn` at a project root to STOP walks from leaking
//     into a parent's scope)
//
// File format (strict TOML; unknown keys fail):
//
//	[scope]
//	vault   = "default"
//	project = "myapp"
//	env     = "dev"
//
// TOFU: trust is recorded as {canonical path, SHA-256 of content} in the
// daemon-owned store (<data-dir>/trusted_byn.json, package internal/trust).
// Discovery is READ-ONLY: it recomputes the hash and looks the path up.
//
//   - trusted   → apply the scope
//   - untrusted → refuse (first use); approve with `byn trust PATH`
//   - changed   → refuse (the file changed since it was trusted); the
//     user must explicitly re-approve with `byn trust PATH`
//
// Discovery NEVER grants trust itself — granting is gated by the master
// password and routed through the daemon (`byn trust`). This closes the
// silent-re-trust hole: a modified `.byn` is never honored until a human
// re-approves it. See docs/security.md and the project memory
// "project-owner-operator-paradigm".

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/bynfile"
)

const discoveryFile = ".byn"

// discoverScope walks parents from CWD looking for a .byn. Returns
// (scope, sourcePath) on success. If no file is found, returns empty
// scope and "". An untrusted or changed `.byn` is an error — discovery
// never grants trust (use `byn trust`).
//
// agentMode only tailors the error hint (an agent can't answer an
// interactive prompt, so it's pointed at running `byn trust` in a
// terminal); the trust decision itself is identical either way.
//
// stopHome: the user's home dir; the walk does not go above this.
func discoverScope(startDir, homeDir, _ string, _ bool) (cliScope, string, error) {
	if os.Getenv("BYN_NO_DISCOVERY") == "1" {
		return cliScope{}, "", nil
	}
	dir := startDir
	for {
		candidate := filepath.Join(dir, discoveryFile)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			// Empty file: STOP marker. Used to shield a project root
			// from a parent .byn.
			if info.Size() == 0 {
				return cliScope{}, "", nil
			}
			body, rerr := os.ReadFile(candidate) // #nosec G304 -- caller-resolved
			if rerr != nil {
				return cliScope{}, "", fmt.Errorf("read %s: %w", candidate, rerr)
			}
			// Discovery resolves the scope but does NOT gate on trust — doing
			// so would block every command (status, list, get, …) on an
			// untrusted .byn. Only `byn exec` verifies the file, since it's the
			// command that injects secrets into a child process (see runExec).
			parsed, derr := bynfile.Parse(body)
			if derr != nil {
				return cliScope{}, "", fmt.Errorf("%s: parse: %w", candidate, derr)
			}
			return cliScope{
				Vault:   parsed.Scope.Vault,
				Project: parsed.Scope.Project,
				Env:     parsed.Scope.Env,
			}, candidate, nil
		}
		// Stop conditions.
		if dir == homeDir {
			return cliScope{}, "", nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return cliScope{}, "", nil
		}
		dir = parent
	}
}

// bynSetAside reports whether --vault (or BYN_VAULT) names a vault other than
// the one the discovered .byn speaks for, an omitted vault line meaning the
// default vault. A .byn's project and env are names inside its own vault, so
// in another vault the file has nothing to contribute: it is set aside whole,
// and the fields the command line did not name fall back to the daemon's
// defaults, never to the file's. Merging field by field put "maison/rinkats"
// on a request from a file that said "rinkats/rinkats" — a project that does
// not exist in that vault, and that nobody asked for.
func bynSetAside(flags, discovered cliScope) bool {
	fileVault := discovered.Vault
	if fileVault == "" {
		fileVault = "default"
	}
	return flags.Vault != "" && flags.Vault != fileVault
}

// overriddenScopeFields names the flags that replaced a value the .byn set,
// so the scope banner can say so. A flag that merely repeats the file is not
// an override, and a project or env the file leaves empty is the flag's to
// fill. An omitted vault line is not empty, it is the default vault, so
// --vault maison beside it is an override like any other.
func overriddenScopeFields(flags, discovered cliScope) []string {
	var out []string
	if bynSetAside(flags, discovered) {
		out = append(out, "--vault")
	}
	if flags.Project != "" && discovered.Project != "" && flags.Project != discovered.Project {
		out = append(out, "--project")
	}
	if flags.Env != "" && discovered.Env != "" && flags.Env != discovered.Env {
		out = append(out, "--env")
	}
	return out
}

// mergeDiscoveryScope folds discovered scope into CLI scope. CLI
// flags win over discovery; discovery wins over daemon defaults — within
// the file's own vault. Named into another vault, the file is set aside
// and contributes nothing (see bynSetAside).
func mergeDiscoveryScope(cli, discovered cliScope) cliScope {
	out := cli
	if bynSetAside(cli, discovered) {
		return out
	}
	if out.Vault == "" {
		out.Vault = discovered.Vault
	}
	if out.Project == "" {
		out.Project = discovered.Project
	}
	if out.Env == "" {
		out.Env = discovered.Env
	}
	return out
}
