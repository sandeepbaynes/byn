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
// TOFU / trust: discovery itself does NOT gate on trust. It only resolves the
// scope from the nearest `.byn` and returns it — gating every command (status,
// list, get, …) on an untrusted `.byn` would be far too broad. Trust is
// verified only by `byn exec`, the sole command that injects secret values
// into a child process: it re-reads the file, recomputes its SHA-256, and
// checks it against the daemon-owned store (<data-dir>/trusted_byn.json,
// package internal/trust) — an untrusted or changed file is refused there.
//
// Discovery is READ-ONLY and NEVER grants trust; granting is gated by the
// master password and routed through the daemon (`byn trust`). This closes the
// silent-re-trust hole: a modified `.byn` is never honored by `byn exec` until
// a human re-approves it. See docs/security.md and the project memory
// "project-owner-operator-paradigm".

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/bynfile"
)

const discoveryFile = ".byn"

// discoverScope walks parents from startDir looking for a .byn. Returns
// (scope, sourcePath) on success. If no file is found, returns an empty scope
// and "". A parse failure is an error; discovery does not gate on trust (see
// the package doc — only `byn exec` verifies trust).
//
// homeDir bounds the walk: it does not ascend above the user's home, so a
// command run inside a project never picks up a stray `.byn` in a shared
// parent. Both paths are canonicalized (symlinks resolved) so the boundary
// compares reliably even when home is reached through a symlinked path.
func discoverScope(startDir, homeDir string) (cliScope, string, error) {
	if os.Getenv("BYN_NO_DISCOVERY") == "1" {
		return cliScope{}, "", nil
	}
	dir := canonDir(startDir)
	homeDir = canonDir(homeDir)
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

// canonDir returns dir with symlinks resolved and cleaned, so the home
// boundary in discoverScope compares reliably (e.g. /home symlinked to
// /System/Volumes/Data/home, or a symlinked home directory). On any error
// (path doesn't resolve) it falls back to filepath.Clean, preserving the
// previous best-effort behavior rather than failing discovery.
func canonDir(dir string) string {
	if dir == "" {
		return dir
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved
	}
	return filepath.Clean(dir)
}

// mergeDiscoveryScope folds discovered scope into CLI scope. CLI
// flags win over discovery; discovery wins over daemon defaults.
func mergeDiscoveryScope(cli, discovered cliScope) cliScope {
	out := cli
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
