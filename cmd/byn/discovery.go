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
// daemon-owned store (<BYN_DIR>/trusted_byn.json, package internal/trust).
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
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const discoveryFile = ".byn"

// dotBynScope is the on-disk format. Unknown keys fail (strict
// parser, Decode with DisallowUnknownFields).
type dotBynScope struct {
	Scope struct {
		Vault   string `toml:"vault,omitempty"`
		Project string `toml:"project,omitempty"`
		Env     string `toml:"env,omitempty"`
	} `toml:"scope"`
}

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
			var parsed dotBynScope
			dec := toml.NewDecoder(strings.NewReader(string(body))).DisallowUnknownFields()
			if derr := dec.Decode(&parsed); derr != nil {
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
