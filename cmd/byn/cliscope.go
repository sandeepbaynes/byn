package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// cliScope captures the user's vault/project/env selection from the
// CLI flags and environment variables. Empty fields fall through to
// the daemon's defaults ("default" everywhere).
//
// Precedence (highest first):
//
//  1. CLI flag      (--vault NAME / --project NAME / --env NAME)
//  2. Env var       (BYN_VAULT / BYN_PROJECT / BYN_ENV)
//  3. Daemon default ("default")
//
// .byn file discovery is planned for a future iteration but not
// wired here yet.
type cliScope struct {
	Vault   string
	Project string
	Env     string
	// SourcePath is the `.byn` that supplied this scope via discovery (or "").
	// `byn exec` verifies trust against it before injecting; other commands
	// ignore it.
	SourcePath string
}

// envFallbackKeys maps each scope field to its environment-variable
// name. Exported so tests can clear them in t.Setenv.
var envFallbackKeys = struct {
	Vault, Project, Env string
}{
	Vault:   "BYN_VAULT",
	Project: "BYN_PROJECT",
	Env:     "BYN_ENV",
}

// ToIPC produces an ipc.Scope from the resolved cliScope. Empty
// fields stay empty — the daemon fills them in.
func (s cliScope) ToIPC() ipc.Scope {
	return ipc.Scope{Vault: s.Vault, Project: s.Project, Env: s.Env}
}

// String returns a compact "vault/project/env" representation,
// substituting "default" for any empty field. Used in audit / human
// output.
func (s cliScope) String() string {
	defaulted := func(v string) string {
		if v == "" {
			return "default"
		}
		return v
	}
	return defaulted(s.Vault) + "/" + defaulted(s.Project) + "/" + defaulted(s.Env)
}

// ---- Pre-parser for global flag positioning ----------------------------
//
// Go's stdlib flag package doesn't natively support flags that can
// appear before OR after the subcommand. The hybrid pattern we want is:
//
//	byn --vault acme exec -- python ...    (flags before subcommand)
//	byn exec --vault acme -- python ...    (flags after subcommand)
//
// preParseGlobals does a single linear scan, pulling out global flag
// + value pairs whenever it sees them, regardless of position. The
// scrubbed argv is returned for subcommand-level flag parsing.
//
// Conflict (same flag specified twice with different values) is a
// hard error.

// globalFlags lists which flags the pre-parser treats as global.
var globalFlags = map[string]struct{}{
	"--vault":   {},
	"--project": {},
	"--env":     {},
}

// jsonModeFromArgs reports whether `--json` appears anywhere before the
// `--` separator. Used to gate `.byn` TOFU prompting — when --json
// is set we must NEVER prompt (agent mode); we hard-fail instead.
func jsonModeFromArgs(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--json" || a == "--json=true" {
			return true
		}
	}
	return false
}

// noDiscoveryFromArgs reports whether `--no-discovery` is set. Lets a
// caller opt out of .byn walk without setting an env var.
func noDiscoveryFromArgs(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--no-discovery" {
			return true
		}
	}
	return false
}

// stripFlagToken removes the literal token (with or without value)
// from args. Used after we've detected --no-discovery / --json so the
// remaining argv goes through the standard pre-parser.
func stripFlagToken(args []string, name string) []string {
	out := args[:0]
	for _, a := range args {
		if a == name {
			continue
		}
		out = append(out, a)
	}
	return out
}

// preParseGlobals scans argv for global flags and returns the
// resolved scope plus a scrubbed argv with the consumed flags
// removed. The pre-parser stops at a literal "--" (which is
// significant for `byn exec -- COMMAND`).
//
// Recognized forms:
//
//	--vault NAME           (two-token form)
//	--vault=NAME           (one-token form)
//
// Anything that doesn't match a global flag is passed through
// untouched. The function never errors except on mixed-value
// duplicates (e.g., --vault a --vault b).
func preParseGlobals(args []string) (cliScope, []string, error) {
	var sc cliScope
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			// Everything after this is opaque (child argv for exec,
			// rename's NEW, etc.). Pass through and stop scanning.
			out = append(out, args[i:]...)
			break
		}
		// Match "--flag" or "--flag=value".
		flagName, value, hasValue := splitFlag(a)
		if _, isGlobal := globalFlags[flagName]; !isGlobal {
			out = append(out, a)
			continue
		}
		// We've found a global flag. Pull its value.
		var v string
		if hasValue {
			v = value
		} else {
			if i+1 >= len(args) {
				return sc, nil, fmt.Errorf("%s requires a value", flagName)
			}
			i++
			v = args[i] //nolint:gosec // G602 false positive: i+1 < len(args) checked above
		}
		// Assign with duplicate-check.
		if err := setScopeField(&sc, flagName, v); err != nil {
			return sc, nil, err
		}
	}
	// Env-var fallbacks fill in anything not set by flags.
	if sc.Vault == "" {
		sc.Vault = os.Getenv(envFallbackKeys.Vault)
	}
	if sc.Project == "" {
		sc.Project = os.Getenv(envFallbackKeys.Project)
	}
	if sc.Env == "" {
		sc.Env = os.Getenv(envFallbackKeys.Env)
	}
	return sc, out, nil
}

// splitFlag breaks "--flag=value" into ("--flag", "value", true) and
// "--flag" into ("--flag", "", false). Non-flag tokens return
// ("", "", false).
func splitFlag(a string) (name, value string, hasValue bool) {
	if !strings.HasPrefix(a, "--") {
		return "", "", false
	}
	eq := strings.IndexByte(a, '=')
	if eq < 0 {
		return a, "", false
	}
	return a[:eq], a[eq+1:], true
}

// setScopeField writes v to the right field of sc, returning an error
// if the field is already set to a different value.
func setScopeField(sc *cliScope, flagName, v string) error {
	switch flagName {
	case "--vault":
		if sc.Vault != "" && sc.Vault != v {
			return fmt.Errorf("--vault specified twice with different values: %q vs %q", sc.Vault, v)
		}
		sc.Vault = v
	case "--project":
		if sc.Project != "" && sc.Project != v {
			return fmt.Errorf("--project specified twice with different values: %q vs %q", sc.Project, v)
		}
		sc.Project = v
	case "--env":
		if sc.Env != "" && sc.Env != v {
			return fmt.Errorf("--env specified twice with different values: %q vs %q", sc.Env, v)
		}
		sc.Env = v
	}
	return nil
}
