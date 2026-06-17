// Package bynfile parses the `.byn` workspace manifest (strict TOML;
// unknown keys fail). Shared by CLI discovery (scope resolution) and the
// daemon (server-side [exec] env allowlist enforcement in exec.fetch) so
// both sides read the file identically.
package bynfile

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/pelletier/go-toml/v2"
)

// MaxSize is the maximum permitted size of a .byn file (64 KiB). Files
// larger than this are refused at grant, exec, and diff. This is generous
// for a config manifest; a .byn that reaches this size almost certainly
// contains machine-generated noise rather than intentional policy.
const MaxSize = 64 * 1024

// File is the parsed `.byn`. Table depth is at most 2; the top-level sections
// are: [scope], [exec], [aliases], [auth]. Each section owns one concern.
// Collections use the Cargo-style string-now/table-later dual form — the
// string form (bare scalar) is the only supported form in v1; table values
// (inline or multi-line) are reserved for a future version.
//
// Top-level tables:
//   - [scope]   — vault/project/env scope bindings
//   - [exec]    — env allowlist + approved actions
//   - [aliases] — named entry points (alias name → command prefix)
//   - [auth]    — per-operation auth override policy
type File struct {
	Scope struct {
		Vault   string `toml:"vault,omitempty"`
		Project string `toml:"project,omitempty"`
		Env     string `toml:"env,omitempty"`
	} `toml:"scope"`
	Exec struct {
		// Env is the `byn exec` allowlist: which scope vars to inject.
		// "*" = all (loud); a list = only those names; empty/absent = none.
		Env EnvList `toml:"env,omitempty"`
		// Actions pins the commands `byn exec` may run re-auth-free
		// (joined argv, exact string match). Mirrors the env allowlist
		// semantics: empty/absent = NO command runs free (every exec
		// needs per-action auth — the secure default); "*" = all run
		// free (loud warning); a list = only those run free. The
		// action's INTERIOR is approved — byn does not police what a
		// listed command does (spec §1a).
		Actions EnvList `toml:"actions,omitempty"`
		// Writable lists extra tool-state directories the privsep exec child
		// (_byn-exec, a different UID) may read/write — e.g. a package manager's
		// global store/cache under a 0700 home dir. byn grants `_byn-exec` access
		// to these at trust time (owner-side ACLs), ON TOP OF a curated set of
		// common defaults. Each entry must resolve UNDER the owner's home (a
		// leading "~" is expanded); entries outside home are refused. Optional;
		// absent ⇒ only the curated defaults are granted.
		Writable []string `toml:"writable,omitempty"`
	} `toml:"exec"`
	// Aliases is the top-level [aliases] table: named entry points for
	// `byn exec`. Each key is an alias name (^[A-Za-z0-9_][A-Za-z0-9_-]*$);
	// each value is the literal command prefix the alias expands to. Alias
	// values must NOT contain placeholders (those live in [exec] actions).
	// Reserved name "--" is rejected by ValidateAliases.
	// [aliases] is a top-level collection table, not nested under [exec].
	Aliases map[string]string `toml:"aliases,omitempty"`
	// Auth is the per-command policy table (spec §4.5): action name →
	// "always" (fresh auth unconditionally, even with an active session),
	// "none" (skip the gate entirely for the matched scope), or "trusted"
	// (exec only: the .byn is the authorization — the default). Absent keys
	// ⇒ the session gate decides. Parsed at TRUST TIME and MAC-bound into
	// the record.
	Auth map[string]string `toml:"auth,omitempty"`
}

// EnvList accepts a bare string (env = "*") or a list of strings
// (env = ["*"] / ["VAR1","VAR2"]).
type EnvList []string

// UnmarshalText lets a bare string decode into a one-element list. A TOML
// array decodes natively into []string without this method.
func (e *EnvList) UnmarshalText(text []byte) error {
	*e = EnvList{string(text)}
	return nil
}

// Parse decodes body as a strict-TOML .byn.
func Parse(body []byte) (File, error) {
	var f File
	dec := toml.NewDecoder(bytes.NewReader(body)).DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return File{}, err
	}
	return f, nil
}

// AllowsAll reports whether the [exec] env allowlist contains "*".
func (f File) AllowsAll() bool {
	for _, n := range f.Exec.Env {
		if n == "*" {
			return true
		}
	}
	return false
}

// ActionsAllowAll reports whether the [exec] actions list contains "*".
func (f File) ActionsAllowAll() bool {
	for _, a := range f.Exec.Actions {
		if a == "*" {
			return true
		}
	}
	return false
}

// ValidateAuth rejects unknown [auth] keys/values. Allowed keys: get,
// update, delete, exec. Allowed values: "always", "none" — plus
// "trusted" for exec only. A nil/empty table is valid.
func (f File) ValidateAuth() error {
	if len(f.Auth) == 0 {
		return nil
	}

	allowedKeys := []string{"get", "update", "delete", "exec"}
	allowedValuesCommon := map[string]bool{"always": true, "none": true}
	allowedValuesExec := map[string]bool{"always": true, "none": true, "trusted": true}

	// Validate in fixed order: get, update, delete, exec.
	for _, key := range allowedKeys {
		val, exists := f.Auth[key]
		if !exists {
			continue
		}

		if key == "exec" {
			if !allowedValuesExec[val] {
				return fmt.Errorf(`[auth] exec: invalid value "%s" (allowed: always, none, trusted)`, val)
			}
		} else {
			if !allowedValuesCommon[val] {
				return fmt.Errorf(`[auth] %s: invalid value "%s" (allowed: always, none)`, key, val)
			}
		}
	}

	// Detect unknown keys in deterministic order.
	var unknownKeys []string
	for key := range f.Auth {
		found := false
		for _, allowed := range allowedKeys {
			if key == allowed {
				found = true
				break
			}
		}
		if !found {
			unknownKeys = append(unknownKeys, key)
		}
	}
	if len(unknownKeys) > 0 {
		sort.Strings(unknownKeys)
		return fmt.Errorf(`[auth] unknown key "%s" (allowed: get, update, delete, exec)`, unknownKeys[0])
	}

	return nil
}
