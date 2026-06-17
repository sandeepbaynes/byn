package privsep

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ExecToolchainDefaults are home-RELATIVE tool-state / cache directories that
// dev toolchains commonly read+write, which the privsep exec child (_byn-exec, a
// different UID) cannot reach on its own — especially under macOS's 0700
// ~/Library. byn auto-grants `_byn-exec` access to those of these that EXIST at
// trust time (non-existent ones are skipped). The list is intentionally broad
// (multi-language) but limited to caches/stores/config — never secret stores
// like ~/.ssh, ~/.aws, ~/.gnupg (those must be declared explicitly via
// [exec] writable). Cross-platform: macOS-only entries (Library/*) simply don't
// exist on Linux and are skipped.
var ExecToolchainDefaults = []string{
	// JS / Node / pnpm / yarn
	".npm", ".yarn", ".pnpm-store",
	"Library/pnpm", "Library/Preferences/pnpm",
	// XDG (Linux + many macOS tools)
	".cache", ".config", ".local/share", ".local/state",
	"Library/Caches",
	// Rust
	".cargo", ".rustup",
	// Go
	"go",
	// JVM
	".gradle", ".m2",
}

// SensitiveHomeDirs are home-relative paths that hold credentials/keys. byn never
// puts them in ExecToolchainDefaults and warns when a .byn declares one in
// [exec] writable (the owner can still grant it — trust is password-gated — but
// it should be a conscious choice).
var SensitiveHomeDirs = map[string]struct{}{
	".ssh":       {},
	".aws":       {},
	".gnupg":     {},
	".config/gh": {},
	".kube":      {},
	".docker":    {},
}

// GrantExecDirsACL grants the _byn-exec service user read/write access to each
// (absolute) dir plus traverse on its ancestors up to home — the same ACE shape
// as a project grant, reused for tool-state dirs. Best-effort: it continues past
// a per-dir failure (e.g. a non-existent dir) and returns the FIRST error so the
// caller can log it without failing the trust.
func GrantExecDirsACL(run func(name string, args ...string) error, dirs []string, home string) error {
	var firstErr error
	for _, d := range dirs {
		if err := GrantProjectACL(run, d, home); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ResolveWritableUnderHome validates a .byn [exec] writable entry and returns its
// cleaned ABSOLUTE path. A leading "~" (or "~/") expands to home; a relative path
// is taken relative to home. The result MUST be under home — anything that
// escapes (system dirs, other users' homes, "..") is refused. This stops a
// trusted .byn from granting _byn-exec access outside the owner's own home.
func ResolveWritableUnderHome(entry, home string) (string, error) {
	if entry == "" {
		return "", fmt.Errorf("empty writable entry")
	}
	home = filepath.Clean(home)
	var abs string
	switch {
	case entry == "~":
		abs = home
	case strings.HasPrefix(entry, "~/"):
		abs = filepath.Join(home, entry[2:])
	case filepath.IsAbs(entry):
		abs = filepath.Clean(entry)
	default:
		abs = filepath.Join(home, entry)
	}
	abs = filepath.Clean(abs)
	// Must be home itself or strictly under it.
	if abs != home && !strings.HasPrefix(abs, home+string(filepath.Separator)) {
		return "", fmt.Errorf("writable %q is not under home %q", entry, home)
	}
	return abs, nil
}

// IsSensitiveHomeDir reports whether abs is (or is inside) a known credential
// directory under home — used to warn when a .byn declares one in [exec] writable.
func IsSensitiveHomeDir(abs, home string) bool {
	home = filepath.Clean(home)
	for rel := range SensitiveHomeDirs {
		s := filepath.Join(home, rel)
		if abs == s || strings.HasPrefix(abs, s+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
