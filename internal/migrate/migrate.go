// Package migrate adopts a byn vault tree from some source into the daemon's
// system data root. NU-6 ships only the SOURCE seam (this file + a local-FS
// implementation); the verify/adopt/relocate core that consumes it lands in a
// later task.
//
// The contract is deliberately small. An [ImportSource] answers two questions —
// "which artifacts are here?" ([ImportSource.List]) and "give me one of them"
// ([ImportSource.Open]) — so the future adopt core is agnostic to WHERE a vault
// comes from. NU-6 plugs in a local directory ([LocalSource]); later work can
// plug in an archive (.tar), a remote (scp/ssh), or a cloud source with no
// change to the adopt core. Per the project's pluggability rule it is a
// candidate to be exported out of internal/ for cloud-sync providers later.
package migrate

import (
	"io"
	"strings"
)

// ImportSource abstracts WHERE a byn vault's artifacts come from so the future
// adopt/verify core (byn migrate) is source-agnostic.
//
// A source exposes only the byn STATE artifacts (see [IsStateArtifact]) — the
// data a vault is made of — and never the ephemera a running daemon leaves
// behind (socket, pidfile, log, portal token, rate-limiter state, owner record,
// per-tty sessions; see [IsEphemeral]). Adopting ephemera would carry a stale
// socket/pidfile/token into the destination, so the seam filters it at the
// source rather than trusting every caller to remember.
type ImportSource interface {
	// List returns the relative paths of the byn state artifacts present at the
	// source. Paths are slash-relative to the source root and never include
	// ephemera. The set spans:
	//   - vaults/<name>/vault.db    — the encrypted SQLite vault (this also
	//                                 carries that vault's passkey enrollments,
	//                                 which live in its `passkey`/`passkey_unlock`
	//                                 tables, NOT as separate files)
	//   - vaults/<name>/wrapped.key — the password-wrapped vault key
	//   - vaults/<name>/meta.json   — per-vault metadata
	//   - audit/<vault>/<YYYY-MM>.log — append-only audit logs
	//   - trusted_byn.json          — the trust store (root-level)
	//   - config                    — the daemon config (root-level)
	List() ([]string, error)

	// Open returns a reader for one artifact by its source-relative path (as
	// returned by List). The caller closes it. Implementations MUST reject a
	// path that escapes the source root (absolute paths, "..").
	Open(rel string) (io.ReadCloser, error)
}

// Root-level state artifact basenames. These mirror the canonical constants in
// internal/trust (trusted_byn.json) and internal/config (config); they are
// re-declared here so internal/migrate carries no dependency on those packages
// for a pair of string literals. A drift would be caught by adopt-side
// verification (the trust store / config must parse), but keep them in sync.
const (
	// TrustStoreFilename is the root-level trust store (which `.byn` files are
	// trusted). Mirrors trust.Filename.
	TrustStoreFilename = "trusted_byn.json"
	// ConfigFilename is the root-level daemon config. Mirrors config.Filename.
	ConfigFilename = "config"
	// VaultsSubdir holds the per-vault subtrees. Mirrors vault.VaultsSubdir.
	VaultsSubdir = "vaults"
	// AuditSubdir holds the per-vault audit logs.
	AuditSubdir = "audit"
)

// rootStateFiles is the set of root-level files that are byn state (as opposed
// to ephemera). Subtrees (vaults/, audit/) are handled structurally, not by
// this set.
var rootStateFiles = map[string]struct{}{
	TrustStoreFilename: {},
	ConfigFilename:     {},
}

// ephemera is the set of root-level basenames a running daemon writes that are
// NOT vault state and must never be carried across a migrate: the Unix socket,
// pidfile, daemon log, portal bootstrap token, auth rate-limiter state, the
// owner-UID record (re-recorded by `byn setup` at the destination), and the
// atomic-write temp files those use. The per-tty `sessions/` subdir is also
// ephemeral (handled in IsEphemeral by prefix).
var ephemera = map[string]struct{}{
	"daemon.sock":     {}, // daemon.SocketFilename
	"daemon.pid":      {}, // daemon.PIDFilename
	"daemon.log":      {}, // rotating daemon stdout/stderr log
	"portal.token":    {}, // ui.TokenFilename — re-minted over the socket
	"auth-state.json": {}, // auth.RateLimiterFile — rate-limiter counters
	"owner":           {}, // privsep owner-UID record — re-written by setup
}

// SessionsSubdir holds per-tty unlock session tokens — ephemeral, never
// migrated.
const SessionsSubdir = "sessions"

// IsEphemeral reports whether a source-root-relative path is daemon ephemera
// that a migrate must skip (rather than a byn state artifact). It is the shared
// contract the adopt/relocate core (later task) reuses so "what do we carry"
// has a single definition.
//
// A path is ephemeral if its top-level segment is the sessions/ subdir, or its
// basename is a known ephemeral file, or it is an atomic-write temp file (a
// leading dot with a .tmp marker, as written by ui.token / privsep.ownerrec via
// os.CreateTemp(dir, ".<name>.tmp")).
func IsEphemeral(rel string) bool {
	rel = normalizeRel(rel)
	if rel == "" {
		return false
	}
	// sessions/ subtree.
	if rel == SessionsSubdir || strings.HasPrefix(rel, SessionsSubdir+"/") {
		return true
	}
	base := rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		base = rel[i+1:]
	}
	if _, ok := ephemera[base]; ok {
		return true
	}
	// Atomic-write temp files: os.CreateTemp(dir, ".portal.token.tmp") and
	// kin produce a dot-prefixed name containing ".tmp".
	if strings.HasPrefix(base, ".") && strings.Contains(base, ".tmp") {
		return true
	}
	return false
}

// IsStateArtifact reports whether a source-root-relative path is a byn state
// artifact that a migrate carries. It is the positive counterpart to
// [IsEphemeral]: a root-level file in [rootStateFiles], or any file under the
// vaults/ or audit/ subtrees, that is not itself ephemera. Directories are not
// artifacts (only the files within them are listed).
func IsStateArtifact(rel string) bool {
	rel = normalizeRel(rel)
	if rel == "" || IsEphemeral(rel) {
		return false
	}
	if _, ok := rootStateFiles[rel]; ok {
		return true
	}
	if strings.HasPrefix(rel, VaultsSubdir+"/") || strings.HasPrefix(rel, AuditSubdir+"/") {
		return true
	}
	return false
}
