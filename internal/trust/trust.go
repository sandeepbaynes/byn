// Package trust is the shared reader/writer for the TOFU trust store
// (`<data-dir>/trusted_byn.json`) that records which `.byn` project files the
// user has approved. The CLI establishes trust (`byn trust`); the daemon
// reads it (so the portal can show the trust list) and can revoke an entry.
//
// The on-disk format is the contract — keep it in sync with the CLI's
// writer in cmd/byn/discovery.go.
package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Filename is the trust store file inside <data-dir>.
const Filename = "trusted_byn.json"

// Record is one trusted `.byn` file: its canonical path and the SHA-256 of
// its content at the time trust was granted.
//
// Vault/FPMAC/VKMAC harden the store against forgery (see mac.go). They are
// minted by the daemon at grant time (it holds the keys) and are empty on
// records written before the hardening landed — such records are treated as
// untrusted (re-trust required). All three use `omitempty` so the on-disk
// format stays additive.
type Record struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	// Vault is the target vault whose key keys the VKMAC ("" ⇒ "default").
	Vault string `json:"vault,omitempty"`
	// FPMAC binds the record to THIS machine (machine-fingerprint key) and is
	// verifiable while the vault is locked — blocks cross-machine copies.
	FPMAC string `json:"fp_mac,omitempty"`
	// VKMAC binds the record to proof-of-password (vault-key-derived) and is
	// verified at use-time — blocks a same-UID local forge.
	VKMAC string `json:"vk_mac,omitempty"`
	// MTimeUnixNano is the .byn's modification time at grant. Part of the
	// v2 fingerprint: change-then-revert still forces re-trust. mtime is
	// forgeable (`touch -t`) — a tamper-detection SIGNAL, not a guarantee.
	MTimeUnixNano int64 `json:"mtime_unix_nano,omitempty"`
	// Snapshot is the full .byn content at grant (a manifest, not a
	// secret) — the diff base for `byn trust diff`.
	Snapshot string `json:"snapshot,omitempty"`
	// Actions / Auth are the policy tables parsed from the .byn AT GRANT
	// TIME and MAC-bound, so a rogue cannot edit policy post-trust.
	Actions []string          `json:"actions,omitempty"`
	Auth    map[string]string `json:"auth,omitempty"`
	// Aliases are the named entry points from the [aliases] top-level table,
	// parsed at grant time and MAC-bound like Actions/Auth so a rogue cannot
	// inject new aliases after the file is trusted.
	Aliases map[string]string `json:"aliases,omitempty"`
	// Scope* mirror the .byn's [scope] at grant — they let the daemon
	// resolve which trusted .byn governs a request scope for [auth]
	// policy lookup without re-reading the file.
	ScopeVault   string `json:"scope_vault,omitempty"`
	ScopeProject string `json:"scope_project,omitempty"`
	ScopeEnv     string `json:"scope_env,omitempty"`
}

// Store is the file content.
type Store struct {
	Records []Record `json:"records"`
}

// Load reads <dir>/trusted_byn.json. A missing file is not an error — it
// yields an empty store.
func Load(dir string) (*Store, error) {
	body, err := os.ReadFile(filepath.Join(dir, Filename)) // #nosec G304 -- daemon-controlled dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Store{}, nil
		}
		return nil, err
	}
	var s Store
	if jerr := json.Unmarshal(body, &s); jerr != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", Filename, jerr)
	}
	return &s, nil
}

// Save writes the store back atomically (write + rename) with mode 0600.
func Save(dir string, s *Store) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, Filename)
	tmp := path + ".tmp"
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if werr := os.WriteFile(tmp, body, 0o600); werr != nil {
		return werr
	}
	return os.Rename(tmp, path)
}

// Remove drops the record whose Path matches exactly. Returns whether
// anything was removed. The caller passes a path taken from a prior Load, so
// no path canonicalization is needed here.
func Remove(dir, path string) (bool, error) {
	s, err := Load(dir)
	if err != nil {
		return false, err
	}
	out := s.Records[:0]
	removed := false
	for _, r := range s.Records {
		if r.Path == path {
			removed = true
			continue
		}
		out = append(out, r)
	}
	if !removed {
		return false, nil
	}
	s.Records = out
	return true, Save(dir, s)
}

// Hash returns the lowercase hex SHA-256 of a `.byn` file's content. It is the
// TOFU fingerprint stored in a Record and recomputed on every discovery.
func Hash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Canonicalize normalizes a path via filepath.EvalSymlinks so stored records
// survive symlinked /tmp on macOS, ~ shortcuts, and dotted segments. Falls
// back to filepath.Abs when EvalSymlinks fails (e.g. the file no longer
// exists — relevant only when revoking trust for a deleted file).
func Canonicalize(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	abs, _ := filepath.Abs(path)
	return abs
}

// Stat is the trust status of a `.byn` path relative to the store.
type Stat int

const (
	// StatusUntrusted means no record exists for the path (first use).
	StatusUntrusted Stat = iota
	// StatusTrusted means a record exists and its hash matches the current
	// content.
	StatusTrusted
	// StatusChanged means a record exists but the content hash differs — the
	// file changed since trust was granted, so it must be explicitly re-approved.
	StatusChanged
)

// String renders the status for messages and logs.
func (s Stat) String() string {
	switch s {
	case StatusTrusted:
		return "trusted"
	case StatusChanged:
		return "changed"
	default:
		return "untrusted"
	}
}

// Status reports whether the given canonical path + content hash is Trusted,
// Changed (known path, different hash), or Untrusted (unknown path). It is the
// read side used by `.byn` discovery; it never mutates the store.
func Status(dir, path, hash string) (Stat, error) {
	s, err := Load(dir)
	if err != nil {
		return StatusUntrusted, err
	}
	for _, r := range s.Records {
		if r.Path == path {
			if r.SHA256 == hash {
				return StatusTrusted, nil
			}
			return StatusChanged, nil
		}
	}
	return StatusUntrusted, nil
}
