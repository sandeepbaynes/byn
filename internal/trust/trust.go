// Package trust is the shared reader/writer for the TOFU trust store
// (`<BYN_DIR>/trusted_byn.json`) that records which `.byn` project files the
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

// Filename is the trust store file inside $BYN_DIR.
const Filename = "trusted_byn.json"

// Record is one trusted `.byn` file: its canonical path and the SHA-256 of
// its content at the time trust was granted.
type Record struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
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

// Grant inserts or updates the trust record for a canonical path. It reports
// changed=true only when a record already existed with a *different* hash
// (the file changed since it was last trusted) — letting callers warn loudly
// on a re-trust versus a first-time grant. Granting an identical hash is a
// no-op (changed=false, no write). The caller is responsible for authorizing
// the grant (the daemon gates it on the master password); this function is
// the storage primitive only.
func Grant(dir, path, hash string) (changed bool, err error) {
	s, err := Load(dir)
	if err != nil {
		return false, err
	}
	for i, r := range s.Records {
		if r.Path == path {
			if r.SHA256 == hash {
				return false, nil // already trusted, identical content
			}
			s.Records[i].SHA256 = hash
			return true, Save(dir, s)
		}
	}
	s.Records = append(s.Records, Record{Path: path, SHA256: hash})
	return false, Save(dir, s)
}
