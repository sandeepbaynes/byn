// Package trust is the shared reader/writer for the TOFU trust store
// (`<BYN_DIR>/trusted_byn.json`) that records which `.byn` project files the
// user has approved. The CLI establishes trust (`byn trust`); the daemon
// reads it (so the portal can show the trust list) and can revoke an entry.
//
// The on-disk format is the contract — keep it in sync with the CLI's
// writer in cmd/byn/discovery.go.
package trust

import (
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
