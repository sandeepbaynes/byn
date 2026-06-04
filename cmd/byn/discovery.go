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
//   [scope]
//   vault   = "default"
//   project = "myapp"
//   env     = "dev"
//
// TOFU: the first time we see a given path, we hash its full content
// with SHA-256 and store {path, hash, sha256} in
// ~/.byn/trusted_byn.json. On subsequent runs we recompute and
// require an exact match; if it differs, we refuse to apply the scope
// and tell the user to re-trust.
//
// `byn trust`, `byn trust list`, `byn untrust` manage the
// trust file from the CLI.
//
// Hard-fail in agent mode: when --json or BYN_HINTS=0 is set, an
// untrusted .byn is a hard error instead of an interactive prompt
// — so an agent can never silently auto-trust a malicious file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const (
	discoveryFile = ".byn"
	trustFile     = "trusted_byn.json"
)

// dotBynScope is the on-disk format. Unknown keys fail (strict
// parser, Decode with DisallowUnknownFields).
type dotBynScope struct {
	Scope struct {
		Vault   string `toml:"vault,omitempty"`
		Project string `toml:"project,omitempty"`
		Env     string `toml:"env,omitempty"`
	} `toml:"scope"`
}

// trustRecord is one entry in trusted_byn.json.
type trustRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// trustStore is the file content.
type trustStore struct {
	Records []trustRecord `json:"records"`
}

// discoverScope walks parents from CWD looking for a .byn. Returns
// (scope, sourcePath) on success. If no file is found, returns empty
// scope and "". On a TOFU mismatch or untrusted-in-agent-mode, returns
// an error.
//
// agentMode: when true, untrusted files are an error (no prompt).
//
// stopHome: the user's home dir; the walk does not go above this.
func discoverScope(startDir, homeDir, bynDir string, agentMode bool) (cliScope, string, error) {
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
			// Trust check.
			trusted, terr := isTrusted(bynDir, candidate, body)
			if terr != nil {
				return cliScope{}, "", terr
			}
			if !trusted {
				if agentMode {
					return cliScope{}, "", fmt.Errorf(
						"%s: untrusted .byn (agent mode); run `byn trust %s` from a terminal first",
						candidate, candidate)
				}
				// Interactive prompt — but only when stdin is a TTY.
				if !stdinIsTTY() {
					return cliScope{}, "", fmt.Errorf(
						"%s: untrusted .byn; run `byn trust %s` to allow it",
						candidate, candidate)
				}
				if perr := promptAndTrust(bynDir, candidate, body); perr != nil {
					return cliScope{}, "", perr
				}
			}
			// Parse.
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

// loadTrustStore reads ~/.byn/trusted_byn.json; if missing,
// returns an empty store with no error.
func loadTrustStore(bynDir string) (*trustStore, error) {
	path := filepath.Join(bynDir, trustFile)
	body, err := os.ReadFile(path) // #nosec G304 -- daemon dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &trustStore{}, nil
		}
		return nil, err
	}
	var ts trustStore
	if jerr := json.Unmarshal(body, &ts); jerr != nil {
		return nil, fmt.Errorf("%s: %w", path, jerr)
	}
	return &ts, nil
}

// saveTrustStore writes the store back to disk atomically (write+rename)
// with mode 0600.
func saveTrustStore(bynDir string, ts *trustStore) error {
	if err := os.MkdirAll(bynDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(bynDir, trustFile)
	tmp := path + ".tmp"
	body, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func hashBynFile(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// canonicalize normalizes a path via filepath.EvalSymlinks so that
// stored trust records survive symlinked /tmp on macOS, ~ shortcuts,
// and dotted segments. Falls back to filepath.Abs if EvalSymlinks
// fails (e.g., the path doesn't exist yet — relevant only for
// untrust, where the file may have been deleted).
func canonicalize(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	abs, _ := filepath.Abs(path)
	return abs
}

// isTrusted reports whether the given path+content matches a record.
// Returns (true, nil) on match, (false, nil) on absent/mismatch, error
// only on storage failure.
func isTrusted(bynDir, path string, body []byte) (bool, error) {
	ts, err := loadTrustStore(bynDir)
	if err != nil {
		return false, err
	}
	want := hashBynFile(body)
	key := canonicalize(path)
	for _, r := range ts.Records {
		if r.Path == key {
			return r.SHA256 == want, nil
		}
	}
	return false, nil
}

// addTrust inserts or updates a record for path with the current
// content's SHA-256.
func addTrust(bynDir, path string, body []byte) error {
	ts, err := loadTrustStore(bynDir)
	if err != nil {
		return err
	}
	key := canonicalize(path)
	rec := trustRecord{Path: key, SHA256: hashBynFile(body)}
	found := false
	for i, r := range ts.Records {
		if r.Path == key {
			ts.Records[i] = rec
			found = true
			break
		}
	}
	if !found {
		ts.Records = append(ts.Records, rec)
	}
	return saveTrustStore(bynDir, ts)
}

// removeTrust drops a path's record. Returns whether anything was removed.
func removeTrust(bynDir, path string) (bool, error) {
	ts, err := loadTrustStore(bynDir)
	if err != nil {
		return false, err
	}
	key := canonicalize(path)
	out := ts.Records[:0]
	removed := false
	for _, r := range ts.Records {
		if r.Path == key {
			removed = true
			continue
		}
		out = append(out, r)
	}
	if !removed {
		return false, nil
	}
	ts.Records = out
	return true, saveTrustStore(bynDir, ts)
}

// promptAndTrust asks the user to allow this file (y/N) and records
// trust on yes. Only called interactively.
func promptAndTrust(bynDir, candidate string, body []byte) error {
	fmt.Fprintf(os.Stderr, "%s byn found %s — trust it?\n", boldYellow("Prompt:"), candidate)
	fmt.Fprintln(os.Stderr, dim("  (content will be hashed; future runs require an exact match)"))
	fmt.Fprint(os.Stderr, "  trust [y/N]: ")
	var answer string
	if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
		// blank line = N
		answer = "n"
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		return fmt.Errorf("refused trust for %s — re-run with --no-discovery or `byn trust %s`", candidate, candidate)
	}
	return addTrust(bynDir, candidate, body)
}

func stdinIsTTY() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
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
