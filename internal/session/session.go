package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/paths"
)

// Dir returns the sessions subdirectory: <data-dir>/sessions/
func Dir(dataDir string) string {
	return filepath.Join(dataDir, "sessions")
}

// StoreDir returns the directory the session-token functions should use.
// Session tokens are a CLIENT-side, per-terminal artifact written by the OWNER's
// CLI (the daemon receives the token over IPC — it never reads the file). On a
// PROVISIONED install the data dir is the _byn-owned system tree the owner can't
// write, so tokens go under the owner's ~/.byn instead. Non-provisioned installs
// (data dir already owner-writable) keep using the data dir, preserving behavior
// — including a custom BYN_DIR. Falls back to dataDir if the home is unknown.
func StoreDir(dataDir string) string {
	if provisioned, _ := paths.ProvisionedIn(dataDir); provisioned {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".byn")
		}
	}
	return dataDir
}

// fileNameFor returns the hex-encoded SHA-256[:16] (32 hex chars) of
// "ttyDev\x00vault". The file stores the raw session token bytes.
// Exported for use in tests (pass ttyDev directly to avoid /dev/tty dependency).
func fileNameFor(ttyDev int32, vault string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d\x00%s", ttyDev, vault)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// loadTokenWithDev reads the session token for ttyDev + vault.
// Returns nil if: ttyDev==0, file missing, or any error.
func loadTokenWithDev(bynDir string, ttyDev int32, vault string) []byte {
	if ttyDev == 0 {
		return nil
	}
	path := filepath.Join(Dir(bynDir), fileNameFor(ttyDev, vault))
	data, err := os.ReadFile(path) // #nosec G304 -- path is under bynDir, controlled by the user
	if err != nil {
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return data
}

// saveTokenWithDev writes token to sessions/<hash> with mode 0600.
// No-op when ttyDev==0 or token is empty.
func saveTokenWithDev(bynDir string, ttyDev int32, vault string, token []byte) error {
	if ttyDev == 0 || len(token) == 0 {
		return nil
	}
	dir := Dir(bynDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("sessions: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, fileNameFor(ttyDev, vault))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304,G302 -- explicit 0600, user-controlled dir
	if err != nil {
		return fmt.Errorf("sessions: create %s: %w", path, err)
	}
	_, werr := f.Write(token)
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("sessions: write %s: %w", path, werr)
	}
	return cerr
}

// deleteTokenWithDev removes the session file for ttyDev + vault.
// No-op if file doesn't exist or ttyDev==0.
func deleteTokenWithDev(bynDir string, ttyDev int32, vault string) {
	if ttyDev == 0 {
		return
	}
	path := filepath.Join(Dir(bynDir), fileNameFor(ttyDev, vault))
	_ = os.Remove(path)
}

// LoadToken reads the session token for the current TTY + vault.
// Returns nil when the process has no controlling terminal (ttyRdev()==0):
// non-interactive callers have no TTY binding and therefore no persistent
// session — they must supply per-action credentials (--password-stdin) or
// use a pinned exec action via a trusted .byn file.
func LoadToken(bynDir, vault string) []byte {
	return loadTokenWithDev(bynDir, ttyRdev(), vault)
}

// SaveToken writes the token to sessions/<hash> with mode 0600.
// When ttyRdev()==0 (no controlling terminal) the call is a no-op:
// non-interactive callers have no TTY to bind the session to, and writing
// a shared uid-only session file would recreate ambient authority for every
// same-UID agent process — exactly the threat the no-global-unlock model
// is designed to prevent.
func SaveToken(bynDir, vault string, token []byte) error {
	return saveTokenWithDev(bynDir, ttyRdev(), vault, token)
}

// DeleteToken removes the session file for the current TTY + vault.
func DeleteToken(bynDir, vault string) {
	deleteTokenWithDev(bynDir, ttyRdev(), vault)
}

// DeleteAllTokens removes every file in the sessions directory.
func DeleteAllTokens(bynDir string) {
	dir := Dir(bynDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// VaultKey returns the vault name to use as the session file key.
// An empty vault name (meaning "default") is normalized to "default".
func VaultKey(vault string) string {
	if vault == "" {
		return "default"
	}
	return vault
}

// SaveTokenForThisTTY stores a token against the terminal the caller is sitting
// at, and reports whether there was a terminal to key it to.
//
// The tty device number stays inside this package. It is the thing that makes a
// session per-terminal rather than per-user — two shells on one machine hold
// different sessions — and a caller that had to fetch it itself would be one
// refactor away from keying a session to the wrong thing, or to nothing.
func SaveTokenForThisTTY(bynDir, vault string, token []byte) (saved bool, err error) {
	dev := ttyRdev()
	if dev == 0 {
		return false, nil
	}
	return true, saveTokenWithDev(bynDir, dev, vault, token)
}

// HasTTY reports whether the caller has a controlling terminal to key a session
// to.
//
// Exported because "is there a terminal" is a question callers legitimately ask
// — a session is per-terminal, so with no terminal there is nowhere to put one —
// while the device number behind it stays private. A caller holding the raw
// device number is one refactor away from keying a session to the wrong thing.
func HasTTY() bool { return ttyRdev() != 0 }

// TokenPathForThisTTY returns the file a session for this terminal lives in,
// and whether there is a terminal at all.
//
// Exists so callers and tests can find the file without reconstructing the
// naming rule. A test that rebuilds the path from the same pieces the code uses
// asserts that two copies of one expression agree, which they will even when
// both are wrong.
func TokenPathForThisTTY(bynDir, vault string) (string, bool) {
	dev := ttyRdev()
	if dev == 0 {
		return "", false
	}
	return filepath.Join(bynDir, fileNameFor(dev, vault)), true
}
