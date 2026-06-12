package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// sessionDir returns the sessions subdirectory: $BYN_DIR/sessions/
func sessionDir(bynDir string) string {
	return filepath.Join(bynDir, "sessions")
}

// sessionFileNameFor returns the hex-encoded SHA-256[:16] (32 hex chars) of
// "ttyDev\x00vault". The file stores the raw session token bytes.
// Exported for use in tests (pass ttyDev directly to avoid /dev/tty dependency).
func sessionFileNameFor(ttyDev int32, vault string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d\x00%s", ttyDev, vault)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// loadSessionTokenWithDev reads the session token for ttyDev + vault.
// Returns nil if: ttyDev==0, file missing, or any error.
func loadSessionTokenWithDev(bynDir string, ttyDev int32, vault string) []byte {
	if ttyDev == 0 {
		return nil
	}
	path := filepath.Join(sessionDir(bynDir), sessionFileNameFor(ttyDev, vault))
	data, err := os.ReadFile(path) // #nosec G304 -- path is under bynDir, controlled by the user
	if err != nil {
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return data
}

// saveSessionTokenWithDev writes token to sessions/<hash> with mode 0600.
// No-op when ttyDev==0 or token is empty.
func saveSessionTokenWithDev(bynDir string, ttyDev int32, vault string, token []byte) error {
	if ttyDev == 0 || len(token) == 0 {
		return nil
	}
	dir := sessionDir(bynDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("sessions: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, sessionFileNameFor(ttyDev, vault))
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

// deleteSessionTokenWithDev removes the session file for ttyDev + vault.
// No-op if file doesn't exist or ttyDev==0.
func deleteSessionTokenWithDev(bynDir string, ttyDev int32, vault string) {
	if ttyDev == 0 {
		return
	}
	path := filepath.Join(sessionDir(bynDir), sessionFileNameFor(ttyDev, vault))
	_ = os.Remove(path)
}

// loadSessionToken reads the session token for the current TTY + vault.
// Returns nil when the process has no controlling terminal (ttyRdev()==0):
// non-interactive callers have no TTY binding and therefore no persistent
// session — they must supply per-action credentials (--password-stdin) or
// use a pinned exec action via a trusted .byn file.
func loadSessionToken(bynDir, vault string) []byte {
	return loadSessionTokenWithDev(bynDir, ttyRdev(), vault)
}

// saveSessionToken writes the token to sessions/<hash> with mode 0600.
// When ttyRdev()==0 (no controlling terminal) the call is a no-op:
// non-interactive callers have no TTY to bind the session to, and writing
// a shared uid-only session file would recreate ambient authority for every
// same-UID agent process — exactly the threat the no-global-unlock model
// is designed to prevent.
func saveSessionToken(bynDir, vault string, token []byte) error {
	return saveSessionTokenWithDev(bynDir, ttyRdev(), vault, token)
}

// deleteSessionToken removes the session file for the current TTY + vault.
func deleteSessionToken(bynDir, vault string) {
	deleteSessionTokenWithDev(bynDir, ttyRdev(), vault)
}

// deleteAllSessionTokens removes every file in the sessions directory.
func deleteAllSessionTokens(bynDir string) {
	dir := sessionDir(bynDir)
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

// vaultSessionKey returns the vault name to use as the session file key.
// An empty vault name (meaning "default") is normalized to "default".
func vaultSessionKey(vault string) string {
	if vault == "" {
		return "default"
	}
	return vault
}
