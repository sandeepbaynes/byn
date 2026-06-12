package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// TokenFilename is the name of the portal owner-token file inside the
	// byn data directory. The file is created with mode 0600 so only the
	// owner (daemon UID) can read it — reading the file proves same-UID.
	TokenFilename = "portal.token"

	// tokenBytes is the number of random bytes in the token. 32 bytes gives
	// 256 bits of entropy (hex-encoded to 64 printable characters).
	tokenBytes = 32
)

// LoadOrCreateToken loads the portal owner-token from tokenPath, creating it
// (mode 0600) if it does not yet exist. The token is 32 random bytes encoded
// as a lowercase hex string (64 characters). It is created once and persisted
// across daemon restarts so that a browser tab with the token in localStorage
// keeps working after a daemon restart.
//
// Reading the file proves same-UID: the file is 0600 and owned by the daemon
// user, so another UID cannot read it even if they reach the loopback socket.
func LoadOrCreateToken(tokenPath string) (string, error) {
	// Happy path: file already exists.
	if data, err := os.ReadFile(tokenPath); err == nil { // #nosec G304 -- daemon-owned dir, caller-controlled path
		tok := string(data)
		if len(tok) != hex.EncodedLen(tokenBytes) {
			// Corrupted / truncated — regenerate.
			return createToken(tokenPath)
		}
		return tok, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("ui: read token %s: %w", tokenPath, err)
	}
	return createToken(tokenPath)
}

// createToken writes a freshly-generated token to tokenPath at mode 0600
// and returns it. The write is atomic on the same filesystem via O_CREATE|O_EXCL
// — if two processes race to create it (daemon restart race) the winner's
// token wins and the loser's write fails; both return the on-disk token.
func createToken(tokenPath string) (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("ui: generate token: %w", err)
	}
	tok := hex.EncodeToString(raw)

	// O_EXCL ensures only one writer wins the race.
	f, err := os.OpenFile(tokenPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- daemon-owned dir, caller-controlled path
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Another writer won the race; read what they wrote.
			data, rerr := os.ReadFile(tokenPath) // #nosec G304 -- daemon-owned dir, caller-controlled path
			if rerr != nil {
				return "", fmt.Errorf("ui: read token after race: %w", rerr)
			}
			// Fail-closed: if the race-winner wrote a truncated/empty file
			// (e.g. crash between O_EXCL create and write), regenerate it
			// atomically so the gate never opens with a zero-length token.
			if len(data) != hex.EncodedLen(tokenBytes) {
				return overwriteToken(tokenPath, tok)
			}
			return string(data), nil
		}
		return "", fmt.Errorf("ui: create token %s: %w", tokenPath, err)
	}
	if _, err := fmt.Fprint(f, tok); err != nil {
		_ = f.Close()
		_ = os.Remove(tokenPath)
		return "", fmt.Errorf("ui: write token: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tokenPath)
		return "", fmt.Errorf("ui: close token: %w", err)
	}
	return tok, nil
}

// overwriteToken replaces the token file at tokenPath atomically (write to a
// temp file in the same directory, then rename over). Used when the race-read
// path finds a zero-length or truncated file (crash between O_EXCL create and
// write). Returns newTok on success.
func overwriteToken(tokenPath, newTok string) (string, error) {
	dir := filepath.Dir(tokenPath)
	tmp, err := os.CreateTemp(dir, ".portal.token.tmp") // #nosec G304 -- daemon-owned dir
	if err != nil {
		return "", fmt.Errorf("ui: overwrite token (tmp create): %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("ui: overwrite token (chmod): %w", err)
	}
	if _, err := fmt.Fprint(tmp, newTok); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("ui: overwrite token (write): %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("ui: overwrite token (close): %w", err)
	}
	if err := os.Rename(tmpPath, tokenPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("ui: overwrite token (rename): %w", err)
	}
	return newTok, nil
}

// tokenMatches performs a constant-time comparison of got against the expected
// portal token. Returns true only when both the length and every byte match.
// Using crypto/subtle prevents timing side-channels.
func tokenMatches(expected, got string) bool {
	return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}
