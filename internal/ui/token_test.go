package ui

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadOrCreateToken_CreatesFile verifies that LoadOrCreateToken creates a
// token file at the expected path when it doesn't exist.
func TestLoadOrCreateToken_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, TokenFilename)

	tok, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("LoadOrCreateToken: %v", err)
	}
	if len(tok) != hex.EncodedLen(tokenBytes) {
		t.Errorf("token length = %d, want %d", len(tok), hex.EncodedLen(tokenBytes))
	}
	// File must exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("token file not created: %v", err)
	}
}

// TestLoadOrCreateToken_FileMode verifies that the token file is created with
// mode 0600 (owner-only read/write).
func TestLoadOrCreateToken_FileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, TokenFilename)

	if _, err := LoadOrCreateToken(path); err != nil {
		t.Fatalf("LoadOrCreateToken: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("token file mode = %o, want 0600", got)
	}
}

// TestLoadOrCreateToken_Idempotent verifies that a second call to
// LoadOrCreateToken returns the same token without overwriting the file.
func TestLoadOrCreateToken_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, TokenFilename)

	tok1, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	tok2, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if tok1 != tok2 {
		t.Errorf("token changed between calls: %q != %q", tok1, tok2)
	}
}

// TestLoadOrCreateToken_Reused simulates a daemon restart: the token file
// written in one call is read back identically in the next, so browser
// localStorage keeps working across restarts.
func TestLoadOrCreateToken_Reused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, TokenFilename)

	tok, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Simulate restart by calling again — must re-read the file, not regenerate.
	got, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got != tok {
		t.Errorf("reload returned %q, want %q", got, tok)
	}
}

// TestTokenMatches_ConstantTime verifies the constant-time comparison.
func TestTokenMatches_ConstantTime(t *testing.T) {
	tok := "abc123"
	if !tokenMatches(tok, tok) {
		t.Error("tokenMatches: identical tokens must match")
	}
	if tokenMatches(tok, "wrong") {
		t.Error("tokenMatches: different tokens must not match")
	}
	if tokenMatches(tok, "") {
		t.Error("tokenMatches: empty got must not match non-empty expected")
	}
	// Both empty — ConstantTimeCompare returns 1 for equal slices, so this
	// returns true. The requireToken middleware checks s.token != "" before
	// calling tokenMatches, so empty-vs-empty only occurs in the disabled-gate
	// path which never calls tokenMatches. This case is intentionally not
	// tested via the middleware (empty token = gate disabled).
}

// TestLoadOrCreateToken_EmptyFile_Regenerates: a 0-byte portal.token file
// (written by a crasher between O_EXCL create and write) is detected and
// replaced with a valid token atomically.  The gate must never open with an
// empty token.
func TestLoadOrCreateToken_EmptyFile_Regenerates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, TokenFilename)

	// Simulate the crash: create the file but write nothing.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}

	tok, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("LoadOrCreateToken with empty file: %v", err)
	}
	if len(tok) != hex.EncodedLen(tokenBytes) {
		t.Errorf("regenerated token length = %d, want %d", len(tok), hex.EncodedLen(tokenBytes))
	}
	// File on disk must now hold the regenerated token.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read regenerated file: %v", err)
	}
	if string(data) != tok {
		t.Errorf("on-disk token %q != returned token %q", string(data), tok)
	}
}

// TestLoadOrCreateToken_ShortFile_Regenerates: a file shorter than the
// expected 64 hex chars is treated as corrupted and regenerated.
func TestLoadOrCreateToken_ShortFile_Regenerates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, TokenFilename)

	if err := os.WriteFile(path, []byte("tooshort"), 0o600); err != nil {
		t.Fatalf("create short file: %v", err)
	}

	tok, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatalf("LoadOrCreateToken with short file: %v", err)
	}
	if len(tok) != hex.EncodedLen(tokenBytes) {
		t.Errorf("regenerated token length = %d, want %d", len(tok), hex.EncodedLen(tokenBytes))
	}
	if tok == "tooshort" {
		t.Error("returned the corrupt short token instead of regenerating")
	}
}

// TestOverwriteToken_Atomic: overwriteToken replaces the file atomically and
// returns the new token.
func TestOverwriteToken_Atomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, TokenFilename)

	// Pre-create a file (simulates the crash scenario that leaves a stale file).
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("write old: %v", err)
	}

	newTok := "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd001122334"
	got, err := overwriteToken(path, newTok)
	if err != nil {
		t.Fatalf("overwriteToken: %v", err)
	}
	if got != newTok {
		t.Errorf("overwriteToken returned %q, want %q", got, newTok)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after overwrite: %v", err)
	}
	if string(data) != newTok {
		t.Errorf("on-disk %q != %q", string(data), newTok)
	}
}
