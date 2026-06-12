package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestRunUnlock_NoTTY_NoSessionFile verifies that when ttyRdev()==0 (no
// controlling terminal — the common case in CI / agent callers),
// saveSessionToken is a no-op and no session file is written to disk.
//
// Security invariant: non-interactive callers (ttyDev==0) must NOT get a
// persistent ambient session. A shared ".latest"-style file would grant every
// same-UID process the session minted by the last non-TTY unlock — exactly
// recreating the ambient authority the no-global-unlock model is designed to
// prevent. Non-TTY callers must supply per-action credentials (--password-stdin)
// or use a pinned action via a trusted .byn file.
func TestRunUnlock_NoTTY_NoSessionFile(t *testing.T) {
	if ttyRdev() != 0 {
		t.Skip("skipping: controlling terminal present; test requires ttyRdev()==0")
	}
	dir := t.TempDir()

	// Verify: saveSessionToken with ttyRdev()==0 creates no file.
	tok := []byte("deadbeef11223344556677889900aabbccddeeff00112233445566778899aabb")
	err := saveSessionToken(dir, "default", tok)
	if err != nil {
		t.Fatalf("saveSessionToken: %v", err)
	}
	// No session file should exist because ttyRdev()==0.
	entries, _ := os.ReadDir(filepath.Join(dir, "sessions"))
	if len(entries) != 0 {
		t.Errorf("expected no session files when ttyRdev()==0, got %d: %v", len(entries), entries)
	}
	// loadSessionToken must also return nil — no ambient session for non-TTY callers.
	loaded := loadSessionToken(dir, "default")
	if loaded != nil {
		t.Errorf("loadSessionToken with ttyRdev()==0 = %q, want nil", loaded)
	}
}

// TestRunUnlock_NoTTY_PlainMessage verifies that when ttyRdev()==0,
// runUnlock prints the plain "vault unlocked" message, NOT "session active".
func TestRunUnlock_NoTTY_PlainMessage(t *testing.T) {
	if ttyRdev() != 0 {
		t.Skip("skipping: controlling terminal present; test requires ttyRdev()==0")
	}
	fd := startFakeDaemon(t)
	tok := []byte("deadbeef11223344556677889900aabbccddeeff00112233445566778899aabb")
	fd.onOK(ipc.OpVaultUnlock, ipc.VaultUnlockResp{SessionToken: tok})

	// Provide password via stdin so we don't block on a TTY prompt.
	withStdin(t, "testpassword\n")

	// Enable hints so we can capture any hint output.
	t.Setenv("BYN_HINTS", "1")

	stderr := captureStderr(t, func() {
		got := runUnlock([]string{"--password-stdin"}, cliScope{})
		if got != exitOK {
			t.Errorf("runUnlock = %d, want exitOK", got)
		}
	})

	if strings.Contains(stderr, "session active") {
		t.Errorf("non-TTY unlock must not print 'session active', got: %q", stderr)
	}
}
