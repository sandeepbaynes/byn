package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/config"
	"github.com/sandeepbaynes/byn/internal/ui"
)

// writeConfig writes a ~/.byn/config body into the daemon's data dir.
func writeConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(config.Path(dir), []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// startBareDaemon brings up a daemon with an explicit Config and registers
// cleanup. Used by reload tests that need to start with the UI off.
func startBareDaemon(t *testing.T, cfg Config) *Daemon {
	t.Helper()
	if cfg.Dir == "" {
		cfg.Dir = shortTempDir(t)
	}
	if cfg.Version == "" {
		cfg.Version = "test"
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := d.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		d.Shutdown(2 * time.Second)
	})
	return d
}

// Reload of a changed idle_timeout updates the live value and the janitor's
// re-lock decision without a restart.
func TestReload_IdleTimeoutChange(t *testing.T) {
	d, c := startTestDaemonIdle(t, 0) // idle disabled, janitor off
	initUnlockDefault(t, c)

	writeConfig(t, d.cfg.Dir, "[ui]\nenabled = false\n[daemon]\nidle_timeout = \"15m\"\n")
	changes, err := d.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if d.idleTimeoutDur() != 15*time.Minute {
		t.Fatalf("idle timeout = %v, want 15m", d.idleTimeoutDur())
	}
	if len(changes) == 0 {
		t.Fatal("expected reload to report a change")
	}
	// The reloaded timeout now governs the janitor's decision.
	e := d.lookupVault("default")
	base := time.Unix(0, e.lastActive.Load())
	if n := d.lockIdleVaults(base.Add(16 * time.Minute)); n != 1 {
		t.Fatalf("locked %d vaults after reload+timeout, want 1", n)
	}
}

// Enabling idle_timeout via reload (when it was disabled at start) starts
// the background janitor, which then re-locks the idle vault.
func TestReload_StartsJanitorWhenEnabled(t *testing.T) {
	d, c := startTestDaemonIdle(t, 0) // janitor not started at boot
	initUnlockDefault(t, c)

	writeConfig(t, d.cfg.Dir, "[ui]\nenabled = false\n[daemon]\nidle_timeout = \"1s\"\n")
	if _, err := d.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	e := d.lookupVault("default")
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if e.store.IsLocked() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !e.store.IsLocked() {
		t.Error("janitor enabled via reload did not lock the idle vault")
	}
}

// Reload can enable the portal, move it to a new port, and disable it —
// all while the daemon keeps serving on the socket.
func TestReload_UIToggle(t *testing.T) {
	d := startBareDaemon(t, Config{}) // UI off
	if d.UIPort() != 0 {
		t.Fatalf("portal running before enable: %d", d.UIPort())
	}

	p := freePort(t)
	writeConfig(t, d.cfg.Dir, fmt.Sprintf("[ui]\nenabled = true\nport = %d\n[daemon]\nidle_timeout = \"0s\"\n", p))
	if _, err := d.Reload(); err != nil {
		t.Fatalf("Reload enable: %v", err)
	}
	if d.UIPort() != p {
		t.Fatalf("portal port = %d, want %d after enable", d.UIPort(), p)
	}

	p2 := freePort(t)
	writeConfig(t, d.cfg.Dir, fmt.Sprintf("[ui]\nenabled = true\nport = %d\n[daemon]\nidle_timeout = \"0s\"\n", p2))
	if _, err := d.Reload(); err != nil {
		t.Fatalf("Reload report: %v", err)
	}
	if d.UIPort() != p2 {
		t.Fatalf("portal port = %d, want %d after port change", d.UIPort(), p2)
	}

	writeConfig(t, d.cfg.Dir, "[ui]\nenabled = false\n[daemon]\nidle_timeout = \"0s\"\n")
	if _, err := d.Reload(); err != nil {
		t.Fatalf("Reload disable: %v", err)
	}
	if d.UIPort() != 0 {
		t.Fatalf("portal still running after disable: %d", d.UIPort())
	}
}

// A reload with no effective change reports nothing changed.
func TestReload_NoChanges(t *testing.T) {
	d := startBareDaemon(t, Config{IdleTimeout: 15 * time.Minute}) // UI off
	writeConfig(t, d.cfg.Dir, "[ui]\nenabled = false\n[daemon]\nidle_timeout = \"15m\"\n")
	changes, err := d.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("expected no changes, got %v", changes)
	}
}

// TestStartUILocked_TokenFailClosedPortalDisabled verifies the fail-closed
// contract: when the portal.token file cannot be created (because its path is
// occupied by a directory — simulating an unwritable data dir), startUILocked
// must return an error and leave uiSrv nil rather than starting an ungated
// portal.
func TestStartUILocked_TokenFailClosedPortalDisabled(t *testing.T) {
	dir := shortTempDir(t)

	// Block the token file path with a directory so LoadOrCreateToken fails.
	tokenPath := filepath.Join(dir, ui.TokenFilename)
	if err := os.MkdirAll(tokenPath, 0o700); err != nil {
		t.Fatalf("mkdir token collision: %v", err)
	}

	d := startBareDaemon(t, Config{Dir: dir})

	// Attempt to start the portal with the collided token path.
	d.uiMu.Lock()
	err := d.startUILocked(freePort(t))
	d.uiMu.Unlock()

	if err == nil {
		t.Fatal("startUILocked: expected error when token unavailable (fail-closed), got nil")
	}
	if d.uiSrv != nil {
		t.Fatal("startUILocked: portal started despite token failure (fail-open!)")
	}
}

// A malformed config makes Reload fail and leaves the running config intact.
func TestReload_MalformedConfig(t *testing.T) {
	d := startBareDaemon(t, Config{IdleTimeout: 5 * time.Minute})
	writeConfig(t, d.cfg.Dir, "ui.port = \"not a number\"\n")
	if _, err := d.Reload(); err == nil {
		t.Fatal("expected error from malformed config")
	}
	if d.idleTimeoutDur() != 5*time.Minute {
		t.Fatalf("idle timeout changed despite reload error: %v", d.idleTimeoutDur())
	}
}
