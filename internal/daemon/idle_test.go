package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// startTestDaemonIdle is startTestDaemon with a configured idle timeout.
func startTestDaemonIdle(t *testing.T, idle time.Duration) (*Daemon, *ipc.Client) {
	t.Helper()
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test", IdleTimeout: idle})
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
	return d, ipc.NewClient(d.SocketPath())
}

func initUnlockDefault(t *testing.T, c *ipc.Client) {
	t.Helper()
	pw := []byte("correct-horse")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
}

func TestLockIdleVaults_LocksAfterTimeout(t *testing.T) {
	// Long timeout so the background janitor never fires mid-test; we
	// drive lockIdleVaults directly with an injected clock.
	d, c := startTestDaemonIdle(t, 15*time.Minute)
	initUnlockDefault(t, c)
	e := d.lookupVault("default")
	if e == nil {
		t.Fatal("no default vault entry after unlock")
	}
	if e.store.IsLocked() {
		t.Fatal("vault locked right after unlock")
	}
	if e.lastActive.Load() == 0 {
		t.Fatal("unlock did not set lastActive")
	}
	base := time.Unix(0, e.lastActive.Load())

	// Just before the timeout: nothing locked.
	if n := d.lockIdleVaults(base.Add(d.idleTimeoutDur() - time.Millisecond)); n != 0 {
		t.Errorf("locked %d vaults before timeout, want 0", n)
	}
	if e.store.IsLocked() {
		t.Error("vault locked before timeout elapsed")
	}

	// Past the timeout: locked exactly once.
	if n := d.lockIdleVaults(base.Add(d.idleTimeoutDur() + time.Millisecond)); n != 1 {
		t.Errorf("locked %d vaults after timeout, want 1", n)
	}
	if !e.store.IsLocked() {
		t.Error("vault not locked after idle timeout elapsed")
	}
}

func TestLockIdleVaults_DisabledByZeroTimeout(t *testing.T) {
	d, c := startTestDaemonIdle(t, 0)
	initUnlockDefault(t, c)
	e := d.lookupVault("default")
	if n := d.lockIdleVaults(time.Now().Add(1000 * time.Hour)); n != 0 {
		t.Errorf("locked %d vaults with idle disabled, want 0", n)
	}
	if e.store.IsLocked() {
		t.Error("vault locked despite idle-timeout disabled (0)")
	}
}

func TestLockIdleVaults_SkipsAlreadyLocked(t *testing.T) {
	d, c := startTestDaemonIdle(t, 15*time.Minute)
	initUnlockDefault(t, c)
	e := d.lookupVault("default")
	e.store.Lock() // already locked → must not be counted
	if n := d.lockIdleVaults(time.Now().Add(1000 * time.Hour)); n != 0 {
		t.Errorf("counted %d already-locked vaults, want 0", n)
	}
}

func TestLockIdleVaults_LeavesActiveVault(t *testing.T) {
	d, c := startTestDaemonIdle(t, 15*time.Minute)
	initUnlockDefault(t, c)
	e := d.lookupVault("default")
	base := time.Unix(0, e.lastActive.Load())
	if n := d.lockIdleVaults(base.Add(time.Minute)); n != 0 { // well within 15m
		t.Errorf("locked %d recently-active vaults, want 0", n)
	}
	if e.store.IsLocked() {
		t.Error("recently-active vault was locked")
	}
}

func TestIdleJanitor_FiresAndLocks(t *testing.T) {
	d, c := startTestDaemonIdle(t, 1*time.Second)
	initUnlockDefault(t, c)
	e := d.lookupVault("default")
	// The janitor ticks ~every second; the vault goes idle 1s after the
	// unlock's touch. Poll generously to stay non-flaky.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if e.store.IsLocked() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !e.store.IsLocked() {
		t.Error("idle janitor did not lock the vault within the deadline")
	}
}
