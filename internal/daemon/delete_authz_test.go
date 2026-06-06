package daemon

import (
	"errors"
	"os"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

const authzPW = "correct-horse-battery-staple"

func lockVaultStore(t *testing.T, d *Daemon, name string) {
	t.Helper()
	e := d.lookupVault(name)
	if e == nil {
		t.Fatalf("no in-memory entry for vault %q", name)
	}
	e.store.Lock()
	if !e.store.IsLocked() {
		t.Fatalf("vault %q did not lock", name)
	}
}

func errCode(t *testing.T, err error) ipc.ErrCode {
	t.Helper()
	var er *ipc.ErrResponse
	if !errors.As(err, &er) {
		t.Fatalf("expected an ErrResponse, got %v", err)
	}
	return er.Code
}

// initNamedLocked creates a named vault and leaves it locked (init does not
// unlock).
func initNamedLocked(t *testing.T, c *ipc.Client, name string, pw []byte) {
	t.Helper()
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: name, Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init %q: %v", name, err)
	}
}

// ---- entry delete while locked -----------------------------------------

// The headline guarantee: a password-authorized delete on a locked vault
// succeeds AND leaves the vault locked, so no process can read the
// remaining values out of daemon memory.
func TestEntryDelete_LockedWithPassword_StaysLocked(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "API_KEY", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	lockVaultStore(t, d, "default")

	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "API_KEY", Password: pw}, &ipc.DeleteResp{}); err != nil {
		t.Fatalf("authorized delete while locked: %v", err)
	}
	if !d.lookupVault("default").store.IsLocked() {
		t.Fatal("vault was left UNLOCKED after an authorized delete — it must stay locked")
	}
	// Entry is gone: a second authorized delete reports not_found.
	err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "API_KEY", Password: pw}, &ipc.DeleteResp{})
	if code := errCode(t, err); code != ipc.CodeNotFound {
		t.Fatalf("second delete code = %v, want not_found", code)
	}
}

func TestEntryDelete_LockedNoPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "API_KEY", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	lockVaultStore(t, d, "default")

	err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "API_KEY"}, &ipc.DeleteResp{})
	if code := errCode(t, err); code != ipc.CodeLocked {
		t.Fatalf("code = %v, want locked", code)
	}
	// The entry survived: its NAME still lists while locked.
	var lr ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &lr); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !hasSecret(lr, "API_KEY") {
		t.Error("entry was deleted despite a missing password")
	}
}

func TestEntryDelete_LockedWrongPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "API_KEY", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	lockVaultStore(t, d, "default")

	err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "API_KEY", Password: []byte("nope")}, &ipc.DeleteResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("code = %v, want wrong_password", code)
	}
	if !d.lookupVault("default").store.IsLocked() {
		t.Error("a wrong password changed the vault lock state")
	}
}

func hasSecret(r ipc.ListResp, name string) bool {
	for _, s := range r.Secrets {
		if s.Name == name {
			return true
		}
	}
	return false
}

// ---- project / env delete while locked ---------------------------------

func TestProjectDelete_LockedWithPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create: %v", err)
	}
	lockVaultStore(t, d, "default")

	// No password → locked.
	err := c.Call(ipc.OpProjectDelete, ipc.ProjectDeleteReq{Name: "svc"}, &ipc.ProjectDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeLocked {
		t.Fatalf("no-password code = %v, want locked", code)
	}
	// With password → deleted, vault stays locked.
	if err := c.Call(ipc.OpProjectDelete, ipc.ProjectDeleteReq{Name: "svc", Password: pw}, &ipc.ProjectDeleteResp{}); err != nil {
		t.Fatalf("authorized project delete: %v", err)
	}
	if !d.lookupVault("default").store.IsLocked() {
		t.Error("vault left unlocked after authorized project delete")
	}
}

func TestEnvDelete_LockedWithPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "stg"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("env create: %v", err)
	}
	lockVaultStore(t, d, "default")

	if err := c.Call(ipc.OpEnvDelete, ipc.EnvDeleteReq{Project: "default", Name: "stg", Password: pw}, &ipc.EnvDeleteResp{}); err != nil {
		t.Fatalf("authorized env delete: %v", err)
	}
	if !d.lookupVault("default").store.IsLocked() {
		t.Error("vault left unlocked after authorized env delete")
	}
}

// ---- vault delete -------------------------------------------------------

func TestVaultDelete_Unlocked(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "acme", pw)
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock acme: %v", err)
	}
	if err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme"}, &ipc.VaultDeleteResp{}); err != nil {
		t.Fatalf("vault delete (unlocked): %v", err)
	}
	if _, err := os.Stat(vault.Dir(d.cfg.Dir, "acme")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("acme dir still present after delete: %v", err)
	}
	if d.lookupVault("acme") != nil {
		t.Error("acme still in the daemon's vault map after delete")
	}
}

func TestVaultDelete_LockedWithPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "acme", pw)

	if err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme", Password: pw}, &ipc.VaultDeleteResp{}); err != nil {
		t.Fatalf("authorized vault delete: %v", err)
	}
	if _, err := os.Stat(vault.Dir(d.cfg.Dir, "acme")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("acme dir still present after authorized delete: %v", err)
	}
}

func TestVaultDelete_LockedNoPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "acme", pw)

	err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme"}, &ipc.VaultDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeLocked {
		t.Fatalf("code = %v, want locked", code)
	}
	if _, err := os.Stat(vault.Dir(d.cfg.Dir, "acme")); err != nil {
		t.Errorf("acme dir removed despite missing password: %v", err)
	}
}

// A delete on a locked vault is rate-limited like unlock: when the shared
// limiter is in backoff, even a correct password is refused.
func TestEntryDelete_LockedRateLimited(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "K", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	lockVaultStore(t, d, "default")
	_ = d.limiter.RecordFailure() // force backoff

	err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "K", Password: pw}, &ipc.DeleteResp{})
	if code := errCode(t, err); code != ipc.CodeRateLimited {
		t.Fatalf("code = %v, want rate_limited", code)
	}
}

func TestVaultDelete_BadName(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "bad/name"}, &ipc.VaultDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeBadName {
		t.Fatalf("code = %v, want bad_name", code)
	}
}

func TestVaultDelete_LockedWrongPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	initNamedLocked(t, c, "acme", pw)

	err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme", Password: []byte("nope")}, &ipc.VaultDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("code = %v, want wrong_password", code)
	}
	if _, err := os.Stat(vault.Dir(d.cfg.Dir, "acme")); err != nil {
		t.Errorf("acme dir removed despite a wrong password: %v", err)
	}
}
