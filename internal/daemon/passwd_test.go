package daemon

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestVaultPasswd_RotatesPassword(t *testing.T) {
	d, c := startTestDaemon(t)
	old := []byte("old-passphrase")
	initUnlocked(t, c, old) // inits + unlocks default with `old`
	newpw := []byte("new-passphrase")

	if err := c.Call(ipc.OpVaultPasswd,
		ipc.VaultPasswdReq{OldPassword: old, NewPassword: newpw}, &ipc.VaultPasswdResp{}); err != nil {
		t.Fatalf("passwd: %v", err)
	}
	// Re-wrap preserves lock state: still unlocked.
	if d.lookupVault("default").store.IsLocked() {
		t.Error("passwd locked an unlocked vault")
	}
	// The NEW password unlocks.
	d.lookupVault("default").store.Lock()
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: newpw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock with new password: %v", err)
	}
	// The OLD password no longer unlocks.
	d.lookupVault("default").store.Lock()
	err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: old}, &ipc.VaultUnlockResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("old password code = %v, want wrong_password", code)
	}
}

func TestVaultPasswd_WhileLocked(t *testing.T) {
	d, c := startTestDaemon(t)
	old := []byte("old-passphrase")
	initUnlocked(t, c, old)
	d.lookupVault("default").store.Lock()

	newpw := []byte("new-passphrase")
	if err := c.Call(ipc.OpVaultPasswd,
		ipc.VaultPasswdReq{OldPassword: old, NewPassword: newpw}, &ipc.VaultPasswdResp{}); err != nil {
		t.Fatalf("passwd while locked: %v", err)
	}
	if !d.lookupVault("default").store.IsLocked() {
		t.Error("passwd unlocked a locked vault")
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: newpw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock with new after locked passwd: %v", err)
	}
}

func TestVaultPasswd_WrongOld(t *testing.T) {
	_, c := startTestDaemon(t)
	old := []byte("old-passphrase")
	initUnlocked(t, c, old)
	err := c.Call(ipc.OpVaultPasswd,
		ipc.VaultPasswdReq{OldPassword: []byte("nope"), NewPassword: []byte("new")}, &ipc.VaultPasswdResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("code = %v, want wrong_password", code)
	}
}

func TestVaultPasswd_EmptyNew(t *testing.T) {
	_, c := startTestDaemon(t)
	old := []byte("old-passphrase")
	initUnlocked(t, c, old)
	err := c.Call(ipc.OpVaultPasswd,
		ipc.VaultPasswdReq{OldPassword: old, NewPassword: nil}, &ipc.VaultPasswdResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}
}

func TestVaultPasswd_RateLimited(t *testing.T) {
	d, c := startTestDaemon(t)
	old := []byte("old-passphrase")
	initUnlocked(t, c, old)
	_ = d.limiter.RecordFailure() // force backoff
	err := c.Call(ipc.OpVaultPasswd,
		ipc.VaultPasswdReq{OldPassword: old, NewPassword: []byte("new")}, &ipc.VaultPasswdResp{})
	if code := errCode(t, err); code != ipc.CodeRateLimited {
		t.Fatalf("code = %v, want rate_limited", code)
	}
}

func TestVaultPasswd_BadName(t *testing.T) {
	_, c := startTestDaemon(t)
	old := []byte("old-passphrase")
	initUnlocked(t, c, old)
	err := c.Call(ipc.OpVaultPasswd,
		ipc.VaultPasswdReq{Name: "bad/name", OldPassword: old, NewPassword: []byte("new")}, &ipc.VaultPasswdResp{})
	if code := errCode(t, err); code != ipc.CodeBadName {
		t.Fatalf("code = %v, want bad_name", code)
	}
}
