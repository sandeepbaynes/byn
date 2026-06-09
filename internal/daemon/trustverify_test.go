package daemon

import (
	"os"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

func grantByn(t *testing.T, c *ipc.Client, path string, pw []byte) {
	t.Helper()
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: path, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}
}

func verifyByn(t *testing.T, c *ipc.Client, path string) ipc.TrustVerifyResp {
	t.Helper()
	var resp ipc.TrustVerifyResp
	if err := c.Call(ipc.OpTrustVerify, ipc.TrustVerifyReq{Path: path}, &resp); err != nil {
		t.Fatalf("verify: %v", err)
	}
	return resp
}

// A granted .byn verifies as trusted with both layers checked while unlocked.
func TestTrustVerify_AfterGrant_Trusted(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)
	grantByn(t, c, p, pw)

	r := verifyByn(t, c, p)
	if r.Status != string(trust.VerifyTrusted) {
		t.Fatalf("status = %q, want trusted", r.Status)
	}
	if !r.VKChecked {
		t.Error("vault unlocked → vk-MAC should have been checked")
	}
}

func TestTrustVerify_Untrusted(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody)
	if r := verifyByn(t, c, p); r.Status != string(trust.VerifyUntrusted) {
		t.Fatalf("status = %q, want untrusted", r.Status)
	}
}

func TestTrustVerify_ChangedContent(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)
	grantByn(t, c, p, pw)
	if err := os.WriteFile(p, []byte("[scope]\nproject = \"changed\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := verifyByn(t, c, p); r.Status != string(trust.VerifyChanged) {
		t.Fatalf("status = %q, want changed", r.Status)
	}
}

// While the vault is locked the fp-MAC alone gates discovery (vk-MAC skipped).
func TestTrustVerify_LockedVault_FPOnly(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)
	grantByn(t, c, p, pw)
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{Name: "default"}, &ipc.VaultLockResp{}); err != nil {
		t.Fatalf("lock: %v", err)
	}
	r := verifyByn(t, c, p)
	if r.Status != string(trust.VerifyTrusted) {
		t.Fatalf("status = %q, want trusted (fp-MAC alone)", r.Status)
	}
	if r.VKChecked {
		t.Error("locked vault → vk-MAC must NOT have been checked")
	}
}

// A record with the right path+hash but invalid MACs (forged / copied from
// another machine) is rejected as tampered.
func TestTrustVerify_TamperedRecord(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)
	grantByn(t, c, p, pw)

	canon := trust.Canonicalize(p)
	hash := trust.Hash([]byte(bynBody))
	if _, err := trust.Put(d.cfg.Dir, trust.Record{Path: canon, SHA256: hash, FPMAC: "00", VKMAC: "00"}); err != nil {
		t.Fatal(err)
	}
	if r := verifyByn(t, c, p); r.Status != string(trust.VerifyTampered) {
		t.Fatalf("status = %q, want tampered", r.Status)
	}
}

// A pre-hardening record (no MACs) must be re-trusted: it verifies as stale.
func TestTrustVerify_StaleRecord(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody)

	canon := trust.Canonicalize(p)
	hash := trust.Hash([]byte(bynBody))
	if _, err := trust.Put(d.cfg.Dir, trust.Record{Path: canon, SHA256: hash}); err != nil {
		t.Fatal(err)
	}
	if r := verifyByn(t, c, p); r.Status != string(trust.VerifyStale) {
		t.Fatalf("status = %q, want stale", r.Status)
	}
}
