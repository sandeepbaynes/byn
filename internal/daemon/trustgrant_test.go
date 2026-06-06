package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

const bynBody = "[scope]\nproject = \"svc\"\n"

// writeByn writes a .byn file into a fresh temp dir and returns its path.
func writeByn(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".byn")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func bynTrusted(t *testing.T, d *Daemon, path, content string) bool {
	t.Helper()
	st, err := trust.Status(d.cfg.Dir, trust.Canonicalize(path), trust.Hash([]byte(content)))
	if err != nil {
		t.Fatal(err)
	}
	return st == trust.StatusTrusted
}

func TestTrustGrant_CorrectPassword_Records(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)

	var resp ipc.TrustGrantResp
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &resp); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if resp.Changed {
		t.Error("a first-time grant should report changed=false")
	}
	if resp.SHA256 != trust.Hash([]byte(bynBody)) {
		t.Errorf("resp hash %q != content hash", resp.SHA256)
	}
	if !bynTrusted(t, d, p, bynBody) {
		t.Fatal("after grant the .byn is not recorded as trusted")
	}
}

// The headline guarantee: granting trust requires the password EVEN when the
// vault is already unlocked — an unlocked session is not consent.
func TestTrustGrant_NoPassword_DeniedEvenWhenUnlocked(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW)) // vault is UNLOCKED
	p := writeByn(t, bynBody)

	err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p}, &ipc.TrustGrantResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("no-password code = %v, want bad_request (password always required)", code)
	}
	if bynTrusted(t, d, p, bynBody) {
		t.Fatal("trust was recorded without a password")
	}
}

func TestTrustGrant_WrongPassword_Denied(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody)

	err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: []byte("nope")}, &ipc.TrustGrantResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("code = %v, want wrong_password", code)
	}
	if bynTrusted(t, d, p, bynBody) {
		t.Fatal("a wrong password still recorded trust")
	}
}

// Re-granting a .byn whose content changed since it was trusted reports
// changed=true, so the CLI/portal can confirm loudly.
func TestTrustGrant_ChangedFile_ReportsChanged(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	if err := os.WriteFile(p, []byte("[scope]\nproject = \"evil\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var resp ipc.TrustGrantResp
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &resp); err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	if !resp.Changed {
		t.Error("re-granting a modified .byn should report changed=true")
	}
}
