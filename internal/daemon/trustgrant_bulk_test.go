package daemon

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Bulk grant trusts every readable path with a single password verification;
// a per-file read error is reported without failing the batch.
func TestTrustGrantBulk_TrustsMany_OneVerify(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p1 := writeByn(t, bynBody)
	const body2 = "[scope]\nproject = \"svc2\"\n"
	p2 := writeByn(t, body2)
	missing := filepath.Join(t.TempDir(), ".byn") // never created

	var resp ipc.TrustGrantBulkResp
	if err := c.Call(ipc.OpTrustGrantBulk,
		ipc.TrustGrantBulkReq{Paths: []string{p1, p2, missing}, Password: pw}, &resp); err != nil {
		t.Fatalf("bulk grant: %v", err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(resp.Results))
	}
	if resp.Results[0].Error != "" || resp.Results[1].Error != "" {
		t.Errorf("first two should succeed, got %+v", resp.Results)
	}
	if resp.Results[2].Error == "" {
		t.Error("the missing file should report an error")
	}
	if !bynTrusted(t, d, p1, bynBody) || !bynTrusted(t, d, p2, body2) {
		t.Error("both readable .byn files should be trusted")
	}
}

// TestTrustGrantBulk_PrivsepEnabled_GrantsACL verifies that when privsep is
// enabled, handleTrustGrantBulk calls grantProjectACL for each successfully
// trusted path (not just for single-path grants via handleTrustGrant). The real
// setfacl binary is not required: the daemon's testACLRunner seam is injected to
// record every invocation.
func TestTrustGrantBulk_PrivsepEnabled_GrantsACL(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	p1 := writeByn(t, bynBody)
	const body2 = "[scope]\nproject = \"svc2\"\n"
	p2 := writeByn(t, body2)

	// Enable privsep and install a recording runner BEFORE issuing the grant.
	d.cfg.Privsep = true
	var mu sync.Mutex
	var aclCalls [][]string
	d.testACLRunner = func(name string, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		aclCalls = append(aclCalls, append([]string{name}, args...))
		return nil // best-effort; never fail the grant
	}

	var resp ipc.TrustGrantBulkResp
	if err := c.Call(ipc.OpTrustGrantBulk,
		ipc.TrustGrantBulkReq{Paths: []string{p1, p2}, Password: pw}, &resp); err != nil {
		t.Fatalf("bulk grant: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(resp.Results))
	}
	for i, r := range resp.Results {
		if r.Error != "" {
			t.Errorf("result[%d] unexpected error: %v", i, r.Error)
		}
	}

	// The ACL runner must have been invoked at least once for each trusted path.
	// (The exact count depends on the platform's aclGrantCommands — we only assert
	// that the grant path was reached for both files.)
	mu.Lock()
	n := len(aclCalls)
	mu.Unlock()
	if n == 0 {
		t.Fatal("privsep ACL runner was never called during bulk trust grant")
	}
	// We trusted 2 files, so the runner must have been called at least twice
	// (one invocation per file minimum).
	if n < 2 {
		t.Errorf("ACL runner called %d time(s), want >= 2 (one per granted file)", n)
	}
}

func TestTrustGrantBulk_WrongPassword_Denied(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody)

	err := c.Call(ipc.OpTrustGrantBulk,
		ipc.TrustGrantBulkReq{Paths: []string{p}, Password: []byte("nope")}, &ipc.TrustGrantBulkResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("code = %v, want wrong_password", code)
	}
	if bynTrusted(t, d, p, bynBody) {
		t.Error("a wrong password must not record trust")
	}
}
