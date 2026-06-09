package daemon

import (
	"path/filepath"
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
