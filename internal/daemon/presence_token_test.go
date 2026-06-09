package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// A valid passkey presence token authorizes trust without the master password.
func TestBynWrite_TrustViaPresenceToken(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	dir := t.TempDir()
	tok, err := d.presenceTokens.mint("default", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	var resp ipc.BynWriteResp
	req := ipc.BynWriteReq{Dir: dir, Scope: ipc.Scope{Project: "svc"}, EnvVars: []string{"X"}, Trust: true, PresenceToken: tok}
	if err := c.Call(ipc.OpBynWrite, req, &resp); err != nil {
		t.Fatalf("byn write via presence token: %v", err)
	}
	if !resp.Trusted {
		t.Fatal("trusted should be true with a valid presence token")
	}
	body, _ := os.ReadFile(resp.Path)
	if !bynTrusted(t, d, resp.Path, string(body)) {
		t.Fatal("file should be trusted via the presence token")
	}
}

func TestBynWrite_RejectsInvalidPresenceToken(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	dir := t.TempDir()

	err := c.Call(ipc.OpBynWrite,
		ipc.BynWriteReq{Dir: dir, Scope: ipc.Scope{Project: "svc"}, Trust: true, PresenceToken: []byte("bogus")},
		&ipc.BynWriteResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".byn")); statErr == nil {
		t.Fatal(".byn written despite an invalid token")
	}
}

// A presence token is single-use — a replay is rejected.
func TestBynWrite_PresenceTokenSingleUse(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	tok, _ := d.presenceTokens.mint("default", time.Now())

	if err := c.Call(ipc.OpBynWrite,
		ipc.BynWriteReq{Dir: t.TempDir(), Scope: ipc.Scope{Project: "svc"}, Trust: true, PresenceToken: tok},
		&ipc.BynWriteResp{}); err != nil {
		t.Fatalf("first use: %v", err)
	}
	err := c.Call(ipc.OpBynWrite,
		ipc.BynWriteReq{Dir: t.TempDir(), Scope: ipc.Scope{Project: "svc"}, Trust: true, PresenceToken: tok},
		&ipc.BynWriteResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("replay code = %v, want bad_request (single-use)", code)
	}
}
