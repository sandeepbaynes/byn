package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestBynFileContent(t *testing.T) {
	c := bynFileContent(ipc.Scope{Vault: "v", Project: "p", Env: "dev"}, []string{"A", "B"})
	for _, want := range []string{
		"[scope]", `vault   = "v"`, `project = "p"`, `env     = "dev"`,
		"[exec]", `env = ["A", "B"]`,
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("missing %q in:\n%s", want, c)
		}
	}
	// No vars ⇒ no [exec] table; empty scope fields are omitted.
	c2 := bynFileContent(ipc.Scope{Project: "p"}, nil)
	if strings.Contains(c2, "[exec]") {
		t.Fatalf("no vars should mean no [exec]:\n%s", c2)
	}
	if strings.Contains(c2, "vault") {
		t.Fatalf("empty vault should be omitted:\n%s", c2)
	}
}

func TestBynWrite_WritesFileWithoutTrust(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	dir := t.TempDir()

	var resp ipc.BynWriteResp
	req := ipc.BynWriteReq{Dir: dir, Scope: ipc.Scope{Project: "svc"}, EnvVars: []string{"API_KEY"}}
	if err := c.Call(ipc.OpBynWrite, req, &resp); err != nil {
		t.Fatalf("byn write: %v", err)
	}
	want := filepath.Join(dir, ".byn")
	if resp.Path != want {
		t.Fatalf("path = %q, want %q", resp.Path, want)
	}
	if resp.Trusted {
		t.Fatal("trusted should be false when Trust is unset")
	}
	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read written .byn: %v", err)
	}
	if !strings.Contains(string(body), `project = "svc"`) || !strings.Contains(string(body), `env = ["API_KEY"]`) {
		t.Fatalf("written content unexpected:\n%s", body)
	}
	if bynTrusted(t, d, want, string(body)) {
		t.Fatal("file should NOT be trusted without Trust")
	}
}

func TestBynWrite_TrustNow(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	dir := t.TempDir()

	var resp ipc.BynWriteResp
	req := ipc.BynWriteReq{Dir: dir, Scope: ipc.Scope{Project: "svc"}, EnvVars: []string{"API_KEY"}, Trust: true, Password: pw}
	if err := c.Call(ipc.OpBynWrite, req, &resp); err != nil {
		t.Fatalf("byn write+trust: %v", err)
	}
	if !resp.Trusted {
		t.Fatal("trusted should be true after Trust=true")
	}
	body, _ := os.ReadFile(resp.Path)
	if !bynTrusted(t, d, resp.Path, string(body)) {
		t.Fatal("file should be trusted after a trust-now write")
	}
}

func TestBynWrite_TrustWithoutPassword_Denied(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	dir := t.TempDir()

	err := c.Call(ipc.OpBynWrite,
		ipc.BynWriteReq{Dir: dir, Scope: ipc.Scope{Project: "svc"}, Trust: true},
		&ipc.BynWriteResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}
	// The password is checked BEFORE the write, so nothing should land.
	if _, statErr := os.Stat(filepath.Join(dir, ".byn")); statErr == nil {
		t.Fatal(".byn was written despite the denied trust")
	}
}

func TestBynWrite_NotADirectory(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	f := writeByn(t, "x") // a file, not a directory

	err := c.Call(ipc.OpBynWrite, ipc.BynWriteReq{Dir: f}, &ipc.BynWriteResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}
}
