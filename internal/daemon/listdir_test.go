package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestListDir_DirsOnlySorted(t *testing.T) {
	_, c := startTestDaemon(t)
	root := t.TempDir()
	for _, d := range []string{"beta", "alpha"} { // unsorted on disk
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	var resp ipc.ListDirResp
	if err := c.Call(ipc.OpFSListDir, ipc.ListDirReq{Path: root}, &resp); err != nil {
		t.Fatalf("listdir: %v", err)
	}
	if resp.Path != filepath.Clean(root) {
		t.Errorf("path = %q, want %q", resp.Path, filepath.Clean(root))
	}
	if resp.Parent != filepath.Dir(filepath.Clean(root)) {
		t.Errorf("parent = %q, want %q", resp.Parent, filepath.Dir(root))
	}
	if len(resp.Entries) != 2 || resp.Entries[0].Name != "alpha" || resp.Entries[1].Name != "beta" {
		t.Fatalf("entries = %+v, want [alpha beta] (dirs only, sorted; file excluded)", resp.Entries)
	}
}

func TestListDir_DefaultsToHome(t *testing.T) {
	_, c := startTestDaemon(t)
	var resp ipc.ListDirResp
	if err := c.Call(ipc.OpFSListDir, ipc.ListDirReq{}, &resp); err != nil {
		t.Fatalf("listdir home: %v", err)
	}
	home, _ := os.UserHomeDir()
	if resp.Path != filepath.Clean(home) {
		t.Errorf("default path = %q, want home %q", resp.Path, filepath.Clean(home))
	}
}

func TestListDir_NotADirectory(t *testing.T) {
	_, c := startTestDaemon(t)
	f := writeByn(t, "x") // a file, not a directory
	err := c.Call(ipc.OpFSListDir, ipc.ListDirReq{Path: f}, &ipc.ListDirResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}
}
