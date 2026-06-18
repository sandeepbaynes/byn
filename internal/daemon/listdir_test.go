package daemon

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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
	// Without IncludeFiles: only dirs returned, file excluded.
	if len(resp.Entries) != 2 || resp.Entries[0].Name != "alpha" || resp.Entries[1].Name != "beta" {
		t.Fatalf("entries = %+v, want [alpha beta] (dirs only, sorted; file excluded)", resp.Entries)
	}
	// IsDir must be true for both returned entries.
	for _, e := range resp.Entries {
		if !e.IsDir {
			t.Errorf("entry %q: IsDir=false, want true", e.Name)
		}
	}
}

func TestListDir_IncludeFiles(t *testing.T) {
	_, c := startTestDaemon(t)
	root := t.TempDir()
	// Create two dirs (unsorted) and two files (unsorted).
	for _, d := range []string{"zdir", "adir"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"zfile.env", "afile.txt"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var resp ipc.ListDirResp
	if err := c.Call(ipc.OpFSListDir, ipc.ListDirReq{Path: root, IncludeFiles: true}, &resp); err != nil {
		t.Fatalf("listdir with files: %v", err)
	}
	// Expect 4 entries: dirs first (sorted), then files (sorted).
	if len(resp.Entries) != 4 {
		t.Fatalf("len(entries) = %d, want 4; got %+v", len(resp.Entries), resp.Entries)
	}
	want := []struct {
		name  string
		isDir bool
	}{
		{"adir", true},
		{"zdir", true},
		{"afile.txt", false},
		{"zfile.env", false},
	}
	for i, w := range want {
		if resp.Entries[i].Name != w.name || resp.Entries[i].IsDir != w.isDir {
			t.Errorf("entry[%d] = {%q, isDir=%v}, want {%q, isDir=%v}",
				i, resp.Entries[i].Name, resp.Entries[i].IsDir, w.name, w.isDir)
		}
	}
}

func TestListDir_DefaultsToHome(t *testing.T) {
	d, c := startTestDaemon(t)
	var resp ipc.ListDirResp
	if err := c.Call(ipc.OpFSListDir, ipc.ListDirReq{}, &resp); err != nil {
		t.Fatalf("listdir home: %v", err)
	}
	// An empty path must default to the OWNER's home (resolveOwnerHome), not the
	// daemon process's home — which under privsep is the _byn user's /var/empty.
	want := filepath.Clean(d.resolveOwnerHome())
	if resp.Path != want {
		t.Errorf("default path = %q, want owner home %q", resp.Path, want)
	}
}

func TestResolveOwnerHome(t *testing.T) {
	uid := os.Getuid()
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		t.Skipf("LookupId(%d): %v", uid, err)
	}
	// Owner UID set → resolves the OWNER's passwd home (the privsep case: the
	// daemon runs as _byn but must point pickers at the owner's real home).
	d := &Daemon{ownerUID: uint32(uid)} //nolint:gosec // G115: a real uid is a small non-negative int.
	if got := d.resolveOwnerHome(); got != u.HomeDir {
		t.Errorf("resolveOwnerHome(ownerUID=%d) = %q, want %q", uid, got, u.HomeDir)
	}
	// Owner UID unset (0, e.g. privsep off) → falls back to the process home.
	home, _ := os.UserHomeDir()
	d0 := &Daemon{ownerUID: 0}
	if got := d0.resolveOwnerHome(); got != home {
		t.Errorf("resolveOwnerHome(ownerUID=0) = %q, want %q", got, home)
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
