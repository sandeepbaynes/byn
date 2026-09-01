package privsep

import (
	"os"
	"path/filepath"
	"testing"
)

// The failure this repairs: a tool rewrites its own state file and chmods it to
// 0600 afterwards, discarding the inherited ACL. Whichever identity wrote last
// owns a file the other cannot read.
func TestLockedDownMode(t *testing.T) {
	for mode, want := range map[os.FileMode]bool{
		0o600: true,  // the AWS CLI's SSO cache after its own chmod
		0o640: true,  // group can read, but the exec user is not in the group
		0o644: false, // ordinary source file: already readable
		0o755: false,
		0o604: false, // other can read
	} {
		if got := lockedDownMode(mode); got != want {
			t.Errorf("lockedDownMode(%v) = %v, want %v", mode, got, want)
		}
	}
}

func TestReconcileWritableACLs_OnlyTouchesLockedFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // umask-proof
			t.Fatal(err)
		}
		return p
	}
	locked := write("sso-cache.json", 0o600)
	open := write("config", 0o644)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	nested := write(filepath.Join("sub", "token.json"), 0o600)

	var touched []string
	run := func(name string, args ...string) error {
		touched = append(touched, args[len(args)-1])
		return nil
	}
	n := ReconcileWritableACLs(run, []string{dir}, "_byn-exec")

	if n != 2 {
		t.Errorf("re-granted %d files, want 2", n)
	}
	got := map[string]bool{}
	for _, p := range touched {
		got[p] = true
	}
	if !got[locked] || !got[nested] {
		t.Errorf("a locked-down file was skipped: %v", touched)
	}
	if got[open] {
		t.Error("a world-readable file was needlessly re-granted — the walk must stay cheap")
	}
}

// A .byn naming a directory this machine does not have must cost nothing.
func TestWritableDirsExist_DropsWhatIsAbsent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got := WritableDirsExist([]string{dir, filepath.Join(dir, "missing"), file})
	if len(got) != 1 || got[0] != dir {
		t.Errorf("kept %v, want just the real directory", got)
	}
}
