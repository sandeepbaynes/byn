package privsep

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
)

// TestReconcile_SecondPassDoesNothing is named after the bug it guards.
//
// The first version of this pass selected work with a mode test alone. setfacl
// answers a 0600 file by setting the ACL mask, which lands in the GROUP bits and
// leaves other-read clear — so every file it fixed still matched, and the pass
// re-granted the identical set on every run. It ran before every exec: on a real
// monorepo that was 21,642 files and 13.6 seconds added to each one, doing
// nothing. Nothing failed, so nothing reported it.
func TestReconcile_SecondPassDoesNothing(t *testing.T) {
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("setfacl not available")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip("cannot resolve current user")
	}

	dir := t.TempDir()
	locked := filepath.Join(dir, "credentials")
	if werr := os.WriteFile(locked, []byte("token"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	// Granting to ourselves: the test needs a uid it is permitted to grant, and
	// what is under test is the bookkeeping, not which account is named.
	run := func(name string, args ...string) error { return exec.Command(name, args...).Run() }

	if n := ReconcileWritableACLs(run, []string{dir}, u.Username); n != 1 {
		t.Fatalf("first pass granted %d file(s), want 1", n)
	}
	if n := ReconcileWritableACLs(run, []string{dir}, u.Username); n != 0 {
		t.Fatalf("second pass granted %d file(s), want 0 — the grant is not being detected, "+
			"so every exec redoes the whole tree", n)
	}

	// And it must still notice a file that genuinely lost its entry, which is
	// the event the pass exists for.
	if rerr := run("setfacl", "-x", "u:"+u.Username, locked); rerr != nil {
		t.Fatalf("strip acl: %v", rerr)
	}
	if cerr := os.Chmod(locked, 0o600); cerr != nil {
		t.Fatal(cerr)
	}
	if n := ReconcileWritableACLs(run, []string{dir}, u.Username); n != 1 {
		t.Fatalf("after the entry was stripped the pass granted %d file(s), want 1", n)
	}
}
