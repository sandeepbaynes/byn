//go:build linux

package privsep

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func hasSetfacl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("no setfacl on this machine")
	}
}

// The deep grant walks every entry under a project. On a 330k-entry monorepo
// that took over three minutes, and it ran again on every re-trust — which is
// every time a .byn is edited. Running it once is enough: a default ACL is
// inherited at creation, at any depth, so only entries predating the first
// grant ever need the walk.
func TestDeepGrantDone_SeesTheInheritableEntry(t *testing.T) {
	hasSetfacl(t)
	dir := t.TempDir()

	if deepGrantDone(dir) {
		t.Fatal("an ungranted directory reported as already granted — the walk would be skipped wrongly")
	}

	// Only the ACCESS entry: not enough, because it is the DEFAULT entry that
	// makes later files inherit. Skipping on this alone would leave everything
	// created afterwards without access.
	if err := exec.Command("setfacl", "-m", "u:"+ExecUser+":rwX", dir).Run(); err != nil {
		t.Skipf("cannot set an ACL for %s here: %v", ExecUser, err)
	}
	if deepGrantDone(dir) {
		t.Error("an access-only entry was taken as proof the deep grant ran")
	}

	if err := exec.Command("setfacl", "-d", "-m", "u:"+ExecUser+":rwX", dir).Run(); err != nil {
		t.Fatalf("set default entry: %v", err)
	}
	if !deepGrantDone(dir) {
		t.Error("the inheritable entry is present but the grant was not recognised")
	}
}

// A path that cannot be read must not read as done: the safe direction is to do
// the work again, not to assume it happened.
func TestDeepGrantDone_UnreadableIsNotDone(t *testing.T) {
	if deepGrantDone(filepath.Join(os.TempDir(), "byn-no-such-dir-xyzzy")) {
		t.Error("a missing directory reported as granted")
	}
}
