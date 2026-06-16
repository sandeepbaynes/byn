package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sandeepbaynes/byn/internal/paths"
)

// TestSessionStoreDir: non-provisioned installs keep using the data dir (so a
// custom BYN_DIR still works); a provisioned install — where the data dir is the
// _byn-owned system tree the owner can't write — diverts session tokens to the
// owner's ~/.byn. Regression test for "mkdir .../byn/sessions: permission denied"
// on `byn unlock` under privsep.
func TestSessionStoreDir(t *testing.T) {
	// Non-provisioned data dir → used as-is.
	dir := t.TempDir()
	if got := sessionStoreDir(dir); got != dir {
		t.Errorf("non-provisioned: got %q, want %q (the data dir)", got, dir)
	}

	// Provisioned (owner record present) → diverts off the data dir.
	prov := t.TempDir()
	if err := os.WriteFile(paths.OwnerRecordIn(prov), []byte("501"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := sessionStoreDir(prov)
	if got == prov {
		t.Fatalf("provisioned: got the data dir %q; must divert to an owner-writable dir", got)
	}
	if home, err := os.UserHomeDir(); err == nil {
		if want := filepath.Join(home, ".byn"); got != want {
			t.Errorf("provisioned: got %q, want %q", got, want)
		}
	}
}
