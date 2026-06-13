package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// resolveActiveSocketPath is the pure selector: provisioned ⇒ runtime socket,
// unprovisioned ⇒ the socket inside the data dir. Both branches are exercised
// without touching the filesystem (so this runs identically tagged or not).
func TestResolveActiveSocketPath(t *testing.T) {
	const dataDir = "/var/lib/byn"
	const runtime = "/run/byn/daemon.sock"

	if got := resolveActiveSocketPath(dataDir, true, runtime); got != runtime {
		t.Fatalf("provisioned: got %q, want %q", got, runtime)
	}
	want := filepath.Join(dataDir, socketFilename)
	if got := resolveActiveSocketPath(dataDir, false, runtime); got != want {
		t.Fatalf("unprovisioned: got %q, want %q", got, want)
	}
}

// ownerRecordExists distinguishes a present record (provisioned) from an absent
// one (unprovisioned) without surfacing "not exist" as an error.
func TestOwnerRecordExists(t *testing.T) {
	dir := t.TempDir()

	absent := filepath.Join(dir, "no-such-owner")
	if ok, err := ownerRecordExists(absent); err != nil || ok {
		t.Fatalf("absent: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	present := filepath.Join(dir, "owner")
	if err := os.WriteFile(present, []byte("501\n"), 0o444); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if ok, err := ownerRecordExists(present); err != nil || !ok {
		t.Fatalf("present: ok=%v err=%v, want ok=true err=nil", ok, err)
	}
}
