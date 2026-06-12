//go:build byntest

package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// Under the byntest seam the data root is an isolated tempdir, so Provisioned()
// and ActiveSocketPath() can be exercised against a real owner-record file: an
// unprovisioned dir (no record) routes the CLI/daemon to the data-dir socket,
// and writing the record flips both to the provisioned/runtime socket.
func TestActiveSocketPath_ProvisionedFlip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BYN_TEST_DIR", dir)

	// Unprovisioned: no owner record.
	if prov, err := Provisioned(); err != nil || prov {
		t.Fatalf("unprovisioned: prov=%v err=%v, want prov=false", prov, err)
	}
	got, err := ActiveSocketPath(dir)
	if err != nil {
		t.Fatalf("ActiveSocketPath (unprovisioned): %v", err)
	}
	if want := filepath.Join(dir, socketFilename); got != want {
		t.Fatalf("unprovisioned socket = %q, want %q", got, want)
	}

	// Provision by writing the owner record where OwnerRecordPath resolves.
	rec, err := OwnerRecordPath()
	if err != nil {
		t.Fatalf("OwnerRecordPath: %v", err)
	}
	if err := os.WriteFile(rec, []byte("501\n"), 0o444); err != nil {
		t.Fatalf("seed owner record: %v", err)
	}

	if prov, err := Provisioned(); err != nil || !prov {
		t.Fatalf("provisioned: prov=%v err=%v, want prov=true", prov, err)
	}
	got, err = ActiveSocketPath(dir)
	if err != nil {
		t.Fatalf("ActiveSocketPath (provisioned): %v", err)
	}
	if want := SocketPath(); got != want {
		t.Fatalf("provisioned socket = %q, want runtime %q", got, want)
	}
}
