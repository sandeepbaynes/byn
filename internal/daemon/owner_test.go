package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// resolveOwnerUID: when provisioned (a record exists) the RECORDED owner UID is
// allowlisted — NOT the daemon's euid (which under privsep is _byn, ≠ the human
// owner). When unprovisioned it falls back to euid (today's behavior).
func TestResolveOwnerUID(t *testing.T) {
	const recorded = 501
	const euid = 999 // stand-in for the _byn service UID

	if got := resolveOwnerUID(true, recorded, euid); got != recorded {
		t.Fatalf("provisioned: resolveOwnerUID = %d, want recorded %d", got, recorded)
	}
	if got := resolveOwnerUID(false, recorded, euid); got != euid {
		t.Fatalf("unprovisioned: resolveOwnerUID = %d, want euid %d", got, euid)
	}
}

// resolveOwnerRecord: a missing record ⇒ unprovisioned (no error); a present
// valid record ⇒ provisioned with its UID; a present but garbage record ⇒ a
// hard error (fail safe — never a silent euid fallback under privsep).
func TestResolveOwnerRecord(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		exists, uid, err := resolveOwnerRecord(t.TempDir())
		if err != nil || exists || uid != 0 {
			t.Fatalf("missing: exists=%v uid=%d err=%v, want false/0/nil", exists, uid, err)
		}
	})

	t.Run("present_valid", func(t *testing.T) {
		dir := t.TempDir()
		if err := privsep.WriteOwnerRecord(filepath.Join(dir, "owner"), 1234); err != nil {
			t.Fatalf("seed: %v", err)
		}
		exists, uid, err := resolveOwnerRecord(dir)
		if err != nil || !exists || uid != 1234 {
			t.Fatalf("valid: exists=%v uid=%d err=%v, want true/1234/nil", exists, uid, err)
		}
	})

	t.Run("present_garbage", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "owner"), []byte("not-a-uid\n"), 0o444); err != nil {
			t.Fatalf("seed: %v", err)
		}
		_, _, err := resolveOwnerRecord(dir)
		if err == nil {
			t.Fatal("garbage record: err = nil, want error (fail safe)")
		}
	})

	t.Run("present_zero", func(t *testing.T) {
		dir := t.TempDir()
		// A record of 0 would allowlist root; ReadOwnerRecord rejects it, so
		// resolveOwnerRecord must surface an error rather than provision uid 0.
		if err := os.WriteFile(filepath.Join(dir, "owner"), []byte("0\n"), 0o444); err != nil {
			t.Fatalf("seed: %v", err)
		}
		_, _, err := resolveOwnerRecord(dir)
		if err == nil {
			t.Fatal("zero record: err = nil, want error")
		}
	})
}

// A daemon built in a provisioned data dir allowlists the RECORDED owner UID,
// proving recorded-UID ≠ euid is the one peercred enforces. No root needed: the
// record is just a file, and we pick a recorded UID that differs from euid.
func TestNew_AllowlistsRecordedOwnerUID(t *testing.T) {
	dir := shortTempDir(t)

	// Choose a recorded UID guaranteed to differ from this process's euid so the
	// test proves the record (not geteuid) drives the allowlist.
	recorded := os.Geteuid() + 4242
	if err := privsep.WriteOwnerRecord(filepath.Join(dir, "owner"), recorded); err != nil {
		t.Fatalf("seed owner record: %v", err)
	}

	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := d.ownerUID; got != uint32(recorded) { //nolint:gosec // recorded > 0
		t.Fatalf("d.ownerUID = %d, want recorded %d (NOT euid %d)", got, recorded, os.Geteuid())
	}
}

// Without an owner record the daemon keeps geteuid() as the owner UID — the
// opt-in-off / unprovisioned path is unchanged (spec D3).
func TestNew_UnprovisionedKeepsEuid(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, want := d.ownerUID, uint32(os.Geteuid()); got != want { //nolint:gosec // euid >= 0
		t.Fatalf("d.ownerUID = %d, want euid %d", got, want)
	}
}

// An explicit cfg.OwnerUID always wins over both the record and euid (tests and
// callers can pin the allowlisted UID directly).
func TestNew_ExplicitOwnerUIDWins(t *testing.T) {
	dir := shortTempDir(t)
	if err := privsep.WriteOwnerRecord(filepath.Join(dir, "owner"), os.Geteuid()+100); err != nil {
		t.Fatalf("seed: %v", err)
	}
	d, err := New(Config{Dir: dir, Version: "test", OwnerUID: 7777})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d.ownerUID != 7777 {
		t.Fatalf("d.ownerUID = %d, want explicit 7777", d.ownerUID)
	}
}

// A present-but-corrupt owner record fails New() loudly rather than silently
// allowlisting euid (which under privsep is the wrong UID — NU-6 note #2).
func TestNew_CorruptOwnerRecordFailsSafe(t *testing.T) {
	dir := shortTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "owner"), []byte("garbage\n"), 0o444); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := New(Config{Dir: dir, Version: "test"}); err == nil {
		t.Fatal("New with corrupt owner record = nil error, want fail-safe error")
	}
}

// An unprovisioned daemon binds its socket INSIDE the data dir (legacy path) —
// no relocation, no separate socket dir created. Confirms today's behavior.
func TestNew_UnprovisionedSocketInDataDir(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if want := filepath.Join(dir, SocketFilename); d.SocketPath() != want {
		t.Fatalf("socket = %q, want data-dir socket %q", d.SocketPath(), want)
	}
}

// TestStart_ProvisionedRelocatesSocketWithTraversableParent and its
// ownerUIDForTest helper live in owner_byntest_test.go (//go:build byntest):
// they depend on the data-dir seam (paths.SocketPath honors BYN_TEST_DIR only
// under that tag), so they must not compile into an untagged
// `go test ./internal/daemon/` run.
