//go:build byntest

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// When provisioned, the daemon binds the RUNTIME socket under a separate
// parent, and Start makes that parent owner-traversable (0755) and the socket
// file 0666 + peercred-gated (the owner is a different UID than _byn and must be
// able to connect; peercred is the real gate). Driven through the byntest seam so
// SocketPath() resolves to an isolated runtime dir distinct from the state dir
// — no root needed. OwnerUID is pinned to this process so peercred + bind work.
//
// This test lives behind the byntest build tag because it depends on the
// data-dir seam (paths.SocketPath honors BYN_TEST_DIR only under that tag). In
// an untagged build SocketPath() resolves to the fixed system path, so the
// relocation it asserts is not observable — keeping it tagged means
// `go test ./internal/daemon/` (untagged) stays green while CI (which builds
// with -tags byntest) still exercises it.
func TestStart_ProvisionedRelocatesSocketWithTraversableParent(t *testing.T) {
	base := shortTempDir(t)
	stateDir := filepath.Join(base, "state")
	runtimeDir := filepath.Join(base, "runtime")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	// byntest seam: SocketPath() (the "runtime" path) resolves under runtimeDir,
	// distinct from the state dir, so relocation is observable.
	t.Setenv("BYN_TEST_DIR", runtimeDir)

	// Provision the STATE dir (cfg.Dir) so ActiveSocketPath picks the runtime
	// socket. Pin OwnerUID so we don't depend on the recorded value here.
	if err := privsep.WriteOwnerRecord(filepath.Join(stateDir, "owner"), os.Geteuid()); err != nil {
		// Geteuid() may be 0 in CI-root; WriteOwnerRecord rejects 0, so fall back
		// to a non-zero recorded UID and still pin OwnerUID explicitly below.
		if werr := privsep.WriteOwnerRecord(filepath.Join(stateDir, "owner"), 501); werr != nil {
			t.Fatalf("seed owner record: %v / %v", err, werr)
		}
	}

	d, err := New(Config{Dir: stateDir, Version: "test", OwnerUID: ownerUIDForTest()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wantSock := filepath.Join(runtimeDir, SocketFilename)
	if d.SocketPath() != wantSock {
		t.Fatalf("socket = %q, want runtime socket %q", d.SocketPath(), wantSock)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { d.Shutdown(2 * time.Second) })

	// Runtime socket parent is owner-traversable (0755).
	fi, err := os.Stat(runtimeDir)
	if err != nil {
		t.Fatalf("stat runtime dir: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o755 {
		t.Fatalf("runtime socket dir mode = %o, want 0755 (owner-traversable)", mode)
	}
	// Provisioned: the daemon runs as _byn, but the human owner (a DIFFERENT UID)
	// must be able to connect(), so the socket is 0666 — a 0600 _byn socket would
	// deny the owner outright, before peercred is even consulted. Access stays
	// gated by peercred (dispatch rejects any UID != ownerUID), so the permissive
	// file mode does not widen real access; it only lets the owner reach the gate.
	sfi, err := os.Stat(d.SocketPath())
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if mode := sfi.Mode().Perm(); mode != 0o666 {
		t.Fatalf("socket mode = %o, want 0666 (owner-connectable, peercred-gated)", mode)
	}
}

// ownerUIDForTest returns a non-zero UID to pin Config.OwnerUID for bind tests,
// using this process's euid when non-zero, else a stand-in.
func ownerUIDForTest() uint32 {
	if euid := os.Geteuid(); euid > 0 {
		return uint32(euid) //nolint:gosec // euid > 0
	}
	return 501
}
