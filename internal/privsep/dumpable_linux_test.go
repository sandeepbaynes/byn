//go:build linux

package privsep

import (
	"testing"

	"golang.org/x/sys/unix"
)

// SetUndumpable lowers the process's own dumpable flag via
// prctl(PR_SET_DUMPABLE, 0). Lowering one's OWN dumpable flag is unprivileged,
// so this runs without root (in CI's Linux job and on any Linux dev box). We
// save + restore the flag via PR_GET/SET_DUMPABLE so the rest of the test
// binary is unaffected by the change.
func TestSetUndumpable(t *testing.T) {
	prev, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE (initial): %v", err)
	}
	t.Cleanup(func() {
		// Restore so subsequent tests in this binary keep the original posture.
		_ = unix.Prctl(unix.PR_SET_DUMPABLE, uintptr(prev), 0, 0, 0)
	})

	if err := SetUndumpable(); err != nil {
		t.Fatalf("SetUndumpable() = %v, want nil", err)
	}

	got, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE (after set): %v", err)
	}
	if got != 0 {
		t.Fatalf("dumpable = %d after SetUndumpable(), want 0", got)
	}
}
