//go:build integration

package integration

import (
	"strings"
	"testing"
)

func TestE2E_EnvClear(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("vx", "put", "X"); code != 0 {
		t.Fatal("put X failed")
	}
	if _, _, code := s.run("vy", "put", "Y"); code != 0 {
		t.Fatal("put Y failed")
	}

	// Without --yes: a preview that does NOT delete.
	_, stderr, code := s.run("", "env", "clear")
	if code == 0 {
		t.Fatal("env clear without --yes should exit non-zero (preview)")
	}
	if !strings.Contains(stderr, "--yes") {
		t.Fatalf("preview should mention --yes:\n%s", stderr)
	}
	if out, _ := s.mustRun("", "list"); !strings.Contains(out, "X") || !strings.Contains(out, "Y") {
		t.Fatalf("preview must not delete; list=%q", out)
	}

	// With --yes: cleared.
	if _, _, code := s.run("", "env", "clear", "--yes"); code != 0 {
		t.Fatalf("env clear --yes failed: %d", code)
	}
	if out, _ := s.mustRun("", "list"); strings.Contains(out, "X") || strings.Contains(out, "Y") {
		t.Fatalf("vars not cleared; list=%q", out)
	}
}
