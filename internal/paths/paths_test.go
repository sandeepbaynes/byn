//go:build !byntest

package paths

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// In a production build (no byntest tag), DataDir must be the fixed per-OS
// system path — and crucially must NOT honor any env override. A repointable
// data root in production is attack surface (spec §6.5).
func TestDataDir_FixedSystemPath(t *testing.T) {
	want := map[string]string{
		"linux":  "/var/lib/byn",
		"darwin": "/Library/Application Support/byn",
	}[runtime.GOOS]
	if want == "" {
		want = "/var/lib/byn" // paths_other.go stub
	}
	if got := DataDir(); got != want {
		t.Fatalf("DataDir() = %q, want %q", got, want)
	}
}

// No env var may move the production data root. We try the removed legacy
// override and the test seam's BYN_TEST_DIR — neither must be honored without
// the byntest tag.
func TestDataDir_NoEnvOverride(t *testing.T) {
	t.Setenv("BYN"+"_DIR", "/tmp/should-be-ignored") // the removed override
	t.Setenv("BYN_TEST_DIR", "/tmp/also-ignored")
	got := DataDir()
	if strings.Contains(got, "should-be-ignored") || strings.Contains(got, "also-ignored") {
		t.Fatalf("DataDir() honored an env override in a production build: %q", got)
	}
}

func TestSocketPath_NonEmpty(t *testing.T) {
	if SocketPath() == "" {
		t.Fatal("SocketPath() is empty")
	}
}

// OwnerRecordPath is the data root plus "/owner".
func TestOwnerRecordPath(t *testing.T) {
	want := DataDir() + "/owner"
	if got := OwnerRecordPath(); got != want {
		t.Fatalf("OwnerRecordPath() = %q, want %q", got, want)
	}
}

// Belt-and-braces: a stray BYN_TEST_DIR in the environment of a production
// build is inert.
func TestNoTestSeamInProductionBuild(t *testing.T) {
	const sentinel = "/tmp/byn-prod-seam-sentinel"
	_ = os.Setenv("BYN_TEST_DIR", sentinel)
	t.Cleanup(func() { _ = os.Unsetenv("BYN_TEST_DIR") })
	if strings.Contains(DataDir(), "sentinel") {
		t.Fatal("test seam leaked into a production build")
	}
}
