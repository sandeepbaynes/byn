//go:build !byntest

package paths

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resolveDataDir is the pure selector: the system path when provisioned (it
// exists on disk), otherwise the legacy ~/.byn. Both branches are exercised
// without touching the real /var/lib.
func TestResolveDataDir(t *testing.T) {
	legacy := func() (string, error) { return "/home/u/.byn", nil }

	got, err := resolveDataDir("/var/lib/byn", true, legacy)
	if err != nil || got != "/var/lib/byn" {
		t.Fatalf("provisioned: got %q, err %v; want /var/lib/byn", got, err)
	}

	got, err = resolveDataDir("/var/lib/byn", false, legacy)
	if err != nil || got != "/home/u/.byn" {
		t.Fatalf("unprovisioned: got %q, err %v; want /home/u/.byn", got, err)
	}

	if _, err := resolveDataDir("/var/lib/byn", false,
		func() (string, error) { return "", errors.New("no home") }); err == nil {
		t.Fatal("expected the legacy resolver error to propagate")
	}
}

// In a bare (unprovisioned) environment the system path does not exist, so
// DataDir falls back to the legacy per-user ~/.byn — preserving today's
// behavior for opt-in-off installs (spec D3).
func TestDataDir_UnprovisionedFallsBackToLegacy(t *testing.T) {
	if _, statErr := os.Stat(systemDataDir()); statErr == nil {
		t.Skipf("host has a provisioned %s; skipping legacy-fallback assertion", systemDataDir())
	}
	got, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir() error: %v", err)
	}
	home, _ := os.UserHomeDir()
	if want := filepath.Join(home, ".byn"); got != want {
		t.Fatalf("DataDir() = %q, want legacy %q", got, want)
	}
}

// No env var may move the production data root: the removed BYN_DIR override and
// the byntest-only BYN_TEST_DIR must both be inert in a production build. This
// is the core §6.5 security property (no repointable data root).
func TestDataDir_NoEnvOverride(t *testing.T) {
	t.Setenv("BYN"+"_DIR", "/tmp/should-be-ignored") // the removed override
	t.Setenv("BYN_TEST_DIR", "/tmp/also-ignored")    // the byntest-only seam
	got, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir() error: %v", err)
	}
	if strings.Contains(got, "should-be-ignored") || strings.Contains(got, "also-ignored") {
		t.Fatalf("DataDir() honored an env override in a production build: %q", got)
	}
}

func TestSocketPath_NonEmpty(t *testing.T) {
	if SocketPath() == "" {
		t.Fatal("SocketPath() is empty")
	}
}

// OwnerRecordPath is the active data root plus "/owner".
func TestOwnerRecordPath(t *testing.T) {
	d, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir() error: %v", err)
	}
	want := filepath.Join(d, "owner")
	got, err := OwnerRecordPath()
	if err != nil {
		t.Fatalf("OwnerRecordPath() error: %v", err)
	}
	if got != want {
		t.Fatalf("OwnerRecordPath() = %q, want %q", got, want)
	}
}
