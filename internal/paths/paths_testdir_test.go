//go:build byntest

package paths

import "testing"

// Under the byntest tag, BYN_TEST_DIR repoints the data root so tests can
// isolate a tempdir. This path is compiled ONLY into test binaries.
func TestDataDir_HonorsBynTestDir(t *testing.T) {
	t.Setenv("BYN_TEST_DIR", "/tmp/byn-seam-check")
	got, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir() error: %v", err)
	}
	if got != "/tmp/byn-seam-check" {
		t.Fatalf("DataDir() = %q, want /tmp/byn-seam-check", got)
	}
	if got := SocketPath(); got != "/tmp/byn-seam-check/daemon.sock" {
		t.Fatalf("SocketPath() = %q, want /tmp/byn-seam-check/daemon.sock", got)
	}
	or, err := OwnerRecordPath()
	if err != nil {
		t.Fatalf("OwnerRecordPath() error: %v", err)
	}
	if or != "/tmp/byn-seam-check/owner" {
		t.Fatalf("OwnerRecordPath() = %q, want /tmp/byn-seam-check/owner", or)
	}
}

// When BYN_TEST_DIR is unset, the seam falls back to /tmp/byn-test.
func TestDataDir_DefaultsToTmp(t *testing.T) {
	t.Setenv("BYN_TEST_DIR", "")
	got, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir() error: %v", err)
	}
	if got != "/tmp/byn-test" {
		t.Fatalf("DataDir() = %q, want /tmp/byn-test", got)
	}
}
