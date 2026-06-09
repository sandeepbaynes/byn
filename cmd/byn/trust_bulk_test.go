package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBynPaths(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"proj1", "proj2", "nested/deep"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, ".byn"), []byte("[scope]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	loose := filepath.Join(root, "loose.byn")
	if err := os.WriteFile(loose, []byte("[scope]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A directory resolves to <dir>/.byn.
	if got := resolveBynPaths([]string{filepath.Join(root, "proj1")}, false); len(got) != 1 ||
		got[0] != filepath.Join(root, "proj1", ".byn") {
		t.Fatalf("dir resolution = %v", got)
	}
	// An explicit file path is taken as-is (any name).
	if got := resolveBynPaths([]string{loose}, false); len(got) != 1 || got[0] != loose {
		t.Fatalf("file = %v", got)
	}
	// Recursive finds every file named exactly .byn (not loose.byn).
	if got := resolveBynPaths([]string{root}, true); len(got) != 3 {
		t.Fatalf("recursive found %d, want 3: %v", len(got), got)
	}
	// Duplicates are removed.
	if got := resolveBynPaths([]string{loose, loose}, false); len(got) != 1 {
		t.Fatalf("dedup = %v", got)
	}

	// Relative inputs resolve to ABSOLUTE paths — the daemon reads them relative
	// to its own cwd, not the caller's, so relative paths would 404 (regression:
	// `byn trust --recursive` from a project directory).
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	rel := resolveBynPaths([]string{"."}, true)
	if len(rel) != 3 {
		t.Fatalf("recursive from cwd found %d, want 3: %v", len(rel), rel)
	}
	for _, p := range rel {
		if !filepath.IsAbs(p) {
			t.Fatalf("resolved path is not absolute: %q", p)
		}
	}
}
