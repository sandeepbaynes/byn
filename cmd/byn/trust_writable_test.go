package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExecWritableDirs verifies the tool-state auto-grant resolution: existing
// curated defaults + declared [exec] writable are returned; non-existent defaults
// are skipped; a declared dir that escapes home is refused; a missing declared dir
// is skipped.
func TestExecWritableDirs(t *testing.T) {
	home := t.TempDir()
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{home}, parts...)...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		return p
	}
	cache := mk(".cache")         // existing curated default
	pnpm := mk("Library", "pnpm") // existing curated default
	proj := mk("myproj")          // project dir
	custom := mk("custom-store")  // declared writable that exists
	// .cargo is NOT created → a curated default that must be skipped.

	byn := filepath.Join(proj, ".byn")
	content := "[exec]\nwritable = [\"~/custom-store\", \"/etc\", \"~/does-not-exist\"]\n"
	if err := os.WriteFile(byn, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, d := range execWritableDirs(byn, home) {
		got[d] = true
	}

	if !got[cache] || !got[pnpm] {
		t.Errorf("existing curated defaults missing: %v", got)
	}
	if !got[custom] {
		t.Errorf("declared existing writable %q missing", custom)
	}
	if got[filepath.Join(home, ".cargo")] {
		t.Error("non-existent curated default .cargo must be skipped")
	}
	if got["/etc"] {
		t.Error("declared dir escaping home (/etc) must be refused")
	}
	if got[filepath.Join(home, "does-not-exist")] {
		t.Error("declared dir that does not exist must be skipped")
	}
}
