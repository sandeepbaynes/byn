package ui

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestAssets_JSSyntax runs `node --check` on every .js file in the embedded
// assets directory to catch non-parsing JS before it reaches production.
// The test is skipped (not failed) when node is not in PATH so that machines
// without Node.js do not block CI.
func TestAssets_JSSyntax(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not in PATH — skipping JS syntax check")
	}

	var jsFiles []string
	err = fs.WalkDir(assetsFS, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".js" {
			jsFiles = append(jsFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk assets: %v", err)
	}

	if len(jsFiles) == 0 {
		t.Fatal("no .js files found in assets — check embed path")
	}

	for _, path := range jsFiles {
		t.Run(filepath.Base(path), func(t *testing.T) {
			src, err := assetsFS.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			// Write to a temp file — node --check requires a real path.
			tmp := t.TempDir()
			dst := filepath.Join(tmp, filepath.Base(path))
			if err := os.WriteFile(dst, src, 0o644); err != nil {
				t.Fatalf("write temp file: %v", err)
			}

			cmd := exec.Command(nodePath, "--check", dst)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("node --check %s failed:\n%s", path, out)
			}
		})
	}
}
