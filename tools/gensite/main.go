// Command gensite renders byn's hand-authored markdown docs into the themed
// static HTML published on the gh-pages branch. The markdown under docs/ is the
// single source of truth; this tool is the only path that produces the HTML, so
// the two can never drift.
//
// Usage:
//
//	go run ./tools/gensite              # generate into ./docs/<name>/index.html
//	go run ./tools/gensite -root DIR    # operate on a different checkout root
//	go run ./tools/gensite -check       # fail if any output would change (CI)
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sandeepbaynes/byn/tools/gensite/site"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gensite:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("gensite", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root (contains docs/ and assets/)")
	check := fs.Bool("check", false, "do not write; exit non-zero if any output differs")
	if err := fs.Parse(args); err != nil {
		return err
	}

	docsDir := filepath.Join(*root, "docs")
	if _, err := os.Stat(docsDir); err != nil {
		return fmt.Errorf("docs dir %q not found (run from repo root or pass -root): %w", docsDir, err)
	}

	pages := site.Manifest()
	changed := 0
	for _, p := range pages {
		srcPath := filepath.Join(docsDir, filepath.FromSlash(p.SourceRel))
		src, err := os.ReadFile(srcPath) //nolint:gosec // path derived from static manifest
		if err != nil {
			return fmt.Errorf("read source %s: %w", p.SourceRel, err)
		}

		htmlOut, err := site.RenderPage(p, string(src))
		if err != nil {
			return err
		}

		outPath := filepath.Join(*root, filepath.FromSlash(p.OutDir), "index.html")
		diff, err := writeOrCheck(outPath, htmlOut, *check)
		if err != nil {
			return err
		}
		if diff {
			changed++
			if *check {
				_, _ = fmt.Fprintf(out, "stale: %s\n", relTo(*root, outPath))
			} else {
				_, _ = fmt.Fprintf(out, "wrote %s\n", relTo(*root, outPath))
			}
		}
	}

	if *check && changed > 0 {
		return fmt.Errorf("%d generated page(s) are stale — run `make site`", changed)
	}
	_, _ = fmt.Fprintf(out, "gensite: %d page(s) processed, %d changed\n", len(pages), changed)
	return nil
}

// writeOrCheck writes content to path (creating parent dirs) unless checkOnly,
// in which case it only reports whether the on-disk content differs. The bool
// return is true when the file is new or would change.
func writeOrCheck(path, content string, checkOnly bool) (bool, error) {
	existing, err := os.ReadFile(path) //nolint:gosec // path derived from static manifest
	switch {
	case err == nil:
		if string(existing) == content {
			return false, nil
		}
	case os.IsNotExist(err):
		// new file
	default:
		return false, fmt.Errorf("stat %s: %w", path, err)
	}

	if checkOnly {
		return true, nil
	}

	if mkErr := os.MkdirAll(filepath.Dir(path), 0o750); mkErr != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), mkErr)
	}
	if wErr := os.WriteFile(path, []byte(content), 0o644); wErr != nil { //nolint:gosec // public static HTML
		return false, fmt.Errorf("write %s: %w", path, wErr)
	}
	return true, nil
}

func relTo(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return r
	}
	return path
}
