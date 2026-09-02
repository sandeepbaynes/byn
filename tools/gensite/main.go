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

	// The version the site shows comes from CHANGELOG.md, which is dated as
	// part of releasing anyway. Deriving it means the site cannot be left
	// naming the previous release, which is exactly what happened at v0.5.0.
	changelog, err := os.ReadFile(filepath.Join(*root, "CHANGELOG.md")) //nolint:gosec // repo root from a flag
	if err != nil {
		return fmt.Errorf("read CHANGELOG.md (needed for the site version): %w", err)
	}
	version, err := site.VersionFromChangelog(changelog)
	if err != nil {
		return fmt.Errorf("CHANGELOG.md: %w", err)
	}
	site.Version = version

	// Refuse to publish a site whose footer names a release its own notes do not
	// describe. See site.ReleaseNotesCover for why this is a build failure rather
	// than a checklist item.
	notes, err := os.ReadFile(filepath.Join(*root, "docs", "releases.md")) //nolint:gosec // repo root from a flag
	if err != nil {
		return fmt.Errorf("read docs/releases.md (needed to check release coverage): %w", err)
	}
	if newest, ok := site.ReleaseNotesCover(notes, version); !ok {
		return fmt.Errorf(
			"docs/releases.md has no section for %s (newest is %s) — CHANGELOG.md dates %s, "+
				"so every page would footer that version and link to notes that stop short of it; "+
				"add a %q section with the headline changes and an \"Upgrade notes\" subsection",
			version, dashIfEmpty(newest), version, "## "+version)
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

	// The landing page is hand-authored HTML, not one of the manifest pages, so
	// it has to be stamped separately — and it is the page that was wrong.
	landingPath := filepath.Join(*root, "index.html")
	landing, err := os.ReadFile(landingPath) //nolint:gosec // repo root from a flag
	if err != nil {
		return fmt.Errorf("read landing page: %w", err)
	}
	stamped, err := site.StampLanding(string(landing), version)
	if err != nil {
		return err
	}
	diff, err := writeOrCheck(landingPath, stamped, *check)
	if err != nil {
		return err
	}
	if diff {
		changed++
		if *check {
			_, _ = fmt.Fprintf(out, "stale: %s\n", relTo(*root, landingPath))
		} else {
			_, _ = fmt.Fprintf(out, "wrote %s\n", relTo(*root, landingPath))
		}
	}

	if *check && changed > 0 {
		return fmt.Errorf("%d generated page(s) are stale — run `make site`", changed)
	}
	_, _ = fmt.Fprintf(out, "gensite: %s, %d page(s) processed, %d changed\n", version, len(pages), changed)
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

// dashIfEmpty renders an absent value as a dash, so an empty release-notes file
// reads as "newest is -" rather than "newest is ".
func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
