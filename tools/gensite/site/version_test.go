package site

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionFromChangelog_TakesTheNewestRelease(t *testing.T) {
	got, err := VersionFromChangelog([]byte(`# Changelog

## v0.5.0 — 2026-08-31

things

## v0.4.1

older things
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != "v0.5.0" {
		t.Errorf("version = %q, want v0.5.0", got)
	}
}

// A dated heading is a release; "unreleased" is not a version to put on a
// website, and the next heading down is the one that shipped.
func TestVersionFromChangelog_SkipsAnUnreleasedHeading(t *testing.T) {
	got, err := VersionFromChangelog([]byte(`# Changelog

## v0.5.1 — unreleased

being written

## v0.5.0 — 2026-08-31

shipped
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != "v0.5.0" {
		t.Errorf("version = %q, want v0.5.0 — the site must not name a release nobody can install", got)
	}
}

func TestVersionFromChangelog_NeedsADatedRelease(t *testing.T) {
	if _, err := VersionFromChangelog([]byte("# Changelog\n\nnothing here\n")); err == nil {
		t.Error("a CHANGELOG with no release heading should be an error, not a default")
	}
	if _, err := VersionFromChangelog([]byte("# Changelog\n\n## v9.9.9 — unreleased\n")); err == nil {
		t.Error("an unreleased heading alone should be an error, not a version")
	}
}

// The real file has to parse, or the site build fails at release time — which
// is the worst possible moment to find out.
func TestVersionFromChangelog_TheRealChangelogParses(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read CHANGELOG: %v", err)
	}
	got, err := VersionFromChangelog(b)
	if err != nil {
		t.Fatalf("the shipped CHANGELOG does not parse: %v", err)
	}
	if !strings.HasPrefix(got, "v") {
		t.Errorf("version = %q, want a v-prefixed release", got)
	}
}

func TestStampLanding_RewritesBothSpots(t *testing.T) {
	src := `<div class="hero-badge"><div class="badge-dot"></div>v0.4.1 — macOS &amp; Linux</div>
<p>a note about v0.3.0 in prose, which must not be touched</p>
<span>byn <a href="docs/releases/">v0.4.1</a> · Sandeep Baynes</span>`
	got, err := StampLanding(src, "v0.5.0")
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if strings.Contains(got, "></div>v0.4.1") || strings.Contains(got, `"docs/releases/">v0.4.1`) {
		t.Errorf("a version spot was left stale:\n%s", got)
	}
	if !strings.Contains(got, "></div>v0.5.0") || !strings.Contains(got, `"docs/releases/">v0.5.0`) {
		t.Errorf("a version spot was not stamped:\n%s", got)
	}
	// Prose is not a version spot. A loose match would rewrite history.
	if !strings.Contains(got, "a note about v0.3.0 in prose") {
		t.Error("prose mentioning an older version was rewritten")
	}
}

// A spot that stops matching must be an error. Silently rewriting nothing is
// how the landing page came to disagree with the release in the first place.
func TestStampLanding_MissingMarkerIsAnError(t *testing.T) {
	if _, err := StampLanding(`<div class="hero-badge">v0.4.1</div>`, "v0.5.0"); err == nil {
		t.Fatal("changed markup silently produced no error")
	}
}
