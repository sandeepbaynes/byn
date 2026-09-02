package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sandeepbaynes/byn/tools/gensite/site"
)

// stageDocs writes the minimal repo root run() needs: the manifest's source
// markdown, the CHANGELOG the site version is derived from, and the
// hand-authored landing page whose version gets stamped.
func stageDocs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range site.Manifest() {
		src := filepath.Join(root, "docs", filepath.FromSlash(p.SourceRel))
		require.NoError(t, os.MkdirAll(filepath.Dir(src), 0o755))
		body := "# " + p.SidebarTitle + "\n\nIntro paragraph.\n\n## Section one\n\nText.\n"
		require.NoError(t, os.WriteFile(src, []byte(body), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "CHANGELOG.md"),
		[]byte("# Changelog\n\n## v9.9.9 — 2026-01-01\n\nstuff\n"), 0o644))
	// The curated notes must name the release the CHANGELOG dates, or run()
	// refuses to publish a site whose footer points at notes that stop short of
	// it. The generic body written above has no version headings.
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "releases.md"),
		[]byte("# Release notes\n\nIntro paragraph.\n\n## v9.9.9\n\nText.\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "index.html"),
		[]byte(`<div class="hero-badge"><div class="badge-dot"></div>v0.0.1 — x</div>`+"\n"+
			`<span>byn <a href="docs/releases/">v0.0.1</a></span>`+"\n"), 0o644))
	return root
}

func TestRun_GeneratesAllPages(t *testing.T) {
	root := stageDocs(t)
	var out bytes.Buffer
	require.NoError(t, run([]string{"-root", root}, &out))
	assert.Contains(t, out.String(), "page(s) processed")

	for _, p := range site.Manifest() {
		outPath := filepath.Join(root, filepath.FromSlash(p.OutDir), "index.html")
		data, err := os.ReadFile(outPath) //nolint:gosec
		require.NoError(t, err, "expected generated %s", p.OutDir)
		assert.Contains(t, string(data), `<nav class="site-nav">`)
		assert.Contains(t, string(data), `<footer class="site-footer">`)
	}

	// A second run with no changes reports zero changed.
	out.Reset()
	require.NoError(t, run([]string{"-root", root}, &out))
	assert.Contains(t, out.String(), "0 changed")
}

func TestRun_BadFlag(t *testing.T) {
	require.Error(t, run([]string{"-nope"}, &bytes.Buffer{}))
}

func TestRun_CheckMode(t *testing.T) {
	root := stageDocs(t)
	// First pass writes everything.
	require.NoError(t, run([]string{"-root", root}, &bytes.Buffer{}))
	// Check mode on a freshly-generated tree must be clean.
	require.NoError(t, run([]string{"-root", root, "-check"}, &bytes.Buffer{}))

	// Mutate one output so it goes stale; check mode must now fail.
	stale := filepath.Join(root, "docs", "security", "index.html")
	require.NoError(t, os.WriteFile(stale, []byte("stale"), 0o644))
	err := run([]string{"-root", root, "-check"}, &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stale")
}

func TestRun_MissingDocsDir(t *testing.T) {
	err := run([]string{"-root", t.TempDir()}, &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docs dir")
}

func TestRun_MissingSourceFile(t *testing.T) {
	root := t.TempDir()
	// Create docs/ but leave the source files absent. The CHANGELOG is a
	// precondition for rendering anything — every page footer names the
	// release — so it has to be present for this test to reach the case it is
	// actually about.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "CHANGELOG.md"),
		[]byte("## v9.9.9 — 2026-01-01\n"), 0o644))
	// releases.md is a precondition for the same reason the CHANGELOG is: the
	// release-coverage check runs before any page is rendered, so without it this
	// test would report that failure instead of the missing source it is about.
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "releases.md"),
		[]byte("## v9.9.9\n"), 0o644))
	err := run([]string{"-root", root}, &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read source")
}

func TestWriteOrCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "index.html")

	// New file: changed=true, written.
	changed, err := writeOrCheck(path, "hello", false)
	require.NoError(t, err)
	assert.True(t, changed)
	got, err := os.ReadFile(path) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))

	// Identical content: changed=false.
	changed, err = writeOrCheck(path, "hello", false)
	require.NoError(t, err)
	assert.False(t, changed)

	// Different content in check mode: changed=true, not written.
	changed, err = writeOrCheck(path, "world", true)
	require.NoError(t, err)
	assert.True(t, changed)
	got, _ = os.ReadFile(path) //nolint:gosec
	assert.Equal(t, "hello", string(got), "check mode must not write")
}

func TestWriteOrCheck_MkdirError(t *testing.T) {
	dir := t.TempDir()
	// Make a regular file, then try to write "under" it as if it were a dir.
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o644))
	_, err := writeOrCheck(filepath.Join(blocker, "child", "index.html"), "data", false)
	require.Error(t, err)
}

func TestRelTo(t *testing.T) {
	assert.Equal(t, filepath.Join("docs", "x"), relTo("/root", filepath.Join("/root", "docs", "x")))
	// Unrelated absolute path still returns something usable.
	assert.NotEmpty(t, relTo("/root", "/other/path"))
}

// The site names the release the CHANGELOG names. Nobody has to remember to
// bump anything, which is the whole point: v0.5.0 shipped with the front page
// still saying v0.4.1 because the only thing keeping them in step was memory.
func TestRun_VersionComesFromTheChangelog(t *testing.T) {
	root := stageDocs(t)
	var out bytes.Buffer
	require.NoError(t, run([]string{"-root", root}, &out))

	landing, err := os.ReadFile(filepath.Join(root, "index.html")) //nolint:gosec
	require.NoError(t, err)
	assert.Contains(t, string(landing), `></div>v9.9.9`, "hero badge not stamped")
	assert.Contains(t, string(landing), `"docs/releases/">v9.9.9`, "footer not stamped")
	assert.NotContains(t, string(landing), "v0.0.1", "a stale version survived")

	page := filepath.Join(root, filepath.FromSlash(site.Manifest()[0].OutDir), "index.html")
	data, err := os.ReadFile(page) //nolint:gosec
	require.NoError(t, err)
	assert.Contains(t, string(data), "v9.9.9", "generated page footer has the wrong version")
}

// A landing page left at the previous release must fail -check, not pass
// quietly. This is the gate that was missing.
func TestRun_CheckModeCatchesAStaleLandingPage(t *testing.T) {
	root := stageDocs(t)
	var out bytes.Buffer
	require.NoError(t, run([]string{"-root", root}, &out))

	landing := filepath.Join(root, "index.html")
	data, err := os.ReadFile(landing) //nolint:gosec
	require.NoError(t, err)
	stale := bytes.ReplaceAll(data, []byte("v9.9.9"), []byte("v0.0.1"))
	require.NoError(t, os.WriteFile(landing, stale, 0o644))

	var checkOut bytes.Buffer
	err = run([]string{"-root", root, "-check"}, &checkOut)
	require.Error(t, err, "a stale landing page passed -check")
	assert.Contains(t, checkOut.String(), "stale: index.html")
}

// The version is a precondition, and a missing or unreadable CHANGELOG has to
// say so plainly: the alternative is a site published with a placeholder
// version, which is the failure this whole mechanism exists to prevent.
func TestRun_MissingChangelogIsNamed(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs"), 0o755))
	err := run([]string{"-root", root}, &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CHANGELOG.md")
}
