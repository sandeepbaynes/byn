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

// stageDocs writes the minimal set of source markdown files the manifest
// expects into a temp repo root, so run() can render against them.
func stageDocs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range site.Manifest() {
		src := filepath.Join(root, "docs", filepath.FromSlash(p.SourceRel))
		require.NoError(t, os.MkdirAll(filepath.Dir(src), 0o755))
		body := "# " + p.SidebarTitle + "\n\nIntro paragraph.\n\n## Section one\n\nText.\n"
		require.NoError(t, os.WriteFile(src, []byte(body), 0o644))
	}
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
	// Create docs/ but leave the source files absent.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs"), 0o755))
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
