package site

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// samplePage models a depth-2 doc page (docs/security) for chrome assertions.
func samplePage() Page {
	return Page{
		SourceRel:    "security.md",
		OutDir:       "docs/security",
		Nav:          NavSecurity,
		Crumbs:       []Crumb{{Label: "Docs", Href: "../"}, {Label: "Security model", Current: true}},
		SidebarTitle: "Security",
		SidebarBadge: "v0.2.0",
		VersionStamp: "v0.2.0",
		StampNote:    "Updated each release",
		GitHubPath:   "docs/security.md",
		Prev:         &NavLink{Label: "← Previous", Title: "CLI Reference", Href: "../cli-reference/"},
		Next:         &NavLink{Label: "Next →", Title: "Why not containers?", Href: "../why-not-containers/"},
	}
}

const sampleMD = "# Security model\n\nWhat byn defends against, and what it doesn't.\n\n## Threat model\n\nText about threats.\n\n### In scope\n\nDetails.\n\n## Crypto stack\n\nPrimitives.\n"

func TestRenderPage_Landmarks(t *testing.T) {
	html, err := RenderPage(samplePage(), sampleMD)
	require.NoError(t, err)

	// Document shell.
	assert.True(t, strings.HasPrefix(html, "<!DOCTYPE html>"))
	assert.Contains(t, html, `<html lang="en" data-theme="system">`)
	assert.Contains(t, html, "<title>Security model — byn docs</title>")
	assert.Contains(t, html, `<meta name="description" content="What byn defends against, and what it doesn`)

	// Depth-2 asset paths.
	assert.Contains(t, html, `<link rel="stylesheet" href="../../assets/site.css">`)
	assert.Contains(t, html, `<script src="../../assets/site.js" defer></script>`)
	assert.Contains(t, html, `href="../../index.html#install"`)

	// Shared nav with the right active item.
	assert.Contains(t, html, `<nav class="site-nav">`)
	assert.Contains(t, html, `<a href="../../docs/security/" class="active">Security</a>`)
	assert.Contains(t, html, `<a href="https://github.com/sandeepbaynes/byn" target="_blank" rel="noopener">GitHub</a>`)
	assert.Contains(t, html, `class="theme-toggle"`)

	// Layout landmarks.
	assert.Contains(t, html, `<div class="docs-layout">`)
	assert.Contains(t, html, `<aside class="docs-sidebar">`)
	assert.Contains(t, html, `<main class="docs-main">`)
	assert.Contains(t, html, `<footer class="site-footer">`)

	// Title + doc-meta + version stamp.
	assert.Contains(t, html, "<h1>Security model</h1>")
	assert.Contains(t, html, `Source: <a href="https://github.com/sandeepbaynes/byn/blob/main/docs/security.md">docs/security.md</a>`)
	assert.Contains(t, html, `href="https://github.com/sandeepbaynes/byn/edit/main/docs/security.md"`)
	assert.Contains(t, html, `<div class="version-stamp">`)
	assert.Contains(t, html, "<strong>v0.2.0</strong>")
}

func TestRenderPage_AutoSidebarFromH2(t *testing.T) {
	html, err := RenderPage(samplePage(), sampleMD)
	require.NoError(t, err)

	// Sidebar self-link with badge, then one entry per H2 (not H3).
	assert.Contains(t, html, `<div class="sb-title">Security</div>`)
	assert.Contains(t, html, `<a href="./" class="sb-item active">Security model <span class="sb-badge">v0.2.0</span></a>`)
	assert.Contains(t, html, `<a href="#threat-model" class="sb-item">Threat model</a>`)
	assert.Contains(t, html, `<a href="#crypto-stack" class="sb-item">Crypto stack</a>`)
	assert.NotContains(t, html, `<a href="#in-scope" class="sb-item">`, "H3 must not appear in the sidebar")
}

func TestRenderPage_AutoTOCFromHeadings(t *testing.T) {
	html, err := RenderPage(samplePage(), sampleMD)
	require.NoError(t, err)

	assert.Contains(t, html, `<nav class="docs-toc docs-toc-col">`)
	assert.Contains(t, html, `<div class="toc-title">On this page</div>`)
	assert.Contains(t, html, `<a href="#threat-model" class="toc-item">Threat model</a>`)
	// H3 renders as a sub-item.
	assert.Contains(t, html, `<a href="#in-scope" class="toc-item sub">In scope</a>`)
	assert.Contains(t, html, `<a href="#crypto-stack" class="toc-item">Crypto stack</a>`)
}

func TestRenderPage_TOCAnchorsResolveToBodyIDs(t *testing.T) {
	html, err := RenderPage(samplePage(), sampleMD)
	require.NoError(t, err)
	// Each TOC anchor must have a matching id in the body.
	for _, id := range []string{"threat-model", "in-scope", "crypto-stack"} {
		assert.Contains(t, html, `href="#`+id+`"`)
		assert.Contains(t, html, `id="`+id+`"`)
	}
}

func TestRenderPage_Breadcrumbs(t *testing.T) {
	html, err := RenderPage(samplePage(), sampleMD)
	require.NoError(t, err)
	assert.Contains(t, html, `<a href="../../index.html" style="color:var(--faint);text-decoration:none;">Home</a>`)
	assert.Contains(t, html, `<a href="../" style="color:var(--faint);text-decoration:none;">Docs</a>`)
	assert.Contains(t, html, `<span style="color:var(--text);font-weight:600;">Security model</span>`)
}

func TestRenderPage_PrevNextPager(t *testing.T) {
	html, err := RenderPage(samplePage(), sampleMD)
	require.NoError(t, err)
	assert.Contains(t, html, `<div class="docs-nav">`)
	assert.Contains(t, html, `<div class="nav-btn-label">← Previous</div>`)
	assert.Contains(t, html, `<div class="nav-btn-title">CLI Reference</div>`)
	assert.Contains(t, html, `<div class="nav-btn-label">Next →</div>`)
	assert.Contains(t, html, `<div class="nav-btn-title">Why not containers?</div>`)
}

func TestRenderPage_Footer(t *testing.T) {
	html, err := RenderPage(samplePage(), sampleMD)
	require.NoError(t, err)
	assert.Contains(t, html,
		`byn docs · sourced from <a href="https://github.com/sandeepbaynes/byn/blob/main/docs/security.md">github.com/sandeepbaynes/byn/docs</a>`)
}

func TestRenderPage_BodyContent(t *testing.T) {
	html, err := RenderPage(samplePage(), sampleMD)
	require.NoError(t, err)
	// First paragraph rendered, indented into main.
	assert.Contains(t, html, "    <p>What byn defends against, and what it doesn't.</p>")
	// Body H2 carries its id.
	assert.Contains(t, html, `<h2 id="threat-model">Threat model</h2>`)
}

func TestRenderPage_SectionIndexNoTOC(t *testing.T) {
	p := Page{
		SourceRel:      "field-notes/README.md",
		OutDir:         "docs/field-notes",
		Nav:            NavFieldNotes,
		Crumbs:         []Crumb{{Label: "Docs", Href: "../"}, {Label: "Field notes", Current: true}},
		SidebarTitle:   "Field notes",
		GitHubPath:     "docs/field-notes",
		IsSectionIndex: true,
		NoTOC:          true,
	}
	md := "# Field notes\n\nA listing intro.\n\n## All notes\n\n- [One](one.md)\n"
	html, err := RenderPage(p, md)
	require.NoError(t, err)

	assert.NotContains(t, html, `class="docs-toc`, "section index must omit the on-this-page column")
	// Directory source → tree link, no edit link.
	assert.Contains(t, html, `https://github.com/sandeepbaynes/byn/tree/main/docs/field-notes`)
	assert.NotContains(t, html, "Edit on GitHub")
	// Footer for a directory source names the subtree.
	assert.Contains(t, html, "github.com/sandeepbaynes/byn/docs/field-notes")
	// Intra-doc .md link rewritten.
	assert.Contains(t, html, `href="one/"`)
}

func TestRenderPage_TitleFallbackNoFrontMatter(t *testing.T) {
	// No front matter, no H1 — title falls back to the humanised file name and
	// the description to the first paragraph.
	p := samplePage()
	p.SidebarBadge = ""
	html, err := RenderPage(p, "Some intro paragraph.\n\n## A section\n")
	require.NoError(t, err)
	assert.Contains(t, html, "<h1>Security</h1>", "falls back to humanised slug from SourceRel")
	assert.Contains(t, html, `content="Some intro paragraph."`)
}

func TestRenderPage_FrontMatterOverrides(t *testing.T) {
	html, err := RenderPage(samplePage(),
		"---\ntitle: Custom Title\ndescription: Custom description.\n---\n## Body section\n\nx\n")
	require.NoError(t, err)
	assert.Contains(t, html, "<title>Custom Title — byn docs</title>")
	assert.Contains(t, html, "<h1>Custom Title</h1>")
	assert.Contains(t, html, `content="Custom description."`)
}

func TestPageDepthAndAssetPrefix(t *testing.T) {
	assert.Equal(t, 0, Page{OutDir: ""}.Depth())
	assert.Equal(t, 1, Page{OutDir: "docs"}.Depth())
	assert.Equal(t, 2, Page{OutDir: "docs/security"}.Depth())
	assert.Equal(t, 3, Page{OutDir: "docs/field-notes/note"}.Depth())

	assert.Equal(t, "", Page{OutDir: ""}.AssetPrefix())
	assert.Equal(t, "../", Page{OutDir: "docs"}.AssetPrefix())
	assert.Equal(t, "../../", Page{OutDir: "docs/security"}.AssetPrefix())
}

func TestManifest_Valid(t *testing.T) {
	pages := Manifest()
	require.NotEmpty(t, pages)
	seen := map[string]bool{}
	for _, p := range pages {
		assert.NotEmpty(t, p.SourceRel, "every page needs a source")
		assert.NotEmpty(t, p.OutDir, "every page needs an output dir")
		assert.False(t, seen[p.OutDir], "duplicate OutDir %q", p.OutDir)
		seen[p.OutDir] = true
		// Last crumb must be the current page.
		require.NotEmpty(t, p.Crumbs)
		assert.True(t, p.Crumbs[len(p.Crumbs)-1].Current, "last crumb of %s must be current", p.OutDir)
	}
}

func TestManifest_RendersWithSampleBody(t *testing.T) {
	// Every manifest page must render without error given a minimal body.
	for _, p := range Manifest() {
		t.Run(p.OutDir, func(t *testing.T) {
			html, err := RenderPage(p, "# "+p.SidebarTitle+"\n\nIntro.\n\n## A\n\nx\n")
			require.NoError(t, err)
			assert.Contains(t, html, "<nav class=\"site-nav\">")
			assert.Contains(t, html, "<footer class=\"site-footer\">")
		})
	}
}
