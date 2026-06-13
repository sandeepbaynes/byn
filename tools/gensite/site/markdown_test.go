package site

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRender_HeadingsAndTOC(t *testing.T) {
	md := "# Title\n\nFirst paragraph here.\n\n## Threat model\n\nText.\n\n### In scope\n\nMore.\n\n## Crypto stack\n\nText.\n"
	r, err := Render(md)
	require.NoError(t, err)

	assert.Equal(t, "Title", r.Title)
	assert.Equal(t, "First paragraph here.", r.FirstPara)

	require.Len(t, r.Headings, 3)
	assert.Equal(t, Heading{Level: 2, Text: "Threat model", ID: "threat-model"}, r.Headings[0])
	assert.Equal(t, Heading{Level: 3, Text: "In scope", ID: "in-scope"}, r.Headings[1])
	assert.Equal(t, Heading{Level: 2, Text: "Crypto stack", ID: "crypto-stack"}, r.Headings[2])
}

func TestRender_DropsLeadingH1(t *testing.T) {
	r, err := Render("# Page Title\n\nBody.\n")
	require.NoError(t, err)
	assert.Equal(t, "Page Title", r.Title)
	assert.NotContains(t, r.HTML, "<h1", "leading H1 must be removed from body to avoid duplication")
	assert.Contains(t, r.HTML, "<p>Body.</p>")
}

func TestRender_HeadingIDsMatchAnchors(t *testing.T) {
	// The id in the rendered <h2> must equal the id used for the TOC anchor.
	r, err := Render("## Known weaknesses\n\nx\n")
	require.NoError(t, err)
	require.Len(t, r.Headings, 1)
	assert.Contains(t, r.HTML, `id="`+r.Headings[0].ID+`"`)
}

func TestRender_Tables(t *testing.T) {
	md := "| A | B |\n|---|---|\n| 1 | 2 |\n"
	r, err := Render(md)
	require.NoError(t, err)
	assert.Contains(t, r.HTML, "<table>")
	assert.Contains(t, r.HTML, "<th>A</th>")
	assert.Contains(t, r.HTML, "<td>1</td>")
}

func TestRender_FencedCode(t *testing.T) {
	md := "```\nbyn unlock\n```\n"
	r, err := Render(md)
	require.NoError(t, err)
	assert.Contains(t, r.HTML, "<pre><code>")
	assert.Contains(t, r.HTML, "byn unlock")
}

func TestRender_InlineHTMLPreserved(t *testing.T) {
	// Docs embed badge/callout HTML; the unsafe renderer must keep it.
	md := "A line with <span class=\"badge badge-ok\">ok</span> inline.\n"
	r, err := Render(md)
	require.NoError(t, err)
	assert.Contains(t, r.HTML, `<span class="badge badge-ok">ok</span>`)
}

func TestRender_Autolink(t *testing.T) {
	r, err := Render("See https://example.com for more.\n")
	require.NoError(t, err)
	assert.Contains(t, r.HTML, `<a href="https://example.com"`)
}

func TestRender_HeadingTextStripsInlineCode(t *testing.T) {
	r, err := Render("## byn `exec` command\n\nx\n")
	require.NoError(t, err)
	require.Len(t, r.Headings, 1)
	assert.Equal(t, "byn exec command", r.Headings[0].Text)
}

func TestRender_NoH1FirstParaStillFound(t *testing.T) {
	r, err := Render("Just a paragraph, no heading.\n\n## H2\n")
	require.NoError(t, err)
	assert.Empty(t, r.Title)
	assert.Equal(t, "Just a paragraph, no heading.", r.FirstPara)
}

func TestRewriteMDDest(t *testing.T) {
	cases := []struct{ in, want string }{
		{"security.md", "security/"},
		{"security.md#crypto", "security/#crypto"},
		{"../why-not-containers.md", "../why-not-containers/"},
		{"field-notes/README.md", "field-notes/"},
		{"README.md", "./"},
		{"../README.md", "../"},
		{"index.md", "./"},
		{"#anchor", "#anchor"},
		{"https://example.com/page.md", "https://example.com/page.md"},
		{"mailto:x@example.com", "mailto:x@example.com"},
		{"styles.css", "styles.css"},
		{"image.png", "image.png"},
		{"", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			assert.Equal(t, c.want, rewriteMDDest(c.in))
		})
	}
}

func TestRewriteMarkdownLinks_InBody(t *testing.T) {
	r, err := Render("See the [security model](security.md#crypto) and [field notes](field-notes/README.md).\n")
	require.NoError(t, err)
	assert.Contains(t, r.HTML, `href="security/#crypto"`)
	assert.Contains(t, r.HTML, `href="field-notes/"`)
}

func TestIsExternalLink(t *testing.T) {
	assert.True(t, isExternalLink("https://x.com"))
	assert.True(t, isExternalLink("http://x.com"))
	assert.True(t, isExternalLink("//x.com"))
	assert.True(t, isExternalLink("mailto:a@b.c"))
	assert.False(t, isExternalLink("docs/x.md"))
	assert.False(t, isExternalLink("../x.md"))
}

func TestHumanizeSlug(t *testing.T) {
	assert.Equal(t, "Why not containers", humanizeSlug("why-not-containers"))
	assert.Equal(t, "Cli reference", humanizeSlug("cli_reference"))
	assert.Equal(t, "Single", humanizeSlug("single"))
}

func TestBaseSlug(t *testing.T) {
	assert.Equal(t, "security", baseSlug("security.md"))
	assert.Equal(t, "tool-comparison", baseSlug("field-notes/tool-comparison.md"))
}

func TestDerivedTitleAndDescription(t *testing.T) {
	r := Rendered{Title: "H1 Title", FirstPara: "Intro para."}

	// Front matter wins.
	fm := FrontMatter{Title: "FM Title", Description: "FM desc."}
	assert.Equal(t, "FM Title", derivedTitle(fm, r, "x.md"))
	assert.Equal(t, "FM desc.", derivedDescription(fm, r))

	// Falls back to H1 / first paragraph.
	empty := FrontMatter{}
	assert.Equal(t, "H1 Title", derivedTitle(empty, r, "x.md"))
	assert.Equal(t, "Intro para.", derivedDescription(empty, r))

	// Last resort: humanised slug.
	bare := Rendered{}
	assert.Equal(t, "Why not containers", derivedTitle(empty, bare, "why-not-containers.md"))
	assert.Empty(t, derivedDescription(empty, bare))
}

func TestIndentBody(t *testing.T) {
	got := indentBody("<p>a</p>\n\n<p>b</p>")
	assert.Equal(t, "    <p>a</p>\n\n    <p>b</p>", got)
	// Blank lines are not indented (no trailing whitespace).
	assert.False(t, strings.Contains(got, "    \n"))
}
