package site

import (
	"fmt"
	"html/template"
	"strings"
)

// repoBlobBase / repoTreeBase are the GitHub URL roots for the doc-meta and
// footer "source" links. The main branch is the canonical source per the
// footer text ("sourced from .../docs").
const (
	repoBlobBase = "https://github.com/sandeepbaynes/byn/blob/main/"
	repoEditBase = "https://github.com/sandeepbaynes/byn/edit/main/"
	repoTreeBase = "https://github.com/sandeepbaynes/byn/tree/main/"
	repoRoot     = "https://github.com/sandeepbaynes/byn"
)

// navSpec is the static definition of the shared top nav, resolved per-page to
// relative hrefs + active state.
var navSpec = []struct {
	Label string
	Key   NavKey
	// rel is the href relative to the docs root (depth 1); RenderPage rewrites
	// it for the page's actual depth.
	relFromDocs string
	external    bool
}{
	{Label: "Docs", Key: NavDocs, relFromDocs: "./"},
	{Label: "CLI reference", Key: NavCLI, relFromDocs: "./cli-reference/"},
	{Label: "Security", Key: NavSecurity, relFromDocs: "./security/"},
	{Label: "Field notes", Key: NavFieldNotes, relFromDocs: "./field-notes/"},
	{Label: "GitHub", Key: "", relFromDocs: repoRoot, external: true},
}

// RenderPage converts a page's source markdown into its final themed HTML. The
// markdown body is parsed once; the title, description, sidebar, and TOC are all
// derived from it (front matter overrides where present).
func RenderPage(p Page, source string) (string, error) {
	fm, body := SplitFrontMatter(source)
	r, err := Render(body)
	if err != nil {
		return "", fmt.Errorf("render markdown for %s: %w", p.SourceRel, err)
	}

	title := derivedTitle(fm, r, p.SourceRel)
	desc := derivedDescription(fm, r)

	d := templateData{
		Lang:        "en",
		Title:       title,
		PageTitle:   title + " — byn docs",
		Description: desc,
		AssetPrefix: p.AssetPrefix(),
		Body:        template.HTML(indentBody(r.HTML)), //nolint:gosec // trusted first-party docs
	}
	d.LandingHref = d.AssetPrefix + "index.html"
	d.InstallHref = d.LandingHref + "#install"

	d.NavItems = buildNav(p)
	d.Crumbs = buildCrumbs(p, d.LandingHref)
	d.SidebarTitle = sidebarTitle(p, title)
	d.SidebarBadge = p.SidebarBadge
	d.SidebarItems = sidebarItems(r)
	d.VersionStamp = p.VersionStamp
	d.StampNote = p.StampNote

	d.SourceURL, d.EditURL, d.SourceLabel = sourceLinks(p)
	d.FooterSource = footerSource(p)
	d.FooterLinks = footerLinks(p)

	d.TOC = tocEntries(r)
	d.ShowTOC = !p.NoTOC && len(d.TOC) > 0
	d.Prev = p.Prev
	d.Next = p.Next

	return renderPage(d)
}

// buildNav resolves the shared nav to hrefs relative to page p and marks the
// active item.
func buildNav(p Page) []navItem {
	prefix := p.AssetPrefix()
	items := make([]navItem, 0, len(navSpec))
	for _, n := range navSpec {
		href := n.relFromDocs
		if !n.external {
			href = rewriteDocsRel(n.relFromDocs, prefix)
		}
		items = append(items, navItem{
			Label:    n.Label,
			Href:     href,
			Active:   n.Key != "" && n.Key == p.Nav,
			External: n.external,
		})
	}
	return items
}

// rewriteDocsRel turns an href expressed relative to the docs root ("./",
// "./security/") into one relative to a page at the given asset prefix. The docs
// root sits one level below the site root, so "{prefix}docs/" is the docs root
// from any page.
func rewriteDocsRel(rel, prefix string) string {
	switch {
	case rel == "./":
		return prefix + "docs/"
	case strings.HasPrefix(rel, "./"):
		return prefix + "docs/" + strings.TrimPrefix(rel, "./")
	default:
		return rel
	}
}

// buildCrumbs resolves breadcrumb hrefs (which the manifest expresses relative
// to the page's own directory) and marks the trailing current crumb.
func buildCrumbs(p Page, _ string) []crumbView {
	out := make([]crumbView, 0, len(p.Crumbs))
	for _, c := range p.Crumbs {
		out = append(out, crumbView{Label: c.Label, Href: c.Href, Current: c.Current || c.Href == ""})
	}
	return out
}

// sidebarTitle returns the curated sidebar section title, defaulting to the page
// title when the manifest leaves it blank.
func sidebarTitle(p Page, title string) string {
	if p.SidebarTitle != "" {
		return p.SidebarTitle
	}
	return title
}

// sourceLinks builds the doc-meta "Source" + "Edit on GitHub" URLs and the
// visible label. A GitHubPath without a ".md" suffix (a directory, e.g. the
// field-notes index) gets a tree link and no edit link.
func sourceLinks(p Page) (sourceURL, editURL, label string) {
	if p.GitHubPath == "" {
		return repoRoot, "", "GitHub"
	}
	if strings.HasSuffix(p.GitHubPath, ".md") {
		return repoBlobBase + p.GitHubPath, repoEditBase + p.GitHubPath, p.GitHubPath
	}
	// Directory source (section index): link the tree, show a trailing slash.
	return repoTreeBase + p.GitHubPath, "", p.GitHubPath + "/"
}

// footerSource builds the inner HTML of the footer "sourced from ..." link.
func footerSource(p Page) template.HTML {
	if p.GitHubPath != "" && !strings.HasSuffix(p.GitHubPath, ".md") {
		href := repoTreeBase + p.GitHubPath
		label := "github.com/sandeepbaynes/byn/" + p.GitHubPath
		return template.HTML(fmt.Sprintf(`<a href="%s">%s</a>`, href, template.HTMLEscapeString(label))) //nolint:gosec
	}
	href := repoBlobBase + p.GitHubPath
	return template.HTML(fmt.Sprintf(`<a href="%s">github.com/sandeepbaynes/byn/docs</a>`, href)) //nolint:gosec
}

// footerLinks returns the small footer link row. It mirrors the existing pages:
// Home plus a couple of cross-links keyed off the page's section.
func footerLinks(p Page) []navItem {
	prefix := p.AssetPrefix()
	home := navItem{Label: "Home", Href: prefix + "index.html"}
	docsRoot := prefix + "docs/"
	switch p.Nav {
	case NavFieldNotes:
		return []navItem{home, {Label: "Quickstart", Href: docsRoot}, {Label: "Security model", Href: docsRoot + "security/"}}
	case NavSecurity:
		return []navItem{home, {Label: "Quickstart", Href: docsRoot}, {Label: "CLI Reference", Href: docsRoot + "cli-reference/"}}
	case NavCLI:
		return []navItem{home, {Label: "Quickstart", Href: docsRoot}, {Label: "Security", Href: docsRoot + "security/"}}
	default:
		return []navItem{home, {Label: "CLI Reference", Href: docsRoot + "cli-reference/"}, {Label: "Security", Href: docsRoot + "security/"}}
	}
}

// indentBody re-indents the rendered markdown HTML so it nests cleanly inside
// <main class="docs-main"> (four spaces), matching the hand-authored pages.
func indentBody(htmlBody string) string {
	lines := strings.Split(htmlBody, "\n")
	var b strings.Builder
	for i, ln := range lines {
		if ln != "" {
			b.WriteString("    ")
			b.WriteString(ln)
		}
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
