package site

import (
	"strings"
)

// NavKey identifies which top-level nav item is active for a page. It matches
// the shared nav.site-nav links: Docs / CLI reference / Security / Field notes.
type NavKey string

// The NavKey constants name each top-level nav item, used to set the active
// state on the shared nav for the current page.
const (
	NavDocs       NavKey = "docs"
	NavCLI        NavKey = "cli"
	NavSecurity   NavKey = "security"
	NavFieldNotes NavKey = "fieldnotes"
)

// Crumb is one breadcrumb segment. A linked crumb has an Href; the current
// (last) crumb sets Current and renders as bold text.
type Crumb struct {
	Label   string
	Href    string // relative to the page's output dir
	Current bool   // the current page — rendered bold, not linked
}

// NavLink is a prev/next pager entry at the foot of a doc page.
type NavLink struct {
	Label string // "← Previous" / "Next →"
	Title string // human title of the target
	Href  string // relative href
}

// Page is one unit of output: a source markdown file plus the curated chrome
// metadata needed to place it in the site (where it writes, its depth for asset
// paths, which nav item is active, breadcrumbs, the GitHub source link, and the
// optional prev/next pager).
//
// The manifest (see manifest.go) is the single place that curation lives —
// everything *inside* a page (title, description, sidebar sections, TOC) is
// derived from the markdown itself, which is the maintenance win: editing a
// doc's headings updates its nav automatically.
type Page struct {
	// SourceRel is the markdown path relative to the docs root, e.g.
	// "security.md" or "field-notes/tool-comparison.md".
	SourceRel string
	// OutDir is the output directory relative to the site root, e.g.
	// "docs/security" or "docs/field-notes/tool-comparison". The file written
	// is OutDir/index.html.
	OutDir string
	// Nav is which top-level nav item is highlighted.
	Nav NavKey
	// Crumbs are the breadcrumb trail (excluding the implicit Home root, which
	// the template always prepends).
	Crumbs []Crumb
	// SidebarTitle is the heading of the auto-generated sidebar's first
	// section (e.g. "Security", "Field notes"). Defaults to the page title.
	SidebarTitle string
	// SidebarBadge is an optional small badge on the sidebar's self-link
	// (e.g. "v0.2.0", "5 min"). Empty renders no badge.
	SidebarBadge string
	// VersionStamp, when non-empty, renders the coverage version-stamp banner
	// under the title (e.g. "v0.2.0") with StampNote as its trailing text.
	VersionStamp string
	StampNote    string
	// Prev/Next render the bottom pager. Nil entries are omitted.
	Prev *NavLink
	Next *NavLink
	// GitHubPath is the repo-relative path the doc-meta "Source"/"Edit" links
	// point at (e.g. "docs/security.md"). Empty hides the edit link.
	GitHubPath string
	// IsSectionIndex marks the docs home / field-notes index pages, which use a
	// hand-derived listing body instead of an auto TOC column.
	IsSectionIndex bool
	// NoTOC suppresses the right-hand on-this-page column (section indexes and
	// short pages without H2s).
	NoTOC bool
}

// Depth is how many directory levels OutDir sits below the site root, which
// determines the "../" prefix for shared assets and the landing page.
func (p Page) Depth() int {
	if p.OutDir == "" {
		return 0
	}
	return strings.Count(p.OutDir, "/") + 1
}

// AssetPrefix is the relative path from this page back to the site root, used
// for assets/, the landing index.html, and cross-page links. Depth 2
// ("docs/security") yields "../../".
func (p Page) AssetPrefix() string {
	return strings.Repeat("../", p.Depth())
}

// derivedTitle returns the front-matter title if set, else the H1 from the
// rendered body, else a humanised file name as a last resort.
func derivedTitle(fm FrontMatter, r Rendered, sourceRel string) string {
	if fm.Title != "" {
		return fm.Title
	}
	if r.Title != "" {
		return r.Title
	}
	return humanizeSlug(baseSlug(sourceRel))
}

// derivedDescription returns the front-matter description if set, else the
// document's first paragraph (plain text), else "".
func derivedDescription(fm FrontMatter, r Rendered) string {
	if fm.Description != "" {
		return fm.Description
	}
	return r.FirstPara
}

// baseSlug strips the directory and ".md" extension from a source path.
func baseSlug(sourceRel string) string {
	s := sourceRel
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSuffix(s, ".md")
}

// humanizeSlug turns "why-not-containers" into "Why not containers".
func humanizeSlug(slug string) string {
	parts := strings.FieldsFunc(slug, func(r rune) bool { return r == '-' || r == '_' })
	if len(parts) == 0 {
		return slug
	}
	parts[0] = strings.ToUpper(parts[0][:1]) + parts[0][1:]
	return strings.Join(parts, " ")
}

// sidebarSections builds the content-derived sidebar entries from the doc's H2
// headings. This deliberately REPLACES the old hand-curated per-page sidebars:
// the doc's own section structure is the nav. The self-link (to the page root)
// always leads, followed by one anchor link per H2.
func sidebarItems(r Rendered) []sbItem {
	items := make([]sbItem, 0, len(r.Headings))
	for _, h := range r.Headings {
		if h.Level != 2 || h.ID == "" {
			continue
		}
		items = append(items, sbItem{Text: h.Text, Href: "#" + h.ID})
	}
	return items
}

type sbItem struct {
	Text string
	Href string
}

// tocEntries builds the on-this-page TOC from H2 (and nested H3) headings.
func tocEntries(r Rendered) []tocItem {
	items := make([]tocItem, 0, len(r.Headings))
	for _, h := range r.Headings {
		if h.ID == "" {
			continue
		}
		items = append(items, tocItem{Text: h.Text, Href: "#" + h.ID, Sub: h.Level == 3})
	}
	return items
}

type tocItem struct {
	Text string
	Href string
	Sub  bool
}
