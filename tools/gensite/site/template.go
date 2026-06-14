package site

import (
	"bytes"
	"html/template"
	"strings"
)

// navItem is one entry in the shared top nav, with its computed href and active
// flag for the current page. External marks links opened in a new tab (GitHub).
type navItem struct {
	Label    string
	Href     string
	Active   bool
	External bool
}

// templateData is the fully-resolved view model handed to the page template.
// All hrefs are pre-computed relative to the page's output directory so the
// template stays logic-free.
type templateData struct {
	Lang             string
	Title            string // <title> and H1
	PageTitle        string // browser <title> ("X — byn docs")
	Description      string
	AssetPrefix      string // "../../" etc.
	LandingHref      string // AssetPrefix + "index.html"
	InstallHref      string // LandingHref + "#install"
	NavItems         []navItem
	Crumbs           []crumbView
	SidebarTitle     string
	SidebarBadge     string
	SidebarItems     []sbItem
	VersionStamp     string
	StampNote        string
	SourceURL        string // GitHub blob URL for doc-meta
	EditURL          string // GitHub edit URL; empty hides the edit link
	SourceLabel      string // text shown in doc-meta "Source: <label>"
	Body             template.HTML
	TOC              []tocItem
	ShowTOC          bool
	Prev             *NavLink
	Next             *NavLink
	FooterLinks      []navItem
	FooterSource     template.HTML // the "sourced from ..." span inner HTML
	Version          string        // current byn release, shown in the footer
	ReleaseNotesHref string        // relative URL to the in-site release-notes page
	ReleasesURL      string        // GitHub releases page (external)
}

type crumbView struct {
	Label   string
	Href    string
	Current bool
}

const pageTemplate = `<!DOCTYPE html>
<html lang="{{.Lang}}" data-theme="system">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.PageTitle}}</title>
<meta name="description" content="{{.Description}}">
<link rel="stylesheet" href="{{.AssetPrefix}}assets/site.css">
<script>document.documentElement.setAttribute('data-theme',localStorage.getItem('byn-theme')||'system')</script>
<script src="{{.AssetPrefix}}assets/site.js" defer></script>
</head>
<body>

<nav class="site-nav">
  <a href="{{.LandingHref}}" class="nav-logo">
    <div class="nav-mark"><svg viewBox="0 0 32 32" fill="none"><path d="M16 7a5 5 0 0 0-5 5v3H9a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-9a1 1 0 0 0-1-1h-2v-3a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v3h-6v-3a3 3 0 0 1 3-3zm0 8a2 2 0 0 1 1 3.73V22h-2v-1.27A2 2 0 0 1 16 17z" fill="#34d8a0"/></svg></div>
    <span class="nav-name">byn</span>
  </a>
  <div class="nav-links">
{{- range .NavItems}}
    <a href="{{.Href}}"{{if .Active}} class="active"{{end}}{{if .External}} target="_blank" rel="noopener"{{end}}>{{.Label}}</a>
{{- end}}
  </div>
  <div class="nav-right">
    <div class="theme-toggle">
      <button class="theme-btn" data-theme="light"><svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="6" cy="6" r="2.5"/><line x1="6" y1=".5" x2="6" y2="1.5"/><line x1="6" y1="10.5" x2="6" y2="11.5"/><line x1=".5" y1="6" x2="1.5" y2="6"/><line x1="10.5" y1="6" x2="11.5" y2="6"/><line x1="2.1" y1="2.1" x2="2.8" y2="2.8"/><line x1="9.2" y1="9.2" x2="9.9" y2="9.9"/><line x1="9.9" y1="2.1" x2="9.2" y2="2.8"/><line x1="2.8" y1="9.2" x2="2.1" y2="9.9"/></svg>Light</button>
      <button class="theme-btn" data-theme="dark"><svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M10 7.5A5 5 0 0 1 4.5 2a4.5 4.5 0 1 0 5.5 5.5z"/></svg>Dark</button>
      <button class="theme-btn active" data-theme="system"><svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="2" width="10" height="7" rx="1.5"/><line x1="4" y1="11" x2="8" y2="11"/><line x1="6" y1="9" x2="6" y2="11"/></svg>System</button>
    </div>
    <a href="{{.InstallHref}}" class="btn-nav-cta">Install →</a>
  </div>
</nav>

<div class="docs-layout">

  <aside class="docs-sidebar">
    <div class="sb-section">
      <div class="sb-title">{{.SidebarTitle}}</div>
      <a href="./" class="sb-item active">{{.Title}}{{if .SidebarBadge}} <span class="sb-badge">{{.SidebarBadge}}</span>{{end}}</a>
{{- range .SidebarItems}}
      <a href="{{.Href}}" class="sb-item">{{.Text}}</a>
{{- end}}
    </div>
  </aside>

  <main class="docs-main">
    <div class="breadcrumb">
      <a href="{{.LandingHref}}" style="color:var(--faint);text-decoration:none;">Home</a>
{{- range .Crumbs}}
      <span class="sep">/</span>
{{- if .Current}}
      <span style="color:var(--text);font-weight:600;">{{.Label}}</span>
{{- else}}
      <a href="{{.Href}}" style="color:var(--faint);text-decoration:none;">{{.Label}}</a>
{{- end}}
{{- end}}
    </div>

    <h1>{{.Title}}</h1>
    <div class="doc-meta">
      <span>Source: <a href="{{.SourceURL}}">{{.SourceLabel}}</a></span>
{{- if .EditURL}}
      <span>·</span>
      <a href="{{.EditURL}}">Edit on GitHub ↗</a>
{{- end}}
    </div>
{{- if .VersionStamp}}

    <div class="version-stamp">
      <span>Coverage:</span>
      <strong>{{.VersionStamp}}</strong>
      <span>·</span>
      <span>{{.StampNote}}</span>
    </div>
{{- end}}

{{.Body}}
{{- if or .Prev .Next}}

    <div class="docs-nav">
{{- if .Prev}}
      <a href="{{.Prev.Href}}" class="docs-nav-btn">
        <div class="nav-btn-label">{{.Prev.Label}}</div>
        <div class="nav-btn-title">{{.Prev.Title}}</div>
      </a>
{{- else}}
      <div></div>
{{- end}}
{{- if .Next}}
      <a href="{{.Next.Href}}" class="docs-nav-btn" style="text-align:right;">
        <div class="nav-btn-label">{{.Next.Label}}</div>
        <div class="nav-btn-title">{{.Next.Title}}</div>
      </a>
{{- end}}
    </div>
{{- end}}
  </main>
{{- if .ShowTOC}}

  <nav class="docs-toc docs-toc-col">
    <div class="toc-title">On this page</div>
{{- range .TOC}}
    <a href="{{.Href}}" class="toc-item{{if .Sub}} sub{{end}}">{{.Text}}</a>
{{- end}}
  </nav>
{{- end}}

</div>

<footer class="site-footer">
  <div class="footer-brand">
    <div class="nav-mark" style="width:20px;height:20px;border-radius:5px;"><svg width="12" height="12" viewBox="0 0 32 32"><path d="M16 7a5 5 0 0 0-5 5v3H9a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-9a1 1 0 0 0-1-1h-2v-3a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v3h-6v-3a3 3 0 0 1 3-3zm0 8a2 2 0 0 1 1 3.73V22h-2v-1.27A2 2 0 0 1 16 17z" fill="#34d8a0"/></svg></div>
    <span>byn <a href="{{.ReleaseNotesHref}}">{{.Version}}</a> · docs sourced from {{.FooterSource}}</span>
  </div>
  <div>
{{- range .FooterLinks}}
    <a href="{{.Href}}">{{.Label}}</a>
{{- end}}
    <a href="{{.ReleaseNotesHref}}">Release notes</a>
    <a href="{{.ReleasesURL}}" target="_blank" rel="noopener">Releases ↗</a>
  </div>
</footer>

</body>
</html>`

var compiledTemplate = template.Must(template.New("page").Parse(pageTemplate))

// renderPage executes the page template into the final HTML string.
func renderPage(d templateData) (string, error) {
	var buf bytes.Buffer
	if err := compiledTemplate.Execute(&buf, d); err != nil {
		return "", err
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out, nil
}
