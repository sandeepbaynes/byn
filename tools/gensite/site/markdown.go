package site

import (
	"bytes"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
)

// Heading is one H2/H3 pulled from a rendered doc, used to build the on-this-page
// TOC and the content-derived left sidebar.
type Heading struct {
	Level int    // 2 or 3
	Text  string // plain-text content, entities decoded
	ID    string // anchor id goldmark assigned (matches the rendered HTML)
}

// Rendered is the result of converting one markdown document: the HTML body
// (the inner content that drops into <main class="docs-main">), the H1 title
// found in the source, the first paragraph as plain text, and the ordered
// H2/H3 headings.
type Rendered struct {
	HTML      string
	Title     string
	FirstPara string
	Headings  []Heading
}

// newMarkdown builds a goldmark instance with the feature set the site needs:
// GFM tables, strikethrough, task lists, autolinks (all via extension.GFM),
// and auto-generated heading ids so the TOC anchors resolve. Hard wraps stay
// off to match the existing hand-authored HTML.
func newMarkdown() goldmark.Markdown {
	return goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
		),
		goldmark.WithRendererOptions(
			html.WithUnsafe(), // docs embed inline HTML (badges, callouts)
		),
	)
}

// Render converts a markdown body to HTML and extracts the structural metadata
// (title, first paragraph, headings) the templates need. The same parsed AST is
// used for both rendering and extraction so heading anchor ids are guaranteed
// to match between the TOC links and the rendered <h2 id="...">.
//
// The leading H1 is extracted as the page Title and removed from the rendered
// body — the chrome renders the title as its own <h1>, so leaving it in would
// duplicate it. Its text is still reported in Rendered.Title.
func Render(body string) (Rendered, error) {
	md := newMarkdown()
	source := []byte(body)
	reader := text.NewReader(source)
	doc := md.Parser().Parse(reader)

	r := Rendered{}
	extractMeta(doc, source, &r)
	dropLeadingH1(doc)
	rewriteMarkdownLinks(doc)

	var buf bytes.Buffer
	if err := md.Renderer().Render(&buf, source, doc); err != nil {
		return Rendered{}, err
	}
	r.HTML = strings.TrimRight(buf.String(), "\n")
	return r, nil
}

// rewriteMarkdownLinks turns intra-repo "*.md" links (written for GitHub
// viewing) into the site's pretty directory URLs, so a doc that links to
// "security.md" resolves to "security/" once rendered. External URLs, in-page
// anchors, and non-markdown assets are left untouched.
func rewriteMarkdownLinks(doc ast.Node) {
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if link, ok := n.(*ast.Link); ok {
			link.Destination = []byte(rewriteMDDest(string(link.Destination)))
		}
		return ast.WalkContinue, nil
	})
}

// rewriteMDDest rewrites a single link destination. It is exported via tests in
// the same package; the rules are documented on rewriteMarkdownLinks.
func rewriteMDDest(dest string) string {
	if dest == "" || isExternalLink(dest) || strings.HasPrefix(dest, "#") {
		return dest
	}
	path, anchor := dest, ""
	if i := strings.IndexByte(dest, '#'); i >= 0 {
		path, anchor = dest[:i], dest[i:]
	}
	if !strings.HasSuffix(path, ".md") {
		return dest
	}
	trimmed := strings.TrimSuffix(path, ".md")
	// A README maps to its containing directory ("dir/README.md" -> "dir/").
	if base := lastSegment(trimmed); base == "README" || base == "index" {
		trimmed = strings.TrimSuffix(trimmed, base)
		if trimmed == "" {
			trimmed = "./"
		}
		return trimmed + anchor
	}
	return trimmed + "/" + anchor
}

// isExternalLink reports whether a destination has a URL scheme or is
// protocol-relative — i.e. not a repo-local path we should rewrite.
func isExternalLink(dest string) bool {
	if strings.HasPrefix(dest, "//") || strings.HasPrefix(dest, "mailto:") {
		return true
	}
	if i := strings.Index(dest, "://"); i > 0 {
		// Only treat as scheme if the prefix is alphabetic (avoids matching a
		// path that happens to contain "://" after a fragment, which is rare).
		for _, r := range dest[:i] {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
				return false
			}
		}
		return true
	}
	return false
}

func lastSegment(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// dropLeadingH1 removes the first top-level H1 from the document so the chrome's
// own <h1> is the only title. Only a document-level first child that is an H1 is
// removed; H1s deeper in the body (rare) are left untouched.
func dropLeadingH1(doc ast.Node) {
	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		if h, ok := c.(*ast.Heading); ok && h.Level == 1 {
			doc.RemoveChild(doc, c)
			return
		}
		// Stop at the first non-heading block — the title H1 is expected first.
		if _, ok := c.(*ast.Heading); !ok {
			return
		}
	}
}

// extractMeta walks the AST collecting the first H1's text (title), the first
// paragraph's text (description fallback), and every H2/H3 with its id.
func extractMeta(doc ast.Node, source []byte, r *Rendered) {
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch node := n.(type) {
		case *ast.Heading:
			text := nodeText(node, source)
			switch {
			case node.Level == 1 && r.Title == "":
				r.Title = text
			case node.Level == 2 || node.Level == 3:
				id := headingID(node)
				r.Headings = append(r.Headings, Heading{
					Level: node.Level,
					Text:  text,
					ID:    id,
				})
			}
		case *ast.Paragraph:
			if r.FirstPara == "" {
				r.FirstPara = nodeText(node, source)
			}
		}
		return ast.WalkContinue, nil
	})
}

// headingID returns the id goldmark's AutoHeadingID assigned to a heading, or
// "" if none (e.g. an empty heading). Stored under parser.attrNameID.
func headingID(h *ast.Heading) string {
	if id, ok := h.AttributeString("id"); ok {
		if b, ok := id.([]byte); ok {
			return string(b)
		}
	}
	return ""
}

// nodeText flattens a node's text content to a plain string, decoding the few
// HTML entities goldmark emits for raw text so the TOC/sidebar read naturally.
func nodeText(n ast.Node, source []byte) string {
	var b strings.Builder
	collectText(n, source, &b)
	return strings.TrimSpace(b.String())
}

func collectText(n ast.Node, source []byte, b *strings.Builder) {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch t := c.(type) {
		case *ast.Text:
			b.Write(t.Segment.Value(source))
		case *ast.String:
			b.Write(t.Value)
		case *ast.RawHTML:
			// Skip inline HTML tags in heading text (e.g. <code>) but keep
			// nested text by recursing.
			collectText(c, source, b)
		default:
			collectText(c, source, b)
		}
	}
}
