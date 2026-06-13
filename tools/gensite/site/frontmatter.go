// Package site renders byn's hand-authored markdown docs into the themed
// static HTML that ships on the gh-pages branch. It is the single render path
// so the markdown sources stay the source of truth and never drift from HTML.
package site

import (
	"strings"
)

// FrontMatter holds the optional, leading "key: value" block of a doc. Every
// field is optional: when absent the renderer derives sensible defaults from
// the document body (title from the first H1, description from the first
// paragraph), so docs never need editing just to render.
type FrontMatter struct {
	Title       string
	Description string
	Section     string
	NavOrder    int
	hasNavOrder bool
}

// HasNavOrder reports whether a nav_order key was present in the front matter.
func (f FrontMatter) HasNavOrder() bool { return f.hasNavOrder }

// SplitFrontMatter separates an optional leading front-matter block from the
// markdown body. Two forms are accepted, both terminated by a blank line or
// end of block:
//
//   - A YAML-style fence delimited by "---" lines:
//     ---
//     title: Security model
//     ---
//   - A bare leading key block (no fences) where every line until the first
//     blank line is "key: value".
//
// If no front matter is recognised the whole input is returned as the body and
// an empty FrontMatter — the graceful-degradation path. The "---" used as a
// markdown horizontal rule *after* prose is never mistaken for front matter
// because a fence must be the very first line of the file.
func SplitFrontMatter(src string) (FrontMatter, string) {
	// Normalise leading whitespace lines but keep the body offset accurate.
	trimmed := strings.TrimLeft(src, "\n")
	if strings.HasPrefix(trimmed, "---\n") || trimmed == "---" {
		if fm, body, ok := parseFencedFrontMatter(trimmed); ok {
			return fm, body
		}
	}
	if fm, body, ok := parseBareFrontMatter(trimmed); ok {
		return fm, body
	}
	return FrontMatter{}, src
}

// parseFencedFrontMatter handles the "---\n...\n---\n" form.
func parseFencedFrontMatter(s string) (FrontMatter, string, bool) {
	rest := strings.TrimPrefix(s, "---\n")
	if rest == s { // no opening fence consumed
		return FrontMatter{}, "", false
	}
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return FrontMatter{}, "", false
	}
	block := rest[:end]
	body := rest[end+len("\n---"):]
	body = strings.TrimPrefix(body, "\n")
	fm, ok := parseKeyBlock(block)
	if !ok {
		return FrontMatter{}, "", false
	}
	return fm, body, true
}

// parseBareFrontMatter handles a leading "key: value" block with no fences. It
// only triggers when the first line itself looks like a known front-matter key,
// so ordinary prose (or an H1) is never consumed.
func parseBareFrontMatter(s string) (FrontMatter, string, bool) {
	nl := strings.Index(s, "\n\n")
	var block, body string
	if nl < 0 {
		block, body = s, ""
	} else {
		block, body = s[:nl], s[nl+2:]
	}
	first := strings.SplitN(block, "\n", 2)[0]
	if !looksLikeFrontMatterKey(first) {
		return FrontMatter{}, "", false
	}
	fm, ok := parseKeyBlock(block)
	if !ok {
		return FrontMatter{}, "", false
	}
	return fm, body, true
}

// looksLikeFrontMatterKey reports whether a line is one of the recognised
// front-matter keys, e.g. "title: foo". Used to gate the fence-less form so a
// markdown heading or paragraph is not swallowed as front matter.
func looksLikeFrontMatterKey(line string) bool {
	key, _, ok := splitKeyValue(line)
	if !ok {
		return false
	}
	switch key {
	case "title", "description", "section", "nav_order":
		return true
	}
	return false
}

// parseKeyBlock parses recognised keys from a block of "key: value" lines. An
// unrecognised key is ignored (forward-compatible). It fails only when no
// recognised key is present so callers can fall back to body derivation.
func parseKeyBlock(block string) (FrontMatter, bool) {
	var fm FrontMatter
	matched := false
	for _, line := range strings.Split(block, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, val, ok := splitKeyValue(line)
		if !ok {
			continue
		}
		switch key {
		case "title":
			fm.Title = val
			matched = true
		case "description":
			fm.Description = val
			matched = true
		case "section":
			fm.Section = val
			matched = true
		case "nav_order":
			if n, ok := atoi(val); ok {
				fm.NavOrder = n
				fm.hasNavOrder = true
				matched = true
			}
		}
	}
	return fm, matched
}

// splitKeyValue splits "key: value", trimming surrounding whitespace and any
// matching single/double quotes around the value.
func splitKeyValue(line string) (key, val string, ok bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	val = strings.TrimSpace(line[idx+1:])
	val = trimMatchingQuotes(val)
	return key, val, true
}

func trimMatchingQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// atoi parses a base-10 int without pulling in strconv error semantics into the
// hot path; returns ok=false on any non-digit content.
func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	neg := false
	digits := 0
	for i, r := range s {
		if i == 0 && r == '-' {
			neg = true
			continue
		}
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
		digits++
	}
	if digits == 0 {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}
