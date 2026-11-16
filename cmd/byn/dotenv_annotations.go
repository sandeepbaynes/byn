// Descriptions and notes in a .env file.
//
// A comment block directly above a variable belongs to it:
//
//	# what this is for          ← description (one line per line of it)
//	# and how to use it
//	## account 1234 on the team plan   ← a note, one per line
//	## rotated 2026-09
//	API_KEY=...
//
// `#` lines form the description; a line starting with `##` (or more) is a
// note. Once a note has started, later `#` lines in the same block are
// dropped, so a description never gets split around a note. A blank line ends
// the block: a comment separated from the variable by one is a heading for
// the file, not something about this value.
//
// A commented-out assignment (`# OLD_KEY=sk_live_...`) is never read as a
// description. A description is plaintext that any tool reaching byn can
// read, and an old secret sitting in a comment is exactly what must not land
// there. It ends the block instead, because the lines above it were about the
// commented-out variable, not the next one.
//
// One more thing a comment can say. A line that is exactly the word `unsecure`
// (or `secure`), in any case, is not text about the variable but an instruction
// about how to store it:
//
//	# unsecure
//	# the port the dev server listens on
//	PORT=8080
//
// An unsecure value is stored unsealed and can be read with no password (see
// `byn help unsecure`). The marker belongs to the ONE variable directly below
// it, like every other line of the block — a blank line ends its reach, so it
// can never apply to a stretch of a file by accident. Everything unmarked is
// sealed, which is why `# secure` is accepted but only ever needed to overrule
// `byn import --unsecure-names`.
package main

import (
	"regexp"
	"strings"
)

// entryAnnotations is what a .env comment block carries for one variable.
type entryAnnotations struct {
	desc  string
	notes []string
	// marker is markerUnsecure or markerSecure when the block said so, else "".
	marker string
}

const (
	markerUnsecure = "unsecure"
	markerSecure   = "secure"
)

func (a entryAnnotations) empty() bool {
	return a.desc == "" && len(a.notes) == 0 && a.marker == ""
}

// storageMarker reads a comment's text as a storage instruction: the whole
// line must be the one word. "unsecure by default" is a description.
func storageMarker(body string) string {
	switch strings.ToLower(strings.TrimSpace(body)) {
	case markerUnsecure:
		return markerUnsecure
	case markerSecure:
		return markerSecure
	}
	return ""
}

// commentedAssignment matches the text of a comment that is really a
// disabled KEY=value line.
var commentedAssignment = regexp.MustCompile(`^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=`)

// commentBlock accumulates the comment lines above the next assignment.
type commentBlock struct {
	desc    []string
	notes   []string
	inNotes bool
	marker  string
}

func (c *commentBlock) reset() { *c = commentBlock{} }

// add takes one trimmed line that starts with '#'.
func (c *commentBlock) add(line string) {
	body := strings.TrimLeft(line, "#")
	hashes := len(line) - len(body)
	body = strings.TrimPrefix(body, " ")
	// Read before anything else, so it counts wherever in the block it sits
	// and never ends up stored as a description. Single `#` only: `## unsecure`
	// is a note that says "unsecure", which is somebody's remark, not an order.
	if hashes == 1 {
		if m := storageMarker(body); m != "" {
			c.marker = m
			return
		}
	}
	if hashes >= 2 {
		c.inNotes = true
		if t := strings.TrimSpace(body); t != "" {
			c.notes = append(c.notes, t)
		}
		return
	}
	if c.inNotes {
		return
	}
	if commentedAssignment.MatchString(body) {
		c.reset()
		return
	}
	c.desc = append(c.desc, strings.TrimRight(body, " \t"))
}

// take returns the block's annotations and clears it for the next variable.
func (c *commentBlock) take() entryAnnotations {
	out := entryAnnotations{
		desc:   strings.Trim(strings.Join(c.desc, "\n"), "\n"),
		notes:  c.notes,
		marker: c.marker,
	}
	c.reset()
	return out
}

// renderAnnotationComments writes a's comment block, or nothing. A
// description keeps its line breaks, one `#` line each; a note is one `##`
// line, so any line breaks inside it become spaces.
func renderAnnotationComments(b *strings.Builder, a entryAnnotations) {
	// First, so it is the first thing read about the variable. Only ever
	// `unsecure`: sealed is what an unmarked variable already is.
	if a.marker == markerUnsecure {
		b.WriteString("# " + markerUnsecure + "\n")
	}
	if a.desc != "" {
		for _, ln := range strings.Split(strings.ReplaceAll(a.desc, "\r\n", "\n"), "\n") {
			ln = strings.TrimRight(ln, " \t")
			if ln == "" {
				b.WriteString("#\n")
				continue
			}
			b.WriteString("# " + ln + "\n")
		}
	}
	for _, n := range a.notes {
		n = strings.Join(strings.Fields(n), " ")
		if n == "" {
			continue
		}
		b.WriteString("## " + n + "\n")
	}
}
