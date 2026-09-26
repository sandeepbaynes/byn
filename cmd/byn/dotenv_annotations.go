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
package main

import (
	"regexp"
	"strings"
)

// entryAnnotations is what a .env comment block carries for one variable.
type entryAnnotations struct {
	desc  string
	notes []string
}

func (a entryAnnotations) empty() bool { return a.desc == "" && len(a.notes) == 0 }

// commentedAssignment matches the text of a comment that is really a
// disabled KEY=value line.
var commentedAssignment = regexp.MustCompile(`^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=`)

// commentBlock accumulates the comment lines above the next assignment.
type commentBlock struct {
	desc    []string
	notes   []string
	inNotes bool
}

func (c *commentBlock) reset() { *c = commentBlock{} }

// add takes one trimmed line that starts with '#'.
func (c *commentBlock) add(line string) {
	body := strings.TrimLeft(line, "#")
	hashes := len(line) - len(body)
	body = strings.TrimPrefix(body, " ")
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
		desc:  strings.Trim(strings.Join(c.desc, "\n"), "\n"),
		notes: c.notes,
	}
	c.reset()
	return out
}

// renderAnnotationComments writes a's comment block, or nothing. A
// description keeps its line breaks, one `#` line each; a note is one `##`
// line, so any line breaks inside it become spaces.
func renderAnnotationComments(b *strings.Builder, a entryAnnotations) {
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
