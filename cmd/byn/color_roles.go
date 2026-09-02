package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// Semantic colour roles.
//
// Colour in a list has to mean something, or it is decoration that costs the
// reader attention and gives nothing back. The approval list grew colours one
// at a time — `why:` yellow, `who:` cyan, everything else uncoloured — so two
// field labels of identical importance were different colours, and the command
// text itself was the same colour as the word introducing it. Nothing was
// wrong, exactly; there was just no rule, and without a rule a reader cannot
// learn anything from a colour.
//
// The rule is: a colour names a KIND of thing, and every colour in a view comes
// from this list.
//
//	label — the name of a field. Never part of the value it introduces.
//	ident — something you type back at byn: a request id, a command.
//	warn  — risk, or a deadline that will pass.
//	bad   — refused, expired, revoked.
//	good  — granted, used, healthy.
//	note  — secondary text: explanation, provenance, help.
//
// These gate on STDOUT, not stderr. A list is a stdout payload like the trust
// diff, so `byn approve > file` writes plain text while the same command on a
// terminal is coloured — the rule color.go already states, and which the
// approval list was not following.
func roleLabel(s string) string { return wrapOut(ansiYellow, s) }
func roleIdent(s string) string { return wrapOut(ansiCyan, s) }
func roleWarn(s string) string  { return wrapOut(ansiBold+ansiYellow, s) }
func roleBad(s string) string   { return wrapOut(ansiRed, s) }
func roleGood(s string) string  { return wrapOut(ansiGreen, s) }
func roleNote(s string) string  { return wrapOut(ansiDim, s) }

// wrapOut is wrap for stdout payloads.
func wrapOut(code, s string) string {
	if !useColorStdout {
		return s
	}
	return code + s + ansiReset
}

// fieldRow renders one label/value pair with the value starting in a fixed
// column, so a record reads as a two-column table rather than as sentences.
//
// The label is padded BEFORE it is coloured. Padding afterwards counts the ANSI
// escape bytes as width, which silently misaligns every coloured row against
// every uncoloured one — visible only on a terminal, and never in a test that
// captures output with colour off.
func fieldRow(label, value string) string {
	return fmt.Sprintf("%s  %s\n", roleLabel(fmt.Sprintf("%*s", fieldLabelWidth, label)), value)
}

// fieldLabelWidth is the width of the label column. Wide enough for the longest
// label in use, so values share one left edge.
const fieldLabelWidth = 10

// termWidthStdout is the usable width for a table, or a conservative default
// when stdout is not a terminal (piped, redirected, or under test).
func termWidthStdout() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w < 40 {
		return 100
	}
	return w
}
