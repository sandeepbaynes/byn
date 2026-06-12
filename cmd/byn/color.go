package main

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// useColor / useColorStdout are set once at startup based on whether stderr /
// stdout is a terminal and the NO_COLOR / FORCE_COLOR env vars. Honoring
// NO_COLOR is a community convention; see https://no-color.org. Diagnostics
// and hints go to stderr (useColor); primary stdout payloads like the trust
// diff gate on stdout (useColorStdout) so a piped or redirected diff stays
// plain — matching git's --color=auto.
var useColor = computeUseColor()
var useColorStdout = computeUseColorStdout()

func computeUseColor() bool       { return computeUseColorFor(os.Stderr) }
func computeUseColorStdout() bool { return computeUseColorFor(os.Stdout) }

func computeUseColorFor(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	return term.IsTerminal(int(f.Fd()))
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

func wrap(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + ansiReset
}

func red(s string) string        { return wrap(ansiRed, s) }
func yellow(s string) string     { return wrap(ansiYellow, s) }
func cyan(s string) string       { return wrap(ansiCyan, s) }
func bold(s string) string       { return wrap(ansiBold, s) }
func dim(s string) string        { return wrap(ansiDim, s) }
func boldRed(s string) string    { return wrap(ansiBold+ansiRed, s) }
func boldYellow(s string) string { return wrap(ansiBold+ansiYellow, s) }

// colorizeDiff applies git-style ANSI colors to a unified diff for terminal
// display: hunk headers (@@) cyan, added lines (+) green, removed lines (-)
// red, and the ---/+++ file headers bold. Context lines are left untouched.
// It no-ops (returns text unchanged) unless stdout is a color terminal, so a
// piped or redirected diff stays plain. The ---/+++ file-header checks run
// before the +/- checks so they are not mistaken for added/removed content.
func colorizeDiff(text string) string {
	if !useColorStdout {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
			lines[i] = ansiBold + line + ansiReset
		case strings.HasPrefix(line, "@@"):
			lines[i] = ansiCyan + line + ansiReset
		case strings.HasPrefix(line, "+"):
			lines[i] = ansiGreen + line + ansiReset
		case strings.HasPrefix(line, "-"):
			lines[i] = ansiRed + line + ansiReset
		}
	}
	return strings.Join(lines, "\n")
}
