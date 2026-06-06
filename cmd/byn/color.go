package main

import (
	"os"

	"golang.org/x/term"
)

// useColor is set once at startup based on whether stderr is a
// terminal and the NO_COLOR / FORCE_COLOR env vars. Honoring NO_COLOR
// is a community convention; see https://no-color.org.
var useColor = computeUseColor()

func computeUseColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	return term.IsTerminal(int(os.Stderr.Fd()))
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
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
