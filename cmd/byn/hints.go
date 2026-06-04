// Hints: short stderr echoes after mutating ops so users see what
// changed where (vault/project/env). Gate via BYN_HINTS=0 (or
// "false"/"off") and also auto-suppress when stderr is not a TTY (so
// scripted callers don't get extra chatter).
//
// Examples:
//
//	Put DB_URL in maison-agent/staging.
//	Created project "billing" in vault "default".
//	Imported 12 entries into default/billing/default.
//
// Why on stderr: keeps stdout clean for piping (e.g.
// `byn list --json | jq ...`).
package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func hintsEnabled() bool {
	switch strings.ToLower(os.Getenv("BYN_HINTS")) {
	case "0", "false", "off", "no":
		return false
	}
	return term.IsTerminal(int(os.Stderr.Fd()))
}

func hintf(format string, args ...any) {
	if !hintsEnabled() {
		return
	}
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}
	fmt.Fprintf(os.Stderr, format, args...)
}
