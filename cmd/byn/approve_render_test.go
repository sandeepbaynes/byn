package main

import (
	"strings"
	"testing"
)

// A request's summary is what the fingerprint is computed from, so it is never
// rewritten in the record. The LIST is a different matter: a `node -e` program
// printed verbatim buried every other entry, and this is the list someone scans
// to find out what an agent asked for.
func TestOneLine_CollapsesAndCaps(t *testing.T) {
	got := oneLine("runs node -e \nimport pg from \"pg\";\nconst c = new pg.Client();\n", 40)
	if strings.ContainsAny(got, "\n") {
		t.Errorf("newlines survived: %q", got)
	}
	if len([]rune(got)) > 41 { // 40 + the ellipsis
		t.Errorf("not capped: %q", got)
	}
	if !strings.HasPrefix(got, "runs node -e") {
		t.Errorf("lost the front of the command: %q", got)
	}
}

// Short lines are left exactly as they are — the common case is a readable
// summary that needs no help.
func TestOneLine_LeavesAShortLineAlone(t *testing.T) {
	in := "runs make dev"
	if got := oneLine(in, 100); got != in {
		t.Errorf("oneLine(%q) = %q, want it unchanged", in, got)
	}
}
