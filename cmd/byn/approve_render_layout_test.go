package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestPendingEntry_ValuesShareOneColumn is the whole complaint in one
// assertion: the card was "too scattered and all over the place" because every
// line started wherever its label happened to end.
func TestPendingEntry_ValuesShareOneColumn(t *testing.T) {
	var b bytes.Buffer
	now := time.Now()
	renderPendingEntry(&b, ipc.ApprovalEntry{
		ID: "abc123", Subject: "/p/.byn", Kind: "action_unpinned",
		Summary:   []string{"runs make dev"},
		Reason:    "needed for the build",
		Requestor: ipc.ApprovalActor{Display: "claude (pid 1)", Cwd: "/p"},
		CreatedAt: now.Add(-5 * time.Minute).Unix(),
	}, now)

	rows := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")[1:]
	if len(rows) < 4 {
		t.Fatalf("want a row per field, got %d:\n%s", len(rows), b.String())
	}
	// Labels are RIGHT-aligned in a fixed column, so what must line up is where
	// each value begins — not where its label does. Measuring the label edge
	// would fail on correct output for the same reason the old layout looked
	// wrong: the label ends in a different place on every row.
	const valueCol = fieldLabelWidth + 2
	for _, line := range rows {
		if len(line) <= valueCol {
			t.Fatalf("row too short to hold a value: %q", line)
		}
		if line[fieldLabelWidth:valueCol] != "  " || line[valueCol] == ' ' {
			t.Fatalf("value does not begin at column %d — values must share a left edge:\n%s",
				valueCol, b.String())
		}
		if strings.TrimSpace(line[:fieldLabelWidth]) == "" {
			t.Fatalf("row has no label: %q", line)
		}
	}
}

// The verb belongs in the label column. "runs /bin/true" read as one string put
// the word introducing the command in the same colour as the command.
func TestSplitSummaryVerb(t *testing.T) {
	for _, tc := range []struct{ in, label, value string }{
		{"runs /bin/true", "runs", "/bin/true"},
		{"grants APP_*", "grants", "APP_*"},
		// Anything byn is not known to write keeps the whole line as the value.
		// Guessing at a verb would relabel text byn did not author.
		{"something else entirely", "asks", "something else entirely"},
		{"runsomething", "asks", "runsomething"},
	} {
		gotL, gotV := splitSummaryVerb(tc.in)
		if gotL != tc.label || gotV != tc.value {
			t.Errorf("%q → (%q,%q), want (%q,%q)", tc.in, gotL, gotV, tc.label, tc.value)
		}
	}
}

// padColored must pad by VISIBLE width. Padding a coloured string counts its
// escape bytes as characters and pulls every later column out of line — and
// only on a terminal, so a test with colour disabled would never see it.
func TestPadColored_IgnoresEscapeBytes(t *testing.T) {
	fake := func(s string) string { return "\033[31m" + s + "\033[0m" }
	got := padColored(fake, "denied", 10)
	if visible := len(got) - len("\033[31m\033[0m"); visible != 10 {
		t.Fatalf("visible width %d, want 10 — coloured cells misalign against plain ones", visible)
	}
}

func TestCompactAge(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{27*time.Minute + 2*time.Second, "27m"},
		{11*time.Hour + 47*time.Minute, "11h"},
		{46 * time.Hour, "1d"},
	} {
		if got := compactAge(tc.d); got != tc.want {
			t.Errorf("compactAge(%s) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// A deadline keeps its second unit: "expires in 5h" when it is really 5h32m
// throws away the half hour you were deciding whether you had.
func TestCompactLeft_KeepsTheSecondUnit(t *testing.T) {
	if got := compactLeft(5*time.Hour + 32*time.Minute); got != "5h32m" {
		t.Fatalf("got %q, want 5h32m", got)
	}
	if got := compactLeft(6 * time.Hour); got != "6h" {
		t.Fatalf("a whole number of hours must not grow a 0m: got %q", got)
	}
}

func TestHistoryTable_HasAHeaderAndARowPerEntry(t *testing.T) {
	var b bytes.Buffer
	now := time.Now()
	renderHistoryTable(&b, []ipc.ApprovalEntry{
		{ID: "aaa", Status: "denied", Summary: []string{"runs rm -rf /"}, CreatedAt: now.Add(-time.Hour).Unix()},
		{ID: "bbb", Status: "approved", Summary: []string{"runs make dev"}, Reason: "build", CreatedAt: now.Add(-2 * time.Hour).Unix()},
	}, now, 100)

	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows, got %d:\n%s", len(lines), b.String())
	}
	for _, want := range []string{"ID", "STATUS", "ASKED", "COMMAND", "WHY"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("header missing %q: %q", want, lines[0])
		}
	}
	if !strings.Contains(lines[1], "denied") || !strings.Contains(lines[1], "rm -rf /") {
		t.Errorf("row lost its status or command: %q", lines[1])
	}
	// A request with no stated reason must still render a cell, or the column
	// silently collapses for that row.
	if !strings.Contains(lines[1], "—") {
		t.Errorf("missing placeholder for an absent reason: %q", lines[1])
	}
}

// The per-kind explanation is said once for the list, not once per card —
// repeating a 100-character sentence down the screen was most of the scatter.
func TestKindNotes_SaysEachKindOnce(t *testing.T) {
	got := kindNotes([]ipc.ApprovalEntry{
		{Kind: "action_unpinned"}, {Kind: "action_unpinned"}, {Kind: "trust_widening"},
	})
	if len(got) != 2 {
		t.Fatalf("want one note per distinct kind, got %d: %v", len(got), got)
	}
	if len(kindNotes(nil)) != 0 {
		t.Fatal("an empty list must produce no notes")
	}
}
