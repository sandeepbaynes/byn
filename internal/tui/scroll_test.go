package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// longListModel builds a Standard-tier model holding n env-var entries,
// focused on the content pane in NORMAL mode — the situation after
// importing a large .env file.
func longListModel(t *testing.T, n, width, height int) Model {
	t.Helper()
	scope := ipc.Scope{Vault: "default", Project: "billing", Env: "staging"}
	model := NewModel(fakeClient{}, "test", scope)
	mAny, _ := model.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m := mAny.(Model)
	ts := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	es := make([]ipc.SecretMeta, n)
	for i := range es {
		es[i] = ipc.SecretMeta{Name: fmt.Sprintf("VAR_%03d", i), Source: "scope", CreatedAt: ts, UpdatedAt: ts}
	}
	m.entries = es
	m.Focus = FocusContent
	m.Mode = ModeNormal
	return m
}

func TestEnvVars_LongList_ScrollsToKeepCursorVisible(t *testing.T) {
	const n = 80
	m := longListModel(t, n, 100, 24)

	// Cursor at the bottom of a long list: the selected entry MUST be
	// visible — the vars column has to scroll to follow it.
	m.entryCursor = n - 1
	view := m.View()
	if last := "VAR_079"; !strings.Contains(view, last) {
		t.Errorf("cursor at last entry but %q not visible — vars column does not scroll", last)
	}
	// With the cursor pinned to the bottom, the far-away top entry must
	// have scrolled out of view (otherwise nothing was windowed).
	if strings.Contains(view, "VAR_000") {
		t.Errorf("VAR_000 still visible with cursor at bottom — entries viewport not windowed")
	}
}

func TestEnvVars_LongList_TopVisibleAtCursorZero(t *testing.T) {
	m := longListModel(t, 80, 100, 24)
	m.entryCursor = 0
	view := m.View()
	if !strings.Contains(view, "VAR_000") {
		t.Error("cursor at top of list but first entry not visible")
	}
}

// TestEnvVars_RealNavigation_KeepsCursorVisible drives the actual j-key
// path through Update (not a direct cursor set) across several terminal
// sizes, then asserts the cursor's entry is within the VISIBLE region —
// the first `height` lines. This guards the real-world reproduction:
// checking the full View() string is not enough, the cursor row must be
// on-screen.
func TestEnvVars_RealNavigation_KeepsCursorVisible(t *testing.T) {
	for _, sz := range []struct{ w, h int }{{120, 30}, {100, 24}, {90, 20}, {80, 16}, {70, 22}} {
		m := longListModel(t, 80, sz.w, sz.h)
		for i := 0; i < 75; i++ {
			mAny, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
			m = mAny.(Model)
		}
		if m.entryCursor != 75 {
			t.Errorf("size %dx%d: entryCursor=%d after 75×j, want 75", sz.w, sz.h, m.entryCursor)
		}
		view := m.View()
		lines := strings.Split(view, "\n")
		if len(lines) > sz.h {
			lines = lines[:sz.h]
		}
		if vis := strings.Join(lines, "\n"); !strings.Contains(vis, "VAR_075") {
			t.Errorf("size %dx%d: cursor entry VAR_075 not in visible region — list does not scroll", sz.w, sz.h)
		}
	}
}

func TestEnvVars_RevealAtBottom_FitsViewport(t *testing.T) {
	for _, sz := range []struct{ w, h int }{{100, 24}, {110, 18}, {90, 14}} {
		m := longListModel(t, 80, sz.w, sz.h)
		m.entryCursor = 79 // last entry, at the bottom of a long list
		m.Mode = ModeReveal
		m.reveal = &revealState{
			Name:      "VAR_079",
			Value:     "super-secret-value",
			ExpiresAt: time.Now().Add(9 * time.Second),
		}
		view := m.View()
		lines := strings.Split(view, "\n")
		// The whole frame MUST fit the terminal — otherwise the expanded
		// reveal box pushes content (and the always-on status line) off
		// the bottom.
		if len(lines) > sz.h {
			t.Errorf("size %dx%d: View has %d lines > terminal height %d (frame overflows)",
				sz.w, sz.h, len(lines), sz.h)
		}
		vis := lines
		if len(vis) > sz.h {
			vis = vis[:sz.h]
		}
		visStr := strings.Join(vis, "\n")
		if !strings.Contains(visStr, "hides in") {
			t.Errorf("size %dx%d: reveal hint (⏱ hides in …) clipped beneath the viewport", sz.w, sz.h)
		}
		if !strings.Contains(visStr, "REVEALED") {
			t.Errorf("size %dx%d: status line (REVEALED …) pushed off-screen", sz.w, sz.h)
		}
	}
}

func TestFlattenRows(t *testing.T) {
	got := flattenRows([]string{"a", "b\nc\nd", "", "e"})
	want := []string{"a", "b", "c", "d", "", "e"}
	if len(got) != len(want) {
		t.Fatalf("flattenRows len = %d, want %d (%q)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("flattenRows[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestVisualRows(t *testing.T) {
	cases := map[string]int{"": 1, "a": 1, "a\nb": 2, "a\nb\nc": 3}
	for s, want := range cases {
		if got := visualRows(s); got != want {
			t.Errorf("visualRows(%q) = %d, want %d", s, got, want)
		}
	}
}

func TestExpandedBoxRows(t *testing.T) {
	m := longListModel(t, 5, 100, 24)
	if got := m.expandedBoxRows(m.Layout.Content.W); got != 0 {
		t.Errorf("NORMAL mode expandedBoxRows = %d, want 0", got)
	}
	m.Mode = ModeReveal
	m.reveal = &revealState{Name: "VAR_000", Value: "x", ExpiresAt: time.Now().Add(time.Second)}
	if got := m.expandedBoxRows(m.Layout.Content.W); got <= 0 {
		t.Errorf("REVEAL mode expandedBoxRows = %d, want > 0", got)
	}
}

func TestEntryWindow(t *testing.T) {
	cases := []struct {
		name               string
		n, cursor, rows    int
		wantStart, wantEnd int
	}{
		{"fits exactly", 5, 2, 5, 0, 5},
		{"fits with room", 3, 0, 10, 0, 3},
		{"empty list", 0, 0, 5, 0, 0},
		{"cursor in first window", 80, 3, 10, 0, 10},
		{"cursor just past fold", 80, 10, 10, 1, 11},
		{"cursor at end pins to bottom", 80, 79, 10, 70, 80},
		{"cursor beyond n clamps to bottom", 80, 999, 10, 70, 80},
		{"single visible row", 80, 40, 1, 40, 41},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end := entryWindow(tc.n, tc.cursor, tc.rows)
			if start != tc.wantStart || end != tc.wantEnd {
				t.Errorf("entryWindow(%d,%d,%d) = (%d,%d), want (%d,%d)",
					tc.n, tc.cursor, tc.rows, start, end, tc.wantStart, tc.wantEnd)
			}
			// Invariants: a valid, in-bounds window that contains the
			// cursor whenever the cursor is itself in range.
			if start < 0 || end > tc.n || start > end {
				t.Errorf("window (%d,%d) out of bounds for n=%d", start, end, tc.n)
			}
			if tc.cursor >= 0 && tc.cursor < tc.n && (tc.cursor < start || tc.cursor >= end) {
				t.Errorf("cursor %d not within window [%d,%d)", tc.cursor, start, end)
			}
		})
	}
}
