package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestSnapshot_AddMode_DuplicateName drives the model into ADD-ENTRY
// with a name that matches an existing entry, then writes the
// rendered View to testdata/. Used as a visual diagnosis when the
// box rendering looks broken.
func TestSnapshot_AddMode_DuplicateName(t *testing.T) {
	cases := []struct {
		name string
		w, h int
	}{
		{"add-medium", 75, 28},
		{"add-standard", 100, 30},
		{"add-large", 140, 35},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := driveTo(t, tc.w, tc.h)
			// Move focus to content.
			mAny, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
			m = mAny.(Model)
			// Press 'a' to start ADD.
			mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
			m = mAny.(Model)
			// Type "API_KEY" — matches the fake daemon's seeded
			// entry, so NameError fires after the last 'Y'.
			for _, r := range "API_KEY" {
				mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
				m = mAny.(Model)
			}
			view := m.View()
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			path := filepath.Join("testdata", tc.name+".txt")
			body := stripANSI(view) + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
			// Light sanity: NameError should be reflected in the View
			// either via the warning chip in the section header or
			// the inline "✘" line under the NAME box.
			if !strings.Contains(view, "API_KEY") {
				t.Errorf("View doesn't contain the typed name 'API_KEY':\n%s", view)
			}
		})
	}
}
