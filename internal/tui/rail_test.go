package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// renderRailVersion is the dim, right-aligned version footer in the rail.
func TestRenderRailVersion(t *testing.T) {
	scope := ipc.Scope{Vault: "default"}
	cases := []struct {
		name    string
		version string
		width   int
		want    string // expected substring; "" means expect empty output
	}{
		{"semver gets a v prefix", "0.0.1", 20, "v0.0.1"},
		{"non-numeric kept verbatim", "dev", 20, "dev"},
		{"empty version renders nothing", "", 20, ""},
		{"zero width renders nothing", "0.0.1", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(fakeClient{}, tc.version, scope)
			out := m.renderRailVersion(tc.width)

			if tc.want == "" {
				if out != "" {
					t.Fatalf("renderRailVersion(%q, %d) = %q, want empty", tc.version, tc.width, out)
				}
				return
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("renderRailVersion(%q, %d) = %q, want substring %q", tc.version, tc.width, out, tc.want)
			}
			// Right-aligned: the rendered width must never exceed the rail width,
			// and the label sits flush to the right edge (no trailing pad).
			if w := lipgloss.Width(out); w > tc.width {
				t.Fatalf("rendered width %d exceeds rail width %d: %q", w, tc.width, out)
			}
		})
	}
}

// On a rail too narrow for the full label, the version truncates with an
// ellipsis and still respects the width budget.
func TestRenderRailVersion_TruncatesNarrow(t *testing.T) {
	m := NewModel(fakeClient{}, "0.0.1", ipc.Scope{Vault: "default"})
	out := m.renderRailVersion(3) // "v0.0.1" (6 cols) cannot fit in 3
	if w := lipgloss.Width(out); w > 3 {
		t.Fatalf("rendered width %d exceeds 3: %q", w, out)
	}
	if !strings.Contains(out, "…") {
		t.Fatalf("expected an ellipsis on a narrow rail, got %q", out)
	}
}
