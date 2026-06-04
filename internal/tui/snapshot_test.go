package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// snapshotFiles writes the rendered output for each tier under
// testdata/. Diffable across changes; regenerate by deleting and
// re-running.
func TestSnapshots_PerTier(t *testing.T) {
	cases := []struct {
		name string
		w, h int
	}{
		{"below-min", 30, 10},
		{"tiny", 50, 24},
		{"medium", 75, 28},
		{"standard", 100, 30},
		{"large", 140, 35},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, view := driveTo(t, tc.w, tc.h)
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatalf("mkdir testdata: %v", err)
			}
			path := filepath.Join("testdata", tc.name+".txt")
			body := stripANSI(view) + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
		})
	}
}

// stripANSI removes color escapes so the snapshot diff is human-
// readable. Quick-and-dirty — matches the CSI sequences lipgloss emits.
func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < '@' || s[j] > '~') {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
