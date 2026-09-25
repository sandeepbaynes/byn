package tui

import (
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func detailModel(e ipc.SecretMeta) Model {
	m := Model{
		scope:   ipc.Scope{Project: "default", Env: "default"},
		entries: []ipc.SecretMeta{e},
		styles:  NewStyles(),
	}
	m.Width, m.Height = 120, 40
	m.Layout = Compute(m.Width, m.Height)
	return m
}

// The detail pane carries the description, because it is plaintext and is for
// whoever has to use the value.
func TestDetail_ShowsTheDescription(t *testing.T) {
	m := detailModel(ipc.SecretMeta{
		Name: "API_KEY", Source: "scope",
		Description: "staging Stripe key, read-only", DescriptionAuthor: "owner",
	})
	if !m.Layout.Detail.Visible() {
		t.Skip("detail pane is not visible at this width")
	}
	out := m.renderDetail()
	if !strings.Contains(out, "staging Stripe key") {
		t.Fatalf("detail = %q, want the description", out)
	}
}

// Who wrote it travels with it. An agent-authored description is marked; the
// owner's own is not, so the marks stay worth noticing.
func TestDetail_MarksANonOwnerDescription(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    ipc.SecretMeta
		want string
	}{
		{"agent", ipc.SecretMeta{
			Name: "A", Description: "invented", DescriptionAuthor: "agent", DescriptionComm: "node",
		}, "node"},
		{"manifest", ipc.SecretMeta{
			Name: "A", Description: "declared", DescriptionSource: ".byn",
		}, ".byn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := detailModel(tc.e)
			if !m.Layout.Detail.Visible() {
				t.Skip("detail pane is not visible at this width")
			}
			if out := m.renderDetail(); !strings.Contains(out, tc.want) {
				t.Fatalf("detail = %q, want it to mention %q", out, tc.want)
			}
		})
	}
	m := detailModel(ipc.SecretMeta{Name: "A", Description: "mine", DescriptionAuthor: "owner"})
	if !m.Layout.Detail.Visible() {
		t.Skip("detail pane is not visible at this width")
	}
	if out := m.renderDetail(); strings.Contains(out, "not by you") {
		t.Fatalf("the owner's own description was marked: %q", out)
	}
}

// The count, never the text. The detail pane is drawn whether or not the vault
// is open, and a note is encrypted.
func TestDetail_ShowsNoteCountNotText(t *testing.T) {
	m := detailModel(ipc.SecretMeta{Name: "API_KEY", Source: "scope", Notes: 3})
	if !m.Layout.Detail.Visible() {
		t.Skip("detail pane is not visible at this width")
	}
	out := m.renderDetail()
	if !strings.Contains(out, "3") {
		t.Fatalf("detail = %q, want the note count", out)
	}
	if !strings.Contains(out, "byn note ls") {
		t.Fatalf("detail = %q, want it to say how to read them", out)
	}
}

func TestDescriptionSource(t *testing.T) {
	for _, tc := range []struct {
		e    ipc.SecretMeta
		want string
	}{
		{ipc.SecretMeta{DescriptionSource: ".byn"}, "from the trusted .byn"},
		{ipc.SecretMeta{DescriptionAuthor: "agent", DescriptionComm: "node"}, "written by node, not by you"},
		{ipc.SecretMeta{DescriptionAuthor: "agent"}, "written by a process, not by you"},
		{ipc.SecretMeta{DescriptionAuthor: "owner"}, ""},
	} {
		if got := descriptionSource(tc.e); got != tc.want {
			t.Fatalf("descriptionSource(%+v) = %q, want %q", tc.e, got, tc.want)
		}
	}
}

func TestWrapPlain(t *testing.T) {
	got := wrapPlain("one two three four five", 10)
	for _, ln := range got {
		if len(ln) > 10 {
			t.Fatalf("line %q exceeds the width", ln)
		}
	}
	if strings.Join(got, " ") != "one two three four five" {
		t.Fatalf("wrap lost or reordered words: %q", got)
	}
	// A word longer than the width is kept whole rather than cut: a cut
	// identifier is worse than a long line.
	if got := wrapPlain("supercalifragilistic", 8); len(got) != 1 {
		t.Fatalf("long word = %q", got)
	}
	if got := wrapPlain("", 10); len(got) != 1 || got[0] != "" {
		t.Fatalf("empty = %q", got)
	}
	// Explicit newlines are paragraph breaks, not spaces.
	if got := wrapPlain("a\nb", 10); len(got) != 2 {
		t.Fatalf("newline = %q", got)
	}
}
