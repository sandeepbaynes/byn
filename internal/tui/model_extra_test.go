package tui

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestVaultProjectEnvOrDefault(t *testing.T) {
	cases := []struct {
		fn   func(string) string
		in   string
		want string
	}{
		{vaultOrDefault, "", "default"},
		{vaultOrDefault, "acme", "acme"},
		{projectOrDefault, "", "default"},
		{projectOrDefault, "web", "web"},
		{envOrDefault, "", "default"},
		{envOrDefault, "dev", "dev"},
	}
	for _, tc := range cases {
		if got := tc.fn(tc.in); got != tc.want {
			t.Errorf("%v -> %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEffectiveScope_FillsDefaults(t *testing.T) {
	m := Model{}
	got := m.effectiveScope()
	if got.Vault != "default" || got.Project != "default" || got.Env != "default" {
		t.Fatalf("got %+v", got)
	}
}

func TestEffectiveScope_PassthroughExplicit(t *testing.T) {
	m := Model{scope: ipc.Scope{Vault: "v", Project: "p", Env: "e"}}
	got := m.effectiveScope()
	if got.Vault != "v" || got.Project != "p" || got.Env != "e" {
		t.Fatalf("got %+v", got)
	}
}

func TestScopeDisplay_AndBreadcrumb(t *testing.T) {
	m := Model{scope: ipc.Scope{Vault: "v"}}
	if m.scopeDisplay() != "v/default/default" {
		t.Fatalf("display=%q", m.scopeDisplay())
	}
	want := "v ▸ default ▸ default"
	if m.scopeDisplayBreadcrumb() != want {
		t.Fatalf("breadcrumb=%q", m.scopeDisplayBreadcrumb())
	}
}

func TestFilteredEntries_NoFilter(t *testing.T) {
	m := Model{entries: []ipc.SecretMeta{{Name: "A"}, {Name: "B"}}}
	got := m.filteredEntries()
	if len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
}

func TestFilteredEntries_MatchesCaseInsensitive(t *testing.T) {
	m := Model{
		entries:       []ipc.SecretMeta{{Name: "DB_URL"}, {Name: "API_KEY"}, {Name: "db_pass"}},
		entriesFilter: "db",
	}
	got := m.filteredEntries()
	if len(got) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(got))
	}
}

func TestFilteredEntries_NoMatches(t *testing.T) {
	m := Model{
		entries:       []ipc.SecretMeta{{Name: "A"}, {Name: "B"}},
		entriesFilter: "zzz",
	}
	got := m.filteredEntries()
	if len(got) != 0 {
		t.Fatalf("got %d", len(got))
	}
}

func TestCurrentEntry_None(t *testing.T) {
	m := Model{entries: nil}
	if m.currentEntry() != nil {
		t.Fatal("expected nil")
	}
}

func TestCurrentEntry_OutOfBounds(t *testing.T) {
	m := Model{entries: []ipc.SecretMeta{{Name: "A"}}, entryCursor: 5}
	if m.currentEntry() != nil {
		t.Fatal("expected nil out-of-bounds")
	}
	m2 := Model{entries: []ipc.SecretMeta{{Name: "A"}}, entryCursor: -1}
	if m2.currentEntry() != nil {
		t.Fatal("expected nil neg")
	}
}

func TestCurrentEntry_OK(t *testing.T) {
	m := Model{entries: []ipc.SecretMeta{{Name: "A"}, {Name: "B"}}, entryCursor: 1}
	got := m.currentEntry()
	if got == nil || got.Name != "B" {
		t.Fatalf("got %+v", got)
	}
}
