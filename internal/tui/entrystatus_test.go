package tui

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestEntryStatus_UsesDaemonComparison pins the badge to what the daemon
// reported: a copy that equals default is "same", not "overrides".
func TestEntryStatus_UsesDaemonComparison(t *testing.T) {
	yes, no := true, false
	m := Model{scope: ipc.Scope{Env: "staging"}}
	cases := []struct {
		name string
		e    ipc.SecretMeta
		want EntryStatus
	}{
		{"inherited", ipc.SecretMeta{Source: "default"}, StatusInherited},
		{"new", ipc.SecretMeta{Source: "scope"}, StatusNew},
		{"same", ipc.SecretMeta{Source: "scope", InDefault: true, SameAsDefault: &yes}, StatusSameAsDefault},
		{"differs", ipc.SecretMeta{Source: "scope", InDefault: true, SameAsDefault: &no}, StatusOverridden},
		{"undecided (locked)", ipc.SecretMeta{Source: "scope", InDefault: true}, StatusOverridden},
	}
	for _, c := range cases {
		if got := m.entryStatus(c.e); got != c.want {
			t.Errorf("%s: entryStatus = %v, want %v", c.name, got, c.want)
		}
	}
	m.scope.Env = "default"
	if got := m.entryStatus(ipc.SecretMeta{Source: "scope", InDefault: true, SameAsDefault: &yes}); got != StatusNone {
		t.Errorf("default env: entryStatus = %v, want StatusNone", got)
	}
}
