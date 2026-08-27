package main

import (
	"strings"
	"testing"
)

func TestStaleDaemonNote(t *testing.T) {
	cases := []struct {
		name         string
		daemon, cli  string
		wantNote     bool
		wantMentions []string
	}{
		{name: "same version says nothing", daemon: "0.4.1", cli: "0.4.1"},
		{name: "unknown daemon version says nothing", daemon: "", cli: "0.4.1"},
		{name: "unknown cli version says nothing", daemon: "0.4.1", cli: ""},
		{
			name: "skew names both versions and the fix",
			// The shape that cost a night: a new binary installed, the old
			// daemon still serving, and status reporting it without comment.
			daemon: "0.4.1-32-g5f3831a", cli: "0.4.1-37-g837aea8",
			wantNote:     true,
			wantMentions: []string{"0.4.1-32-g5f3831a", "0.4.1-37-g837aea8", "restart"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := staleDaemonNote(tc.daemon, tc.cli)
			if !tc.wantNote {
				if got != "" {
					t.Fatalf("staleDaemonNote(%q, %q) = %q, want no note", tc.daemon, tc.cli, got)
				}
				return
			}
			if got == "" {
				t.Fatalf("staleDaemonNote(%q, %q) = \"\", want a note", tc.daemon, tc.cli)
			}
			for _, want := range tc.wantMentions {
				if !strings.Contains(got, want) {
					t.Errorf("note %q should mention %q", got, want)
				}
			}
		})
	}
}
