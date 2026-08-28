package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTildeHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory in this environment")
	}
	cases := []struct {
		in, want string
	}{
		{filepath.Join(home, "code", "proj"), "~" + string(os.PathSeparator) + filepath.Join("code", "proj")},
		{home, home},                           // the home dir itself is not abbreviated to a bare "~"
		{"/etc/byn", "/etc/byn"},               // outside home, left alone
		{"", ""},                               // nothing to abbreviate
		{home + "-other/x", home + "-other/x"}, // a prefix match that is NOT a subdirectory
	}
	for _, tc := range cases {
		if got := tildeHome(tc.in); got != tc.want {
			t.Errorf("tildeHome(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDashIfEmpty(t *testing.T) {
	if got := dashIfEmpty(""); got != "-" {
		t.Errorf("dashIfEmpty(\"\") = %q, want \"-\" — a blank column reads as a rendering bug", got)
	}
	if got := dashIfEmpty("x"); got != "x" {
		t.Errorf("dashIfEmpty(%q) = %q, want it unchanged", "x", got)
	}
}
