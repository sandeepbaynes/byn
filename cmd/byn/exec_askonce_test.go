package main

import (
	"reflect"
	"testing"
)

func TestStripExecAskOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in, want []string
		once     bool
	}{
		{name: "long form", in: []string{"--once", "--", "make", "dev"}, want: []string{"--", "make", "dev"}, once: true},
		{name: "explicit spelling", in: []string{"--ask-once", "--", "ls"}, want: []string{"--", "ls"}, once: true},
		{name: "absent", in: []string{"--", "ls"}, want: []string{"--", "ls"}},
		// The boundary rule, which is the one that matters: a child of byn can
		// have a --once of its own, and byn must not eat it.
		{name: "after the boundary belongs to the child",
			in: []string{"--", "prog", "--once"}, want: []string{"--", "prog", "--once"}},
		{name: "after a bare command too",
			in: []string{"make", "--once"}, want: []string{"make", "--once"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, once := stripExecAskOnce(tc.in)
			if !reflect.DeepEqual(got, tc.want) || once != tc.once {
				t.Fatalf("got (%v,%v), want (%v,%v)", got, once, tc.want, tc.once)
			}
		})
	}
}
