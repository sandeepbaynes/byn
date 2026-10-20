package main

import (
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Every card says how long a plain yes lasts. Shown only for a single-use
// request, every other card looked the same whether a yes meant six hours, one
// hour or standing trust.
func TestLastsText_SaysTheWindowOnEveryKind(t *testing.T) {
	cases := []struct {
		name string
		e    ipc.ApprovalEntry
		want string
	}{
		{"unpinned command", ipc.ApprovalEntry{Kind: "action_unpinned", WindowSeconds: 6 * 3600}, "6h"},
		{"ad hoc", ipc.ApprovalEntry{Kind: "adhoc", WindowSeconds: 3600}, "1h"},
		{"asked once", ipc.ApprovalEntry{Kind: "adhoc", WindowSeconds: 3600, AskOnce: true}, "one run"},
		{"widening", ipc.ApprovalEntry{Kind: "trust_widening"}, "until the file changes again"},
	}
	for _, c := range cases {
		got := lastsText(c.e)
		if got == "" || !strings.Contains(got, c.want) {
			t.Errorf("%s: lasts = %q, want it to open with %q", c.name, got, c.want)
		}
	}
	if lastsText(ipc.ApprovalEntry{Kind: "adhoc", WindowSeconds: 3600, AskOnce: true}) ==
		lastsText(ipc.ApprovalEntry{Kind: "adhoc", WindowSeconds: 3600}) {
		t.Error("a single-use request must not read like a window")
	}
}
