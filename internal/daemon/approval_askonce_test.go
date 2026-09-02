package daemon

import "testing"

// The decision matrix, stated once. The asker sets a default; the approver
// overrides it; an explicit override always wins over what was asked for.
func TestOnceResolution(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		reqOnce, reqAlways, askOnce bool
		want                        bool
	}{
		{name: "nothing asked, nothing said: a normal grant"},
		{name: "asked once, plain approval honours it", askOnce: true, want: true},
		{name: "approver forces once on a normal ask", reqOnce: true, want: true},
		{name: "approver widens a once ask with --always", askOnce: true, reqAlways: true, want: false},
		{name: "approver narrows with --once regardless", reqOnce: true, askOnce: true, want: true},
		// --once and --always together: the narrower one wins. An approver who
		// passed both did not mean to widen, and guessing the wider reading
		// hands out more authority than anyone asked for.
		{name: "both flags: the narrower wins", reqOnce: true, reqAlways: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveOnce(tc.reqOnce, tc.reqAlways, tc.askOnce); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
