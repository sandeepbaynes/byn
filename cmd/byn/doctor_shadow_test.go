package main

import "testing"

// The failure this exists for had no symptom: `go install …@latest` succeeded,
// put a new byn in ~/go/bin, ~/go/bin was not on PATH, and the older byn in
// ~/.local/bin kept answering — so `byn version` reported the old number right
// after a successful upgrade, and nothing anywhere said why.
func TestDiagnoseShadowedInstalls(t *testing.T) {
	t.Run("disagreeing versions fail and name the newer one", func(t *testing.T) {
		got := diagnoseShadowedInstalls([]bynInstall{
			{Path: "/home/u/.local/bin/byn", Version: "0.5.2", OnPath: true},
			{Path: "/home/u/go/bin/byn", Version: "0.5.3", OnPath: false},
		})
		if len(got) != 1 || got[0].OK {
			t.Fatalf("two byn at different versions should fail the check: %+v", got)
		}
		if !contains(got[0].Detail, "0.5.3") || !contains(got[0].Detail, "not on your PATH") {
			t.Errorf("detail does not explain the situation: %q", got[0].Detail)
		}
	})

	t.Run("agreeing copies are fine", func(t *testing.T) {
		got := diagnoseShadowedInstalls([]bynInstall{
			{Path: "/usr/local/bin/byn", Version: "0.5.3", OnPath: true},
			{Path: "/home/u/.local/bin/byn", Version: "0.5.3", OnPath: true},
		})
		if len(got) != 1 || !got[0].OK {
			t.Fatalf("copies at the same version are not a problem: %+v", got)
		}
	})

	t.Run("a single install says nothing", func(t *testing.T) {
		if got := diagnoseShadowedInstalls([]bynInstall{
			{Path: "/usr/local/bin/byn", Version: "0.5.3", OnPath: true},
		}); got != nil {
			t.Errorf("one byn needs no check: %+v", got)
		}
	})
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
