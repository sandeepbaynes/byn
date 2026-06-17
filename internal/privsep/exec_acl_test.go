package privsep

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExecToolchainDefaults_AreSafe(t *testing.T) {
	if len(ExecToolchainDefaults) == 0 {
		t.Fatal("expected a curated default list")
	}
	const home = "/Users/me"
	for _, rel := range ExecToolchainDefaults {
		abs := filepath.Join(home, rel)
		if IsSensitiveHomeDir(abs, home) {
			t.Errorf("curated default %q is a credential dir — must never be auto-granted", rel)
		}
		if filepath.IsAbs(rel) {
			t.Errorf("curated default %q must be home-relative, not absolute", rel)
		}
	}
}

func TestResolveWritableUnderHome(t *testing.T) {
	const home = "/Users/me"
	ok := map[string]string{
		"~/Library/pnpm": "/Users/me/Library/pnpm",
		"~":              "/Users/me",
		".cache":         "/Users/me/.cache",
		"/Users/me/x/y":  "/Users/me/x/y",
	}
	for in, want := range ok {
		got, err := ResolveWritableUnderHome(in, home)
		if err != nil || got != want {
			t.Errorf("ResolveWritableUnderHome(%q) = (%q, %v), want (%q, nil)", in, got, err, want)
		}
	}
	bad := []string{"", "/etc", "/Users/other", "~/../../etc", "../x", "~/.."}
	for _, in := range bad {
		if got, err := ResolveWritableUnderHome(in, home); err == nil {
			t.Errorf("ResolveWritableUnderHome(%q) = %q, want an error (escapes home)", in, got)
		}
	}
}

func TestIsSensitiveHomeDir(t *testing.T) {
	const home = "/Users/me"
	for _, s := range []string{"/Users/me/.ssh", "/Users/me/.aws/credentials", "/Users/me/.gnupg"} {
		if !IsSensitiveHomeDir(s, home) {
			t.Errorf("%q should be flagged sensitive", s)
		}
	}
	for _, s := range []string{"/Users/me/.cache", "/Users/me/Library/pnpm", "/Users/me/.cargo"} {
		if IsSensitiveHomeDir(s, home) {
			t.Errorf("%q should NOT be flagged sensitive", s)
		}
	}
}

func TestGrantExecDirsACL_GrantsEachUnderExecUser(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ACL grants are no-ops on this platform")
	}
	var ran [][]string
	run := func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	dirs := []string{"/Users/me/.cache", "/Users/me/Library/pnpm"}
	if err := GrantExecDirsACL(run, dirs, "/Users/me"); err != nil {
		t.Fatalf("GrantExecDirsACL: %v", err)
	}
	for _, d := range dirs {
		found := false
		for _, c := range ran {
			if c[len(c)-1] == d {
				found = true
			}
		}
		if !found {
			t.Errorf("no ACL command targeted dir %q", d)
		}
	}
	named := false
	for _, c := range ran {
		if strings.Contains(strings.Join(c, " "), ExecUser) {
			named = true
		}
	}
	if !named {
		t.Errorf("no ACL command named the exec user %q", ExecUser)
	}
}
