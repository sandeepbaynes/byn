package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeByn puts a .byn with the given [exec] writable list in dir.
func writeByn(t *testing.T, dir string, writable ...string) string {
	t.Helper()
	body := "[scope]\nproject = \"p\"\nenv = \"dev\"\n"
	if len(writable) > 0 {
		body += "\n[exec]\nwritable = ["
		for i, w := range writable {
			if i > 0 {
				body += ", "
			}
			body += "\"" + w + "\""
		}
		body += "]\n"
	}
	p := filepath.Join(dir, ".byn")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The fatal bug: a declared writable that does not exist was skipped, so the
// tool that wanted the directory had to create it itself — under a 0700
// ~/Library/Preferences with no ACE on it, which is EACCES. Astro died on
// exactly this. It must now be queued for creation instead.
func TestWritableTargets_AbsentDeclaredDirIsCreatedNotSkipped(t *testing.T) {
	home := t.TempDir()
	bynPath := writeByn(t, home, "~/Library/Preferences/astro")

	got := writableTargetsFor(bynPath, home, false)
	want := filepath.Join(home, "Library/Preferences/astro")
	if len(got.create) != 1 || got.create[0] != want {
		t.Fatalf("create = %v, want [%s]", got.create, want)
	}
	if len(got.grant) != 0 {
		t.Errorf("a path that does not exist cannot be granted yet: %v", got.grant)
	}
}

func TestWritableTargets_ExistingDeclaredDirIsGranted(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "Library", "Preferences", "astro")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	bynPath := writeByn(t, home, "~/Library/Preferences/astro")

	got := writableTargetsFor(bynPath, home, false)
	if len(got.grant) != 1 || got.grant[0] != real {
		t.Fatalf("grant = %v, want [%s]", got.grant, real)
	}
	if len(got.create) != 0 {
		t.Errorf("nothing to create: %v", got.create)
	}
}

// The pnpm warning: Library/Preferences/pnpm is a curated default that does not
// exist on this machine, so it was skipped — and because the ancestor traverse
// was part of that same grant, ~/Library/Preferences got no ACE either. pnpm
// then got EACCES rather than ENOENT looking for a file that is not there, on
// every single invocation.
func TestWritableTargets_AbsentCuratedDefaultStillMakesParentReachable(t *testing.T) {
	home := t.TempDir()
	// Library/Preferences exists; the pnpm dir under it does not.
	if err := os.MkdirAll(filepath.Join(home, "Library", "Preferences"), 0o700); err != nil {
		t.Fatal(err)
	}
	bynPath := writeByn(t, home)

	got := writableTargetsFor(bynPath, home, true)
	want := filepath.Join(home, "Library", "Preferences")
	var found bool
	for _, d := range got.traverse {
		if d == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("traverse = %v, want it to include %s", got.traverse, want)
	}
	// A curated default is a guess about the machine, so byn must not create it.
	if len(got.create) != 0 {
		t.Errorf("curated defaults must never be created: %v", got.create)
	}
}

func TestWritableTargets_TraverseParentsAreDeduplicated(t *testing.T) {
	home := t.TempDir()
	bynPath := writeByn(t, home)
	got := writableTargetsFor(bynPath, home, true)
	seen := map[string]bool{}
	for _, d := range got.traverse {
		if seen[d] {
			t.Fatalf("duplicate traverse target %s in %v", d, got.traverse)
		}
		seen[d] = true
	}
}

func TestWritableTargets_SensitiveDirsAreReportedNotSilentlyGranted(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	bynPath := writeByn(t, home, "~/.aws")

	got := writableTargetsFor(bynPath, home, false)
	if len(got.sensitive) != 1 {
		t.Fatalf("sensitive = %v, want the credential dir named", got.sensitive)
	}
	// It is still granted — trust is password-gated, so this is the owner's
	// call — but the caller has to be able to say so.
	if len(got.grant) != 1 {
		t.Errorf("grant = %v, want the declared dir", got.grant)
	}
}

func TestWritableTargets_RefusesEscapingEntries(t *testing.T) {
	home := t.TempDir()
	bynPath := writeByn(t, home, "../../etc", "/etc/passwd")
	got := writableTargetsFor(bynPath, home, false)
	if len(got.grant) != 0 || len(got.create) != 0 {
		t.Fatalf("a path outside home must never be granted or created: %+v", got)
	}
}

// The per-exec callers must stay pure: they run before every command, and a
// classification pass is not the place to make directories.
func TestWritableTargetsFor_CreatesNothingItself(t *testing.T) {
	home := t.TempDir()
	bynPath := writeByn(t, home, "~/Library/Preferences/astro")
	_ = writableTargetsFor(bynPath, home, true)
	if _, err := os.Stat(filepath.Join(home, "Library/Preferences/astro")); err == nil {
		t.Fatal("classification created a directory; only trust may do that")
	}
}
