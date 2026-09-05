package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/agentskill"
)

func TestSkillInstall_WritesIntoTheNamedSkillDirectory(t *testing.T) {
	root := t.TempDir()
	if got := runSkillInstall([]string{"--dir", root}); got != exitOK {
		t.Fatalf("exit = %d", got)
	}
	// The spec requires the directory to carry the skill's name, so --dir names
	// the skills ROOT and byn appends the rest. Getting this wrong writes a
	// skill agents silently ignore.
	dest := filepath.Join(root, agentskill.Name, agentskill.FileName)
	body, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("expected the skill at %s: %v", dest, err)
	}
	if strings.Contains(string(body), agentskill.Placeholder()) {
		t.Error("the installed skill still carries the version placeholder")
	}
	if got := agentskill.VersionOf(string(body)); got != version {
		t.Errorf("installed skill declares %q, want this binary's version %q", got, version)
	}
}

func TestSkillInstall_IsIdempotent(t *testing.T) {
	root := t.TempDir()
	if runSkillInstall([]string{"--dir", root}) != exitOK {
		t.Fatal("first install failed")
	}
	first, _ := os.ReadFile(filepath.Join(root, agentskill.Name, agentskill.FileName))
	if runSkillInstall([]string{"--dir", root}) != exitOK {
		t.Fatal("second install failed")
	}
	second, _ := os.ReadFile(filepath.Join(root, agentskill.Name, agentskill.FileName))
	if string(first) != string(second) {
		t.Error("re-installing changed the file")
	}
}

// --project is byn's GLOBAL scope flag. If the skill command ever claims it,
// `byn skill install --project foo` becomes ambiguous and the global parser
// eats the argument — which is exactly what happened before it was renamed.
func TestSkillFlags_DoesNotClaimProject(t *testing.T) {
	if _, code := skillFlags("install", []string{"--repo"}); code != exitOK {
		t.Fatal("--repo should be accepted")
	}
	dir, code := skillFlags("install", []string{"--repo"})
	if code != exitOK {
		t.Fatal("unexpected exit")
	}
	if !strings.HasPrefix(dir, filepath.Join(".claude", "skills")) {
		t.Errorf("--repo resolved to %q, want it under .claude/skills", dir)
	}
}

func TestSkillFlags_UserAndRepoAreExclusive(t *testing.T) {
	if _, code := skillFlags("install", []string{"--user", "--repo"}); code == exitOK {
		t.Error("--user with --repo must be refused, not silently resolved")
	}
}

func TestSkillFlags_DefaultIsUserScope(t *testing.T) {
	dir, code := skillFlags("install", nil)
	if code != exitOK {
		t.Fatal("default should resolve")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	if !strings.HasPrefix(dir, home) {
		t.Errorf("default resolved to %q, want it under %q", dir, home)
	}
}

func TestRunSkill_UnknownSubcommandFails(t *testing.T) {
	if got := runSkill([]string{"frobnicate"}, cliScope{}); got == exitOK {
		t.Error("an unknown subcommand must not exit 0")
	}
	if got := runSkill(nil, cliScope{}); got == exitOK {
		t.Error("no subcommand must not exit 0")
	}
}

// doctor must stay SILENT when no skill is installed: byn is used plenty
// without an agent, and a permanent line telling those people to install
// something they do not want is the noise that teaches people to skip doctor.
func TestCheckSkillFresh_SilentWhenNotInstalled(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	if _, applies := checkSkillFresh(); applies {
		t.Error("reported a finding with no skill installed anywhere")
	}
}

func TestCheckSkillFresh_OKWhenCurrent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	if runSkillInstall([]string{"--repo"}) != exitOK {
		t.Fatal("install failed")
	}
	c, applies := checkSkillFresh()
	if !applies {
		t.Fatal("expected a finding for an installed skill")
	}
	if !c.OK {
		t.Errorf("a freshly installed skill should be OK, got %+v", c)
	}
}

func TestCheckSkillFresh_WarnsWhenStale(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	if runSkillInstall([]string{"--repo"}) != exitOK {
		t.Fatal("install failed")
	}
	p := filepath.Join(".claude", "skills", agentskill.Name, agentskill.FileName)
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately not a plausible real version: under `go test` the binary's
	// own version is the unstamped default, and picking a neighbouring number
	// made the replacement a no-op that looked like a broken test.
	const old = "0.0.0-previous"
	stale := strings.Replace(string(body), `version: "`+version+`"`, `version: "`+old+`"`, 1)
	if stale == string(body) {
		t.Fatalf("could not construct a stale skill from a %q skill", version)
	}
	if werr := os.WriteFile(p, []byte(stale), 0o644); werr != nil {
		t.Fatal(werr)
	}

	c, applies := checkSkillFresh()
	if !applies {
		t.Fatal("expected a finding")
	}
	// WARN, not FAIL: a stale skill is a stale document, not a broken machine,
	// and doctor's exit code should not turn red over it.
	if c.OK || !c.Warn {
		t.Errorf("a stale skill should WARN, got %+v", c)
	}
	if !strings.Contains(c.Detail, old) || !strings.Contains(c.Fix, "byn skill install") {
		t.Errorf("the finding must name the stale version and the fix, got %+v", c)
	}
}
