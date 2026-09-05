package agentskill

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// frontmatter returns the YAML block between the leading --- fences.
func frontmatter(t *testing.T, doc string) string {
	t.Helper()
	if !strings.HasPrefix(doc, "---\n") {
		t.Fatal("SKILL.md must OPEN with a --- frontmatter fence; the spec requires it at the very beginning")
	}
	end := strings.Index(doc[4:], "\n---\n")
	if end < 0 {
		t.Fatal("frontmatter is never closed")
	}
	return doc[4 : 4+end]
}

// The Agent Skills spec requires `name` to match the directory the SKILL.md
// sits in — here, and wherever it is installed. Our install path is built from
// Name, so a mismatch would write a skill that agents silently ignore.
func TestName_MatchesItsDirectory(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.IsDir() && e.Name() == Name {
			if _, serr := os.Stat(filepath.Join(e.Name(), FileName)); serr == nil {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no %s/%s — the skill directory must be named %q", Name, FileName, Name)
	}
	fm := frontmatter(t, Template())
	if !strings.Contains(fm, "name: "+Name+"\n") {
		t.Errorf("frontmatter name must be %q to match the directory", Name)
	}
}

// name constraints from the specification.
func TestName_SatisfiesTheSpec(t *testing.T) {
	if len(Name) == 0 || len(Name) > 64 {
		t.Fatalf("name must be 1-64 chars, got %d", len(Name))
	}
	if !regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`).MatchString(Name) {
		t.Errorf("name %q must be lowercase alphanumerics and single hyphens, "+
			"not starting or ending with one", Name)
	}
}

// description is what an agent reads at startup to decide whether the skill is
// relevant, and it is capped by the spec.
func TestDescription_PresentAndWithinTheCap(t *testing.T) {
	fm := frontmatter(t, Template())
	var desc string
	for _, line := range strings.Split(fm, "\n") {
		if rest, ok := strings.CutPrefix(line, "description:"); ok {
			desc = strings.TrimSpace(rest)
		}
	}
	if desc == "" {
		t.Fatal("frontmatter must carry a non-empty description")
	}
	if len(desc) > 1024 {
		t.Errorf("description is %d chars; the spec caps it at 1024", len(desc))
	}
	// It must be ONE line: the site generator reads it with a line scan rather
	// than a YAML parser, so a folded block would silently truncate it.
	if strings.Contains(desc, "\n") {
		t.Error("description must be a single line")
	}
	// It should say WHEN to use the skill, not only what it is — that is what
	// makes an agent load it at the right moment.
	if !strings.Contains(strings.ToLower(desc), "use when") {
		t.Error(`description should say when to activate ("Use when ...")`)
	}
}

// The version must stay DERIVED. Hardcoding one is the exact failure this
// design exists to prevent: a skill claiming a version it was not built with.
func TestTemplate_KeepsTheVersionPlaceholder(t *testing.T) {
	if !strings.Contains(Template(), Placeholder()) {
		t.Fatalf("the checked-in SKILL.md no longer contains %s — the version must be "+
			"substituted at emit time, never written into the file", Placeholder())
	}
	if regexp.MustCompile(`(?m)^\s*version:\s*"\d+\.\d+\.\d+"`).MatchString(Template()) {
		t.Error("a concrete version is hardcoded in the template; it will go stale silently")
	}
}

func TestRender_SubstitutesTheVersion(t *testing.T) {
	got := Render("1.2.3")
	if strings.Contains(got, Placeholder()) {
		t.Error("placeholder survived rendering")
	}
	if !strings.Contains(got, `version: "1.2.3"`) {
		t.Error("rendered skill does not declare the version it was given")
	}
	if VersionOf(got) != "1.2.3" {
		t.Errorf("VersionOf round-trip = %q, want 1.2.3", VersionOf(got))
	}
}

// An empty version must not produce a skill claiming version "": unhelpful is
// better than wrong, and the doctor check compares this field.
func TestRender_EmptyVersionLeavesThePlaceholder(t *testing.T) {
	if Render("") != Template() {
		t.Error("an empty version should leave the template untouched")
	}
}

func TestVersionOf_NoVersion(t *testing.T) {
	if got := VersionOf("---\nname: byn\n---\nbody"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// Progressive disclosure: the whole body is loaded once a skill activates, so
// the spec asks for under 500 lines. Past that it should be split into
// references/ rather than growing.
func TestTemplate_StaysWithinTheRecommendedSize(t *testing.T) {
	if n := strings.Count(Template(), "\n"); n > 500 {
		t.Errorf("SKILL.md is %d lines; the spec recommends under 500 — "+
			"move detail into references/ instead of growing the body", n)
	}
}

// The skill's central instruction. If this ever stops being stated the skill has
// lost its purpose, because everything else it says is in service of it.
func TestTemplate_TellsAgentsNotToReadSecrets(t *testing.T) {
	body := Template()
	for _, must := range []string{"byn exec", "Never read a secret"} {
		if !strings.Contains(body, must) {
			t.Errorf("SKILL.md no longer contains %q", must)
		}
	}
}
