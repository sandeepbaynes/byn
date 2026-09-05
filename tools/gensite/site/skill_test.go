package site

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const testSkill = `---
name: byn
description: Does a thing. Use when the thing is needed.
metadata:
  version: "1.2.3"
---

# byn
body
`

func TestSkillOutputs_ServesTheDiscoverableSurfaces(t *testing.T) {
	outs, err := SkillOutputs(testSkill, "byn")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"skill.md",
		".well-known/agent-skills/index.json",
		".well-known/agent-skills/byn/SKILL.md",
		".well-known/skills/index.json",
		".well-known/skills/byn/SKILL.md",
	} {
		if _, ok := outs[want]; !ok {
			t.Errorf("missing output %s", want)
		}
	}
}

// macOS filesystems are case-insensitive, so SKILL.md and skill.md in the SAME
// directory collapse into one file locally while a Linux runner writes two —
// generated output that differs by the machine that produced it.
func TestSkillOutputs_NoCaseCollisionWithinADirectory(t *testing.T) {
	outs, err := SkillOutputs(testSkill, "byn")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for path := range outs {
		key := strings.ToLower(path)
		if prev, dup := seen[key]; dup {
			t.Errorf("%s and %s differ only by case; they are the same file on macOS", prev, path)
		}
		seen[key] = path
	}
}

// A discovery index that points at a URL we do not serve is worse than none.
func TestSkillOutputs_IndexPointsAtSomethingServed(t *testing.T) {
	outs, err := SkillOutputs(testSkill, "byn")
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range []string{".well-known/agent-skills/index.json", ".well-known/skills/index.json"} {
		var parsed struct {
			Schema string `json:"$schema"`
			Skills []struct {
				Name, Type, Description, URL, Digest string
			} `json:"skills"`
		}
		if uerr := json.Unmarshal([]byte(outs[idx]), &parsed); uerr != nil {
			t.Fatalf("%s is not valid JSON: %v", idx, uerr)
		}
		if len(parsed.Skills) != 1 {
			t.Fatalf("%s: got %d skills, want 1", idx, len(parsed.Skills))
		}
		e := parsed.Skills[0]
		if parsed.Schema == "" || e.Type != "skill-md" || e.Name != "byn" {
			t.Errorf("%s: unexpected entry %+v", idx, e)
		}
		// The site is a GitHub Pages PROJECT site, so every URL must carry the
		// base path or it points at the root of somebody else's pages.
		if !strings.HasPrefix(e.URL, SiteBase+"/") {
			t.Errorf("%s: url %q must start with the site base %q", idx, e.URL, SiteBase)
		}
		served := strings.TrimPrefix(e.URL, SiteBase+"/")
		if _, ok := outs[served]; !ok {
			t.Errorf("%s: index points at %q, which is not published", idx, served)
		}
		// The digest must describe the file actually served there.
		sum := sha256.Sum256([]byte(outs[served]))
		if want := "sha256:" + hex.EncodeToString(sum[:]); e.Digest != want {
			t.Errorf("%s: digest %s does not match the served file (%s)", idx, e.Digest, want)
		}
	}
}

func TestSkillDescription(t *testing.T) {
	got, err := SkillDescription(testSkill)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Does a thing. Use when the thing is needed." {
		t.Errorf("got %q", got)
	}
	if _, err := SkillDescription("---\nname: byn\n---\n"); err == nil {
		t.Error("a skill with no description must be an error, not an empty index entry")
	}
	if _, err := SkillDescription("---\nname: byn\ndescription:\n---\n"); err == nil {
		t.Error("an empty description must be an error")
	}
}
