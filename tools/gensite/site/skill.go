package site

// skill.go publishes byn's Agent Skill from the docs site, so an agent can
// discover and install it from a URL without cloning anything.
//
// The file itself is the one embedded in the binary (internal/agentskill) —
// published here rather than duplicated, because a second copy of a document
// whose whole job is to describe the current CLI is a second thing to get wrong.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// SiteBase is the path the site is served under.
//
// byn's docs are a GitHub Pages PROJECT site (…github.io/byn/), not a user
// site, so nothing can be published at the true domain root — the discovery
// URLs have to carry the prefix or they point at somebody else's pages. The
// spec is fine with this; Mintlify's own index serves "/docs/.well-known/…"
// for the same reason.
const SiteBase = "/byn"

// discoverySchema is the agent-skills discovery format the well-known index
// declares. Pinned rather than floating: a discovery document that silently
// changes shape is one an agent cannot rely on.
const discoverySchema = "https://schemas.agentskills.io/discovery/0.2.0/schema.json"

// skillEntry is one row of a discovery index.
type skillEntry struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Digest      string `json:"digest"`
}

type skillIndex struct {
	Schema string       `json:"$schema"`
	Skills []skillEntry `json:"skills"`
}

// SkillDescription pulls the description out of a rendered SKILL.md's
// frontmatter, which is what a discovery index advertises — the one field an
// agent reads before deciding whether to fetch the whole skill.
//
// It reads the single line it needs instead of adding a YAML dependency. The
// field is written as one line on purpose; a folded block would need a parser,
// and this is checked by a test.
func SkillDescription(rendered string) (string, error) {
	for _, line := range strings.Split(rendered, "\n") {
		if rest, ok := strings.CutPrefix(line, "description:"); ok {
			d := strings.TrimSpace(rest)
			if d == "" {
				return "", fmt.Errorf("skill frontmatter has an empty description")
			}
			return d, nil
		}
	}
	return "", fmt.Errorf("skill frontmatter has no description field")
}

// SkillOutputs returns the site files that publish the skill, keyed by path
// relative to the site root.
//
// Three surfaces, because agents disagree about where to look and the cost of
// serving all of them is a few hundred bytes:
//   - /skill.md              the plain endpoint, fetched directly
//   - /.well-known/agent-skills/…  the current discovery format (0.2.0)
//   - /.well-known/skills/…        the older one, still what some clients use
//
// One casing per directory, and the index links exactly what is served. Serving
// both SKILL.md and skill.md side by side is impossible to generate correctly:
// macOS filesystems are case-insensitive by default, so the two collapse into
// one file locally while the Linux build runner writes two — output that
// differs by the machine that produced it. The spec's casing wins inside
// .well-known/, the root endpoint keeps the lowercase /skill.md that Mintlify
// documents, and discovery is self-consistent because the URL comes from the
// index rather than from a client's guess.
func SkillOutputs(rendered, name string) (map[string]string, error) {
	desc, err := SkillDescription(rendered)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(rendered))
	digest := "sha256:" + hex.EncodeToString(sum[:])

	index := func(dir string) (string, error) {
		idx := skillIndex{
			Schema: discoverySchema,
			Skills: []skillEntry{{
				Name:        name,
				Type:        "skill-md",
				Description: desc,
				URL:         SiteBase + "/.well-known/" + dir + "/" + name + "/SKILL.md",
				Digest:      digest,
			}},
		}
		b, merr := json.Marshal(idx)
		if merr != nil {
			return "", merr
		}
		return string(b) + "\n", nil
	}

	agentSkills, err := index("agent-skills")
	if err != nil {
		return nil, err
	}
	legacy, err := index("skills")
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"skill.md": rendered,

		".well-known/agent-skills/index.json":            agentSkills,
		".well-known/agent-skills/" + name + "/SKILL.md": rendered,

		".well-known/skills/index.json":            legacy,
		".well-known/skills/" + name + "/SKILL.md": rendered,
	}, nil
}
