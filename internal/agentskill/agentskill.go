// Package agentskill carries byn's Agent Skill — the instructions an AI coding
// agent reads to learn how to use byn correctly.
//
// The skill is EMBEDDED in the binary rather than installed as a separate file,
// and that is the whole design. A skill describes a CLI's behaviour, so a skill
// and a binary that disagree are worse than no skill at all: the agent follows
// instructions for a version it is not running. Shipping them as one artifact
// means the skill a binary emits is, necessarily, the skill for that binary.
//
// The version is substituted at emit time rather than written into the file.
// A version constant next to the words "bump this on release" is a step only a
// person can remember, and the site version was left stale exactly that way
// before it was derived instead (see tools/gensite/site.Version). The same
// reasoning applies here.
package agentskill

import (
	_ "embed"
	"strings"
)

// Name is the skill's identifier. The Agent Skills specification requires it to
// match the directory the SKILL.md sits in — here and wherever it is installed.
const Name = "byn"

// FileName is the spec's required filename inside a skill directory.
const FileName = "SKILL.md"

// versionPlaceholder is what the checked-in template carries where the version
// belongs. A test asserts it is still there, so that hardcoding a version — the
// failure this design exists to prevent — breaks the build rather than shipping.
const versionPlaceholder = "{{BYN_VERSION}}"

//go:embed byn/SKILL.md
var template string

// Template returns the skill exactly as checked in, placeholder intact.
func Template() string { return template }

// Placeholder returns the token Render replaces. Exported for the site
// generator, which performs the same substitution from the CHANGELOG version.
func Placeholder() string { return versionPlaceholder }

// Render returns the skill with version substituted in.
//
// An empty version yields the template unchanged rather than an empty metadata
// field: a skill that says nothing about its version is merely unhelpful, while
// one claiming version "" is wrong.
func Render(version string) string {
	if version == "" {
		return template
	}
	return strings.ReplaceAll(template, versionPlaceholder, version)
}

// VersionOf reads the metadata.version a rendered skill declares, or "" when it
// has none. It parses the one line it needs rather than pulling in a YAML
// dependency to read a single string out of frontmatter byn itself wrote.
func VersionOf(rendered string) string {
	for _, line := range strings.Split(rendered, "\n") {
		t := strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(t, "version:")
		if !ok {
			continue
		}
		return strings.Trim(strings.TrimSpace(rest), `"'`)
	}
	return ""
}
