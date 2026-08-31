package site

import (
	"fmt"
	"regexp"
)

// Version is the byn release the site describes — the footer on every page and
// the per-page coverage stamps.
//
// It is DERIVED, not maintained. It used to be a constant with "bump it on
// every release" written next to it, and v0.5.0 shipped with the site still
// saying v0.4.1: a step that only a person can remember is a step that is
// eventually forgotten, and nothing failed when it was. `gensite` now sets this
// from CHANGELOG.md, which is already dated as part of releasing, and the
// generated pages are checked in CI — so a stale version becomes a failing
// build rather than a wrong number on the front page.
//
// The default is only what a caller that never sets it would see; gensite
// always does.
var Version = "v0.0.0-dev"

// ReleasesURL is the GitHub releases page (downloads + per-release assets),
// linked from the site footer.
const ReleasesURL = "https://github.com/sandeepbaynes/byn/releases"

// changelogRelease matches a released version heading: "## v1.2.3", with
// anything after it (the date). An unreleased heading has no version to show.
var changelogRelease = regexp.MustCompile(`(?m)^## (v\d+\.\d+\.\d+)\b`)

// VersionFromChangelog returns the newest release named in a CHANGELOG.
//
// Newest means first: the file is newest-first, and that ordering is load
// bearing here. If it ever stops being true this returns the wrong version
// rather than an error, which is why the site's own release notes are generated
// from the same file — the two would be wrong together and visibly so.
func VersionFromChangelog(changelog []byte) (string, error) {
	m := changelogRelease.FindSubmatch(changelog)
	if m == nil {
		return "", fmt.Errorf("no released version heading (## vX.Y.Z) in CHANGELOG")
	}
	return string(m[1]), nil
}
