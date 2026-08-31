package site

import (
	"fmt"
	"regexp"
)

// The landing page is hand-authored HTML rather than generated from markdown,
// so it is not in the manifest and nothing was keeping its version honest. It
// named the release twice, both times as literal text, and both were still
// v0.4.1 the day v0.5.0 shipped.
//
// Each spot is anchored to the markup around it and must match exactly once.
// A loose search for a version-shaped string would also rewrite one mentioned
// in prose ("added in v0.3.0"), and silently matching nothing is how this was
// missed in the first place — so a spot that stops matching is an error, not a
// no-op.
var landingVersionSpots = []struct {
	what string
	re   *regexp.Regexp
}{
	{
		what: "hero badge",
		re:   regexp.MustCompile(`(<div class="hero-badge"><div class="badge-dot"></div>)v\d+\.\d+\.\d+`),
	},
	{
		what: "footer",
		re:   regexp.MustCompile(`(<span>byn <a href="docs/releases/">)v\d+\.\d+\.\d+`),
	},
}

// StampLanding rewrites the release named on the hand-authored landing page.
func StampLanding(html, version string) (string, error) {
	for _, spot := range landingVersionSpots {
		if n := len(spot.re.FindAllString(html, -1)); n != 1 {
			return "", fmt.Errorf("landing page %s: found %d version markers, want exactly 1 "+
				"(the markup changed — update landingVersionSpots)", spot.what, n)
		}
		html = spot.re.ReplaceAllString(html, "${1}"+version)
	}
	return html, nil
}
