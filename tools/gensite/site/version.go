package site

// Version is the current byn release. It is the single source of truth for the
// version shown in the docs-site footer and the per-page coverage stamps.
//
// Bump it on every release (see the release checklist) — it drives both the
// manifest's per-page version stamp and the footer version on every page.
const Version = "v0.4.1"

// ReleasesURL is the GitHub releases page (downloads + per-release assets),
// linked from the site footer.
const ReleasesURL = "https://github.com/sandeepbaynes/byn/releases"
