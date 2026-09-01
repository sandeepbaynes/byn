# Internal design notes — not published

Working notes: plans, spikes, and decisions in progress. They are for people
building byn, not for people using it.

**Nothing in this directory is published.** The site publishes exactly the pages
listed in `tools/gensite/site/manifest.go`, and the deploy fails if a markdown
source reaches the built site at all.

That guard exists because the rule used to be a convention. The workflow copied
`docs/` into the site verbatim, so every file here was served raw at its own
`.md` URL — design notes included, with whatever they happened to mention.

Writing for users? Put it in `docs/` proper and add it to the manifest. If it is
not in the manifest it does not exist as far as the site is concerned, which is
the intended behaviour for this directory.
