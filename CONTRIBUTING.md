# Contributing to byn

Thanks for your interest in byn. A few things before you start.

## Sign-off: Developer Certificate of Origin (DCO)

byn is licensed under the **Business Source License 1.1** — source-available
(see [`LICENSE`](LICENSE)); each version converts to Apache-2.0 four years
after release. There is **no CLA**. Contributions are accepted under the
**[Developer Certificate of Origin](DCO)**: you keep full copyright in your
work and simply certify that you have the right to submit it under the
project's license.

You certify by **signing off your commits**:

```sh
git commit -s -m "Add vault unlock command"
```

That appends a `Signed-off-by: Your Name <you@example.com>` line from your
`git config` name/email. Every commit in a PR must carry one — the
[DCO check](.github/workflows/dco.yml) enforces it. Read exactly what you're
certifying in [`DCO`](DCO).

> Forgot to sign off? Amend the last commit with `git commit --amend -s`, or a
> whole branch with `git rebase --signoff origin/main`, then force-push.

> **Why DCO, not a CLA?** It keeps contribution friction low and the project
> never asks you to hand over relicensing rights. (BUSL is source-available,
> not OSI "open source" — but every release becomes Apache-2.0 on its fourth
> anniversary, and DCO means that promise can't be quietly revoked.)

## Project shape

- **Binary = thin IPC client.** All business logic lives in the daemon
  (`cmd/byn` → `internal/`).
- **Tests ship with the code** in the same PR. Every error path is tested.
- **No secrets in plaintext, ever; no secrets via CLI args.**
- Commit messages: imperative mood, ≤72-char subject
  (e.g. `Add vault unlock command`).

See [`docs/spec.md`](docs/spec.md) for the behavior contract and
[`docs/architecture.md`](docs/architecture.md) for the design.

## Build, test, install

Requires **Go 1.25+** (the dependencies set the floor). Works on macOS and Linux.

```sh
git clone git@github.com:sandeepbaynes/byn.git
cd byn
make build              # build the byn binary
make test               # unit tests
make test-integration   # integration tests
```

Install onto your PATH:

```sh
make install                          # → /usr/local/bin/byn (may need sudo)
make install BINDIR=$HOME/.local/bin  # no sudo
```

Or install straight with the Go toolchain (while the repo is private, point
Go at it via your GitHub SSH key — one-time per machine):

```sh
go env -w GOPRIVATE=github.com/sandeepbaynes/byn
git config --global url."git@github.com:".insteadOf "https://github.com/"
go install github.com/sandeepbaynes/byn/cmd/byn@main
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`. Once the repo is public
and tagged, this becomes the standard `…/cmd/byn@latest`.

## Pull requests

1. Branch off `main`.
2. Add tests with your change.
3. `make test` + `make test-integration` green; `golangci-lint` clean.
4. Open the PR; the DCO check confirms every commit is signed off.
5. A maintainer reviews. `main` is protected — merges require review + a
   passing DCO check.

## Maintainer notes — branch protection

Configure once at **Settings → Branches → Add branch protection rule** for
`main`:

- ✅ Require a pull request before merging (+ at least 1 approval)
- ✅ Require status checks to pass → select **DCO** and the **CI** jobs
- ✅ Require conversation resolution before merging
- ✅ (optional, stricter) Do not allow bypassing the above

That gives "public read, private write": anyone may fork and propose, but
nothing merges without your review and a DCO sign-off.
