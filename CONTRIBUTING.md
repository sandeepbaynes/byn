# Contributing to byn

Thanks for your interest in byn. A few things before you start.

## Contributor License Agreement (required)

byn is licensed under **PolyForm Noncommercial 1.0.0** (see [`LICENSE`](LICENSE)).
Because the project may also be offered under separate commercial terms,
every contributor must agree to the **[Contributor License Agreement](CLA.md)**
before a pull request can be merged.

It's lightweight and automated. The first time you open a PR, a bot comments
with a link; you sign by replying **exactly**:

> I have read the CLA Document and I hereby sign the CLA

Your signature is recorded and applies to all your future PRs. The CLA lets
you keep copyright on your contribution while granting the project the right
to use and relicense it. Read it in full: [`CLA.md`](CLA.md).

> **The bot is a convenience, not a precondition.** Per the [CLA](CLA.md) (§6),
> **submitting any contribution — by any means — is itself acceptance** of the
> agreement, whether or not the bot recorded a signature and regardless of how
> the contribution reached the project. The signing step just makes that
> acceptance explicit and easy to track.

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
4. Open the PR; sign the CLA when the bot asks.
5. A maintainer reviews. `main` is protected — merges require review + a
   passing CLA check.

## Maintainer notes — branch protection

Configure once at **Settings → Branches → Add branch protection rule** for
`main`:

- ✅ Require a pull request before merging (+ at least 1 approval)
- ✅ Require status checks to pass → select **CLA Assistant** and the **CI** jobs
- ✅ Require conversation resolution before merging
- ✅ (optional, stricter) Do not allow bypassing the above

That gives "public read, private write": anyone may fork and propose, but
nothing merges without your review and a signed CLA.
