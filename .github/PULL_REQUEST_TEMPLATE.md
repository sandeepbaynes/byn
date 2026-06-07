<!-- Thanks for contributing to byn! Keep PRs focused — one change per PR. -->

## What & why

<!-- What does this change, and why? Link the issue it closes. -->

Closes #

## Checklist

- [ ] Tests ship with the change (new behavior **and** error paths) — `make test` and `make test-integration` pass
- [ ] `golangci-lint run ./...` is clean
- [ ] Docs updated if behavior changed (`docs/`, `man/`, CLI help text)
- [ ] No secrets in plaintext and none via CLI args; nothing sensitive in the diff or test fixtures
- [ ] Commit subjects are imperative mood, ≤72 chars (e.g. `Add vault unlock command`)
- [ ] My commits are signed off (`git commit -s`) per the [DCO](../DCO)

<!-- New to the layout? See CONTRIBUTING.md, docs/architecture.md, and docs/spec.md. -->
