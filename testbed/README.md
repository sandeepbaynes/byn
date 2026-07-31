# testbed — a throwaway project for exercising byn as an agent would

A disposable playground so changes to byn can be tried end to end without
touching a real vault. Everything here targets the **`agenttest`** vault,
which holds only fake values.

`FINDINGS.md` is the log of what broke when byn was driven from a non-TTY
shell. Read that before designing v2 changes.

## Setup (already done once; repeat only if the vault is gone)

```sh
head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 28 > testbed/TEST-VAULT-PASSWORD
PW=$(cat testbed/TEST-VAULT-PASSWORD)
printf '%s' "$PW" | byn --vault agenttest init   --password-stdin
printf '%s' "$PW" | byn --vault agenttest unlock --password-stdin
byn --vault agenttest project create testbed
printf 'postgres://localhost/testbed' | byn --vault agenttest --project testbed put TESTBED_DB_URL
printf '%s' "$PW" | byn trust --password-stdin testbed/
```

`TEST-VAULT-PASSWORD` is gitignored. It guards nothing real — its only job is
letting an agent work without stopping for a human. Never store a real secret
in this vault.

## Layout

| File | Role |
|---|---|
| `.byn` | scope + `[exec] env` allowlist + pinned `[exec] actions` |
| `app.sh` | service stand-in; hard-fails on any missing variable |
| `build.sh` | creates `.next/` and `node_modules/.vite/` — reproduces the ownership trap |
| `server.sh` | long-running process, for rotation/staleness and kill tests |
| `clean.sh` | deletes build output; exists *only* because the user cannot |

## Gotchas that will waste your time (all confirmed, see FINDINGS.md)

- **Put flags before positionals.** `byn put --password-stdin NAME`, not
  `byn put NAME --password-stdin` — the latter is byn's documented example and
  it silently treats the flag as the secret value.
- **Pin absolute paths in `[exec] actions`.** Relative patterns never match
  under privsep; the command is absolutized before matching.
- **`byn exec <alias>` skips privsep** and runs as you. Use
  `byn exec -- <absolute-path>` when testing isolation.
- **Any `.byn` edit — even `touch` — blocks every command** until re-trust.
- **`byn trust diff` needs the file path** (`./.byn`), not the directory.

## Cleanup

```sh
byn exec -- "$PWD/clean.sh"                    # build output belongs to _byn-exec
printf '%s' "$(cat testbed/TEST-VAULT-PASSWORD)" | byn vault delete agenttest --password-stdin
```
