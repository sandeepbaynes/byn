---
name: byn
description: Run commands with secrets injected from an encrypted local vault, without ever reading the secret values into context. Use when a repository contains a .byn file, when a command needs API keys, database URLs, or cloud credentials, when you would otherwise read or write a .env file, or when the user mentions byn, secrets, credentials, or environment variables for a dev server, test run, or script.
license: BSL-1.1, converting to Apache-2.0. See LICENSE in the byn repository.
compatibility: Requires the byn CLI (macOS or Linux) with its daemon running. Check with `byn status`.
metadata:
  version: "{{BYN_VERSION}}"
  homepage: "https://github.com/sandeepbaynes/byn"
  docs: "https://sandeepbaynes.github.io/byn/"
---

# byn

byn keeps secrets in an encrypted local vault and injects them into a child
process's environment. **You run commands that use secrets; you never see the
secrets.** That is the entire point of the tool — if a value reaches your
context, byn has failed at its job and so have you.

## The rules

1. **Never read a secret value.** Do not run `byn get`, `byn cat`, or
   `byn export` to "check" a value, and never echo one. Use `byn exec`, which
   passes values to the child process without printing them.
2. **Never write secrets to a file.** No `.env`, no config file, no test
   fixture. If a tool needs a value, run that tool under `byn exec`.
3. **Prefix the command, do not reshape it.** `npm run dev` becomes
   `byn exec -- npm run dev`. Keep the command otherwise identical.
4. **Never pass a secret as a command-line argument.** argv is world-readable
   in `ps`. `byn put` reads from stdin for this reason.
5. **You cannot approve your own access.** Trust and approval are the human's
   job (see [Trust](#trust-is-a-human-action)). Do not try to work around a
   refusal — report it and ask.

## Running a command

```bash
byn exec -- <command> [args...]
```

Everything after `--` runs with the vault values named in the project's `.byn`
allowlist injected into its environment. The child runs under privilege
separation as the `_byn-exec` service user, so its environment is hidden even
from same-user `ps -E`. This is the mode intended for agents and unattended runs.

If the project's `.byn` is trusted and declares a matching action, this runs
**credential-free** — no password, even with the vault locked. That is the
normal path for you.

Named actions declared in `[aliases]` can be run by name:

```bash
byn exec dev          # runs whatever [aliases] dev = "..." names
```

Use `--dry-run` to see which variables *would* be injected, without running
anything and without printing values.

### Exit codes

The exit code is normally the child's own. Before the child starts:

| Code | Meaning | What to do |
|---|---|---|
| 1 | Bad usage, missing binary, or alias with no `.byn` | Fix the command |
| 2 | Daemon unreachable | `byn status`; the error names the recovery command |
| 3 | Vault locked, or `.byn` untrusted / changed / tampered | A human must act — see below |

Exit 3 with an untrusted or changed `.byn` is the common one. **It is not a bug
and not something to route around.** Report it and ask the user to re-trust.

## The `.byn` file

A project declares its own scope and what may be injected. It is committed to
the repository; it holds **no secret values**, only names.

```toml
[scope]
vault   = "default"
project = "myapp"
env     = "dev"

[exec]
env     = ["DATABASE_URL", "API_KEY"]     # ONLY these are injected
actions = ["npm run dev", "npm test"]      # commands allowed to run
writable = ["~/Library/Preferences/mytool"] # dirs the child may write

[aliases]
dev = "npm run dev"
```

- `[exec] env` is an allowlist. A variable not named here is never injected,
  however it is stored.
- `[exec] actions` pins which commands may run credential-free.
- `[exec] writable` grants the child access to tool-state directories outside
  the project. Declare one when a tool fails with `EACCES` on its own cache or
  config directory. Paths must be under the user's home.

**Editing `.byn` invalidates its trust.** The file is fingerprinted at trust
time, so any change — including one you make — requires a human to re-trust it
before `byn exec` will work again. If you edit it, say so explicitly and tell
the user they must run `byn trust`.

## Trust is a human action

Granting trust always requires the master password, even when the vault is
unlocked, because approving a `.byn` is a proof-of-presence action. **You cannot
do it and must not try.** When you hit an untrusted or changed `.byn`:

1. Run `byn trust diff` to show *what* changed. This is safe and reveals no
   secrets.
2. Report the diff to the user and ask them to run `byn trust`.
3. Wait. Do not edit the `.byn` to make the error go away, and do not fall back
   to reading a `.env`.

## When byn asks for approval

Some requests raise an approval the owner must answer. The response carries a
`watch_ticket`. **Keep it — it is issued once and cannot be re-requested.**

```bash
byn request watch <TICKET>     # blocks until answered, prints JSON
byn request cancel <TICKET>    # withdraw a request you no longer need
```

The JSON gives `status` (`approved` / `denied`), the decider's `reason`, and
whether the grant was `once`. A denial is an answer, not an obstacle: report the
reason to the user and stop.

If you are running unattended and cannot wait for a human, prefer
`byn exec --wait-approval=DUR` so the request has a bounded life rather than
hanging forever.

## Storing a value

Only when the user asks you to store something:

```bash
printf '%s' "$VALUE" | byn put NAME     # value on stdin, never in argv
```

Values you store while unattended are marked `put.unattended` in the audit log,
because byn cannot tell a value an agent invented from one the user dictated.
Expect the user to review them; `byn list --long` shows the marking.

## Diagnostics

| Command | Use |
|---|---|
| `byn status` | Is the daemon up, which vaults exist, are they locked |
| `byn doctor` | Full health check; needs no unlock, prints no secrets |
| `byn ps` | Running `byn exec` jobs and what each is running |
| `byn kill <pid>` | Stop a job **and its whole process tree** |
| `byn repair` | Give the user back access to files an exec child created |
| `byn audit tail` | Recent activity, including who ran what |

**Use `byn kill`, never `kill` or `pkill`.** Under privilege separation the
children run as `_byn-exec`, so a signal from your shell is refused with EPERM —
silently, because `kill(1)` reports nothing when it cannot signal. Killing the
wrapper yourself succeeds and orphans its children, which strands the port with
nothing left to signal it by. `byn kill` signals the whole tree through the
privileged helper and tells you what actually stopped.

If a dev server fails with `EACCES` on a cache or config directory, that is the
exec child lacking access to a path outside the project. The fix is an
`[exec] writable` entry in the `.byn` (which needs a re-trust), not a `chmod`.

## Things that look like solutions and are not

- Reading a value "just to verify it is set" — use `byn exec --dry-run`, which
  names the variables without printing values, or `byn list NAME`, which is a
  grep-style existence check.
- Writing a `.env` "temporarily" — it will be committed, or read, or both.
- Editing `.byn` to widen the allowlist so a command works — that is a privilege
  escalation the user has not agreed to. Ask.
- Running `byn` with `sudo` — byn runs as the user. `sudo` is only for the
  service commands (`setup`, `restart`), which you should not be running.
- `byn exec --no-privsep` — it requires the master password on every run by
  design, and no trusted `.byn` authorizes it. It exists for human debugging.

## Keeping this skill current

byn's behaviour changes between releases, and a stale skill will describe a CLI
that no longer matches.

- The version this skill documents is in its frontmatter: `metadata.version`.
- The installed CLI's version comes from `byn --version`.

**If they differ, refresh the skill:**

```bash
byn skill install        # rewrites this file from the installed binary
```

The binary carries the skill matching itself, so the reinstall cannot produce a
mismatch. `byn doctor` also reports a stale installed skill.

When a byn upgrade lands, re-run `byn skill install` before relying on details
here. If a command in this skill does not exist in `byn help`, trust `byn help`
and tell the user the skill is out of date.
