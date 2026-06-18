# byn + AI coding agents

This document shows how an AI coding agent can use byn to read, write,
and consume vault secrets safely — agents can see **key names** and
**structure**, but values only land in the child process spawned via
`byn exec`, not in agent context or scrollback.

---

## Why byn for agents

A code agent often has the following problem:

- It needs to know **what env vars exist** (to build a `.env.example`,
  configure a script, write tests).
- It must **not** read raw secret values into its conversational
  context — once in the agent's working memory, they can leak to logs,
  remote tracing, or model providers.
- It needs to **run** real commands that use those secrets.

byn addresses all three:

| Need                                     | byn command                         | Returns to agent? |
|------------------------------------------|----------------------------------------|-------------------|
| Discover vaults                          | `byn vault list --json`             | yes (names only)  |
| Discover projects                        | `byn project list --json`           | yes (names only)  |
| Discover envs                            | `byn env list --json`               | yes (names only)  |
| Discover keys in current scope           | `byn list --json`                   | yes (names only)  |
| Read a secret value                      | `byn get NAME`                      | **NO** — block this in your harness |
| Run a command with secrets injected      | `byn exec -- CMD ARGS`              | child's stdout; values never sent back to agent |
| Bulk-write keys (from .env / .json / yaml) | `byn import [PATH \| -]`            | yes (counts only) |
| Export entire scope (dangerous)          | `byn export --format env`           | **NO** — block this in your harness |

> **`byn exec` and authorization — the agent pattern.** For an **unattended**
> agent the only credential-free path is a **trusted `.byn` with the command
> pinned in `[exec] actions`**: it runs with **no password, even while the vault
> is locked** (the values are injected via a sealed capability). An **unpinned**
> command, or **ad-hoc exec** with no `.byn`, requires a fresh master password
> per run — which an unattended agent can't supply, so it **fails closed**.
> `byn unlock` / sessions do **not** authorize exec. So: set up the project's
> `.byn` (pinned `[exec] actions` + a minimal `[exec] env` allowlist), `byn trust`
> it once, and the agent runs the approved commands autonomously while everything
> else stays gated. **Do not use `--no-privsep` in an agent harness** — it
> requires a password every run and exists for interactive human debugging.

---

## Recommended agent harness rules

In your agent harness (hooks, permission rules, or system prompt), allow:

```
byn daemon status
byn status
byn status --json
byn vault list --json
byn project list --json
byn env list --json
byn list --json
byn --vault X --project Y --env Z list --json
byn import …       # writes only
byn project create NAME
byn env create NAME --project P
byn put NAME       # value comes from agent-provided stdin; ok
byn exec -- ANY    # values land in child; never bubble back to agent context
```

Deny:

```
byn get NAME             # leaks plaintext into agent transcript
byn export …             # bulk leak
```

(Deny `cat NAME` and `byn cat NAME` similarly — `cat` is an alias
for `get`.)

---

## Example agent flow: bootstrap a project

1. **Agent**: lists current state.

   ```sh
   byn status --json
   byn project list --json
   byn --project myapp-agent env list --json
   byn --project myapp-agent list --json
   ```

2. **User (before the agent is active)**: import any existing `.env`
   into the vault and delete the file, so the agent never has a
   plaintext file to read in the first place:

   ```sh
   byn --project myapp-agent import .env.local
   rm .env.local   # values now live in the vault only
   ```

   Do this step *yourself*. If the agent runs the import, the values
   pass through the agent's own process — which defeats the point.

3. **Agent**: writes a runner that uses byn for any command that
   needs secrets:

   ```sh
   #!/usr/bin/env bash
   exec byn --project myapp-agent exec -- "$@"
   ```

4. **Agent**: now runs the user's tests via that wrapper:

   ```sh
   ./scripts/with-secrets npm test
   ```

The agent never sees `DATABASE_URL=postgres://…` — only `DATABASE_URL`.
The test runner gets the URL via environ from `byn exec`.

---

## Example: harness allow/deny rules

Most agent harnesses read an allow/deny rule file. Configure it with
rules like:

```jsonc
{
  "permissions": {
    "allow": [
      "Bash(byn status*)",
      "Bash(byn list*)",
      "Bash(byn project*)",
      "Bash(byn env*)",
      "Bash(byn vault list*)",
      "Bash(byn import*)",
      "Bash(byn put*)",
      "Bash(byn exec --*)"
    ],
    "deny": [
      "Bash(byn get*)",
      "Bash(byn cat*)",
      "Bash(byn export*)"
    ]
  }
}
```

(Tighten or loosen as fits your trust model. For a fully sandboxed
project, you may want to allow `get` too — but only if the agent's
output is not piped anywhere the user wouldn't otherwise see.)

> **Important — these deny rules are best-effort, not a guarantee.**
> Agent-harness permission rules have a documented history of not being
> reliably enforced — e.g.
> [anthropics/claude-code#24846](https://github.com/anthropics/claude-code/issues/24846),
> where a `read.deny` rule failed to block `.env` reads. Do **not** treat
> the deny list as byn's security boundary. byn's real protections are:
> (1) there is **no plaintext `.env` on disk** for the agent to read —
> values live only in the vault; and (2) **every value access is
> audited** (`byn audit`), so a leak is *detectable* even when a deny
> rule fails. Prevention is best-effort; detection is the guarantee.

---

## Patterns to know

### Pin a per-project scope

Add to your project's `.envrc` (direnv) or shell init:

```sh
export BYN_PROJECT=myapp-agent
export BYN_ENV=dev
```

The agent then needs no flags — every `byn` command picks the right
scope.

### Read-only agent on a remote VM

When you ssh a long-running agent into a dev VM:

1. The agent gets `byn` and the daemon dir read access.
2. The vault unlock password lives on YOUR laptop only.
3. Agent runs `byn exec -- whatever` — values are injected only
   when you're connected and have unlocked the vault from your client.
4. An idle vault auto-relocks after `[daemon] idle_timeout` (default
   15m); run `byn lock` (or `byn lock --session`) to drop access
   immediately.

### Audit trail

Every `byn` op writes an HMAC-chained entry to the vault's audit
log. The agent's actions are reviewable with `byn audit`
(`tail`, `view`, `verify`).

---

## Scoping what an agent can do

Per-command secret scoping is shipped via the `.byn` manifest:

- `[exec] env` lists exactly which vars `byn exec` injects — the agent
  never sees the rest of the scope.
- `[exec] actions` pins which commands run without per-call
  authorization; everything else is gated.

See the [`.byn` file format](../byn-file-format.md).

### Not yet shipped

- Push-based unlock approval (laptop receives a notification when an
  agent on a remote VM tries to read; user taps to allow). Deferred.
