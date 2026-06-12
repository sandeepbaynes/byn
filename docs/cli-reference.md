# CLI reference

Every command, every flag, every env var, every exit code.

Per-command help is also reachable from the binary itself:

```
byn <command> --help
byn help <command>
byn <command> -h
```

Help output pages through `$PAGER` (default `less -RFX`) when stdout
is a TTY. See [Pager / hint env vars](#pager-and-hint-env-vars).

---

## Global flags (work before OR after the subcommand)

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `--vault NAME` | `BYN_VAULT` | `default` | Target vault |
| `--project NAME` | `BYN_PROJECT` | `default` | Target project |
| `--env NAME` | `BYN_ENV` | `default` | Target env |
| `--no-discovery` | `BYN_NO_DISCOVERY=1` | off | Skip `.byn` walk for this call |
| `--json` | n/a | off | Agent mode: machine-readable output AND no interactive prompts; untrusted `.byn` hard-fails |

Conflicting duplicate values are a **hard error**:

```
$ byn --vault a --vault b list
Error: --vault specified twice with different values: "a" vs "b"
```

Resolution precedence (highest first): CLI flag > env var > `.byn`
discovery > daemon default.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic error (bad input, runtime failure, lint-style problem) |
| `2` | Daemon unreachable — recovery hint printed to stderr |
| `3` | Daemon returned a typed error (wrong password, locked, not found, audit chain broken, etc.) |

Use these for scripting:

```sh
byn get DB_URL || case $? in
    2) echo "start the daemon" ;;
    3) echo "unlock the vault" ;;
esac
```

---

## Lifecycle

### `byn init [--password-stdin]`

Create a new vault under `~/.byn/vaults/<scope.Vault>/` (defaults to
`default`).

- Prompts for the master password twice in TTY mode (confirms typo).
- `--password-stdin` reads one line, no confirm.
- Implicitly creates `default` project + `default` env.

Errors:
- `already_init` if the vault directory already exists.

### `byn unlock [--password-stdin]`

Unwrap the vault key into the daemon's memory.

- Subject to the failed-unlock backoff (`auth-state.json`).
- On success, starts the per-vault idle timer.

### `byn lock`

Zero the in-memory vault key for `--vault` (or `*` to lock all).

### `byn daemon start [--foreground]`

Start the long-lived daemon.

- Default: detached via `Setsid: true`, logs to `~/.byn/daemon.log`.
- `--foreground` runs in the current terminal; ctrl-C signals shutdown.
- Refuses if a daemon is already responding (stale pidfile is
  detected via signal-0 probe and ignored).

### `byn daemon stop`

SIGTERM via pidfile. Idempotent.

### `byn daemon status` (alias: `byn status [--json]`)

Print:
- Daemon running state + version + protocol range
- Socket path + uptime
- Every vault on disk + locked/unlocked + last-active timestamp
  (last-active is suppressed when the vault is locked — see
  [security.md](security.md))

`--json` emits the full `StatusResp` for agent harnesses.

---

## Structure CRUD

### `byn vault list [--json]`

List every vault present under `~/.byn/vaults/`. Human output
shows name + state (`unlocked`/`locked`/`uninitialized`).

### `byn vault delete NAME [--password-stdin]`

Cascade-delete: removes the vault directory and all entries. Refuses
`default`. Password required when locked or when no session is present.

### `byn vault rename OLD NEW [--password-stdin]`

Rename a vault and its audit trail. Refuses `default` and an existing
destination. The vault is left **locked** after the rename. Password
required when locked or when no session is present.

### `byn vault {init,unlock,lock}`

Aliases for the top-level lifecycle commands (`byn init`, etc.).
Provided so muscle memory works either way.

### `byn project list [--json]`

List projects in the active vault.

### `byn project create NAME`

Create a project. Implicitly creates a `default` env for it.

- `NAME` can be a positional or `--project NAME` (the scope flag).

### `byn project delete NAME [--password-stdin]`

Cascade-delete: removes the project + every env + every entry +
every entry_version. Refuses `default`. Password required when locked
or when no session is present.

### `byn project rename OLD NEW`

Rename. Refuses to rename to `default` or rename `default` away.

### `byn env list [--json]`

List envs in the active project. The default env is pinned first; the
rest are alphabetical.

### `byn env create NAME`

Create a non-default env in the active project.

### `byn env delete NAME [--password-stdin]`

Delete a non-default env. Refuses `default`. Cascades to its entries
+ entry versions. Password required when locked or when no session is
present.

### `byn env rename OLD NEW`

Rename. Refuses `default`.

---

## Env-vars (active scope)

### `byn put NAME [--create-only] [--password-stdin]`

Store an env-var entry under `(scope.Project, scope.Env)`.

- Value comes from **stdin only**. `byn put NAME VALUE` is
  rejected — values in argv leak to ps and shell history.
- `--create-only` fails with `already_exists` if the name is taken
  (used by `import --skip-existing`).
- Hint on success: `Stored "NAME" in vault/project/env.`
- Overwriting an existing entry requires the master password when no session
  is present. New entries (first put of a name, or `--create-only`) do not.
- `--password-stdin` contract: the **first line** of stdin is always
  the master password; the **remainder** (after the first `\n`) is the
  secret value. The first line is always consumed when `--password-stdin`
  is set, even if the daemon never requests authorization:
  ```sh
  { echo "$BYN_PW"; printf 'new-val'; } | byn put key --password-stdin
  ```
- Locked vault with `--password-stdin`: hard fail ("byn unlock") — a
  password alone cannot decrypt a locked vault for a write.

Examples:
```sh
echo 's3cr3t' | byn put DB_PASSWORD
byn put TLS_CERT < server.crt
```

### `byn get NAME [--json] [--password-stdin]` (alias: `byn cat NAME`)

Print the decrypted value to stdout.

- Inheritance: if the name doesn't exist in `scope.Env`, the daemon
  falls back to the project's `default` env.
- TTY: appends a trailing newline so the next prompt doesn't run on.
- Non-TTY: raw bytes, no trailing newline (safe for piping/redirection).
- `--json` emits `{"name": ..., "value": ...}` — use only in trusted
  harnesses; values land in your agent's context.
- The master password is required when no session is present.
  `--password-stdin` reads the entire stdin as the password (no newline
  split — contrast with `put`).
- Locked vault: always a hard fail ("byn unlock"); a password cannot
  decrypt a locked vault.

### `byn list [--json]` (alias: `byn ls`)

List entry names + per-entry metadata. JSON emits:

```json
[
  {
    "name": "DB_URL",
    "source": "scope",       // or "default" if inherited from default env
    "created_at": "...",
    "updated_at": "..."
  }
]
```

Allowed while locked (names are not secret). Not gated by the session matrix.

### `byn delete NAME [--password-stdin]` (alias: `byn rm NAME`)

Remove an entry. No inheritance — must exist in `scope.Env`.
Allowed while locked (names only, no values touched).

- When the vault is locked or no session is present, the master password
  is required. `--password-stdin` reads entire stdin as the password.
- A locked vault accepts `delete` with the password (unlike `get`/`put`
  which require unlock for value operations).

### `byn rename OLD NEW [--password-stdin]` (alias: `byn mv OLD NEW`)

Move within `scope.Env`. Daemon re-encrypts under the new AAD.
Requires unlock (re-encryption needs the vault key).

- The master password is required when no session is present.
  `--password-stdin` reads entire stdin as the password.
- Locked vault: hard fail ("byn unlock") — re-encryption requires the
  vault key.

---

## Bulk I/O

### `byn import [--format env|yaml|json] [--dry-run] [--skip-existing | --replace [--yes]] [PATH | -]`

Bulk-load key→value entries.

- Format inferred from extension first (`.env`, `.yaml`, `.yml`,
  `.json`), then sniffed (leading `{` → JSON), then `--format`
  override required.
- Stdin: `-` or no positional. Pipeable: `cat .env | byn import`.
- Nested data is rejected with `key %q: nested or unsupported type
  %T — only flat string/scalar maps are accepted`.
- `--dry-run` prints `Would import N entries into vault/project/env:`
  + key + byte length (never values). With `--replace`, also shows
  deletions.

Three explicit modes (mutually exclusive):

| Mode | Effect |
|---|---|
| **merge** (default) | Add new keys; overwrite matching ones; leave other keys in scope untouched. |
| `--skip-existing` | Add-only. Existing keys count as "skipped"; nothing overwritten. |
| `--replace` | **Destructive.** Wipe every existing key in the scope first, then import. Prompts for confirmation; pass `--yes` to skip. Required in non-TTY/agent mode. |

Examples:

```sh
byn import .env                              # merge — today's default
byn import --skip-existing config.env        # add only
byn import --replace --yes config.env        # wipe scope, then import
byn import --replace --dry-run config.env    # preview deletions + adds
```

Dotenv parser understands:
- `export PREFIX` strips the prefix
- Double-quoted values with `\n`/`\t`/`\\`/`\"` escapes
- Single-quoted values (literal, no interpolation)
- Unquoted values with trailing ` # comment` stripped
- `#` line comments
- Empty lines

YAML/JSON values are coerced: bool → `"true"`/`"false"`, numbers →
printed, null → empty string.

### `byn export [--format env|yaml|json] [--output PATH] [--password-stdin]`

Dump active scope as a flat key→value document.

- Default format: `env` (dotenv quoting).
- `--output PATH` writes mode 0600.
- `-` (or default) writes to stdout.
- Keys sorted alphabetically.
- Dotenv quoting: values containing `\s\n#="` get wrapped in
  `"..."` with `\n`/`\\`/`\"` escapes.
- `--password-stdin`: read the master password once from stdin and
  reuse it for every get (non-interactive path). Without the flag, the
  CLI prompts once interactively on the first `auth_required` and reuses
  the same password for the rest. With an active session, no prompts fire.
  Each sessionless get re-verifies via Argon2id — run `byn unlock` first
  for large exports.

**Caveat:** this materializes plaintext. Treat the output like a
`.env` file — never commit, never share. Same warning as `byn get`.

---

## Execution

### `byn exec -- COMMAND [ARGS]` (direct form)
### `byn exec NAME [ARGS]` (alias form)

Replace the CLI process with COMMAND (direct form) or with the command
expanded from the `.byn` `[aliases]` table (alias form), injecting vault
env-vars into its environment.

**Two grammars:**

- `byn exec -- COMMAND [ARGS]` — direct form. The `--` separator is
  **required** to disambiguate byn's own flags from the child's flags.
- `byn exec NAME [ARGS]` — alias form. `NAME` must be defined in the
  trusted `.byn`'s `[aliases]` table. The alias value is the base
  command; extra `ARGS` are appended before exec. A `.byn` must be in
  scope.

**Strict passthrough for alias form:** everything after `NAME` (including
`--flag`, `--help`, `--vault`, etc.) is passed opaquely to the child — byn
does NOT scan those tokens for its own flags.

Examples:

```sh
byn exec -- /usr/bin/env                      # direct: exec /usr/bin/env
byn exec deploy                               # alias: expands from .byn [aliases]
byn exec deploy --env prod                    # alias + extra args (passthrough)
byn --vault myv exec deploy                   # globals before subcommand still work
```

- Implemented via `syscall.Exec`: the child gets the same PID as the
  CLI that invoked it.
- **Server-side authorization (one round-trip):** the CLI sends a
  single `OpExecFetch` request. The daemon reads, trust-verifies, and
  parses the `.byn` itself, then returns **only** the entries listed in
  `[exec] env`. A compromised client cannot widen the allowlist — the
  daemon owns the entire path from trust check to env assembly.
- **Alias not found:** if the alias name is not in the trust record, the
  daemon returns an error listing up to 8 available alias names.
- **Alias shadowing:** `byn exec test` (no `--`) runs the alias if one is
  defined; `byn exec -- test` always runs the literal binary `test`.
- Denial messages (untrusted / changed / tampered / stale) come from
  the daemon with a `byn trust` recovery hint.
- **`[exec] actions` — command allowlist (three states):**
  Controls which commands may run without per-call authorization. For the
  alias form, matching is performed against the *resolved* argv (alias
  base + extra args) — the same as the direct form.
  - *Absent or empty:* every exec requires authorization (password/token).
  - `actions = ["/usr/bin/env", "/usr/local/bin/make"]`: listed commands
    run freely (authorization is the act of pinning); unlisted commands
    require authorization on each run. Entries may use typed placeholders
    (`{{uuid}}`, `{{args}}`, etc.) — see
    [byn-file-format.md](byn-file-format.md#actions-pattern-placeholders).
  - `actions = ["*"]` or `actions = "*"`: all commands run freely
    (wildcard — shown as a warning at `byn trust` time; use with care).
  Actions policy is read from the MAC-bound trust record, not the live
  file — editing the `.byn` post-trust cannot change the effective policy
  without re-trusting (which requires the master password). Actions
  enforcement is **independent** of session state.
- Every exec attempt — allowed or denied, including locked-vault
  failures — is audited with the full command line. Alias execs are
  audited as `alias <name> → <resolved command>`.
- **Vault locked:** always a hard failure ("vault is locked"). Unlike
  `delete`, exec cannot proceed with a password; `byn unlock` first.
- Stage 1: `exec.LookPath` to vet the binary
- Stage 2: parent's environ + injected vars (last value wins, so
  vault values shadow shell exports)
- Stage 3: `syscall.Exec`

**Limitations:**
- Values briefly live as Go strings in heap between OpExecFetch and exec
- Shell builtins (`cd`, `source`) can't be exec'd — wrap via
  `bash -c '...'`

### `byn edit` / `byn view` / `byn` (no args)

Open the modal vi-style TUI. Currently env-vars in the default scope
only — the left-rail multi-scope redesign is Slice 7.

---

## Diagnostics

### `byn doctor [--json]`

Run a battery of self-checks against every vault on disk:

| Check | What it verifies |
|---|---|
| `daemon` | Daemon responding to status |
| `vaults.list` | Vault directories enumerable; warn if none |
| `vault[X].open` | Schema version current + meta.json fingerprint matches |
| `vault[X].audit` | HMAC chain walk reports no broken links |

Severity is `ok` / `warn` / `fail`. Exit code is non-zero if any
`fail`. `--json` emits `[]DoctorCheck{Name, Severity, Detail}`.

### `byn audit tail [--lines N] [--json]`

Print the most recent N events from the active vault's audit log.
Default N = 50; `--lines 0` returns everything.

Allowed while locked — audit metadata is not secret. See
[security.md](security.md) for what's captured per event.

Human format: timestamp + op + scope + entry name + outcome:

```
2026-06-02 12:34:56Z  put        default/billing/staging  DB_URL    ok
2026-06-02 12:35:01Z  vault.lock default                  -         ok
```

With `--json`, a snapshot is a single **JSON array** of event objects (so
`byn audit tail --json | jq` works, like every other `--json` command). Add
`-f` to follow: that streams **NDJSON** (one object per line) so new events
can be appended live.

### `byn audit verify [--json]`

Re-walk the active vault's audit log; recompute the HMAC chain;
report the first bad index.

- Exit 0 + `audit chain intact — N events verified` if clean.
- Exit 3 + `FAIL: audit chain BROKEN at event #M (of N)` otherwise,
  with a treat-as-compromised hint.

---

## Trust (`.byn` TOFU)

### `byn trust [PATH]`

Approve a `.byn` file (default: `./.byn`). **Always prompts for the
master password** — granting trust is a proof-of-presence action, so it
requires the password even when the vault is unlocked. The daemon (which
owns `~/.byn/trusted_byn.json`) verifies the password against the vault
the `.byn` targets, then records the canonical path + SHA-256 + mtime
snapshot + vault-key MAC (v2 trust record).

If the `.byn` already exists in the store with a *different* hash (it
changed since you trusted it), `byn trust` warns loudly before
re-approving. Discovery itself never auto-trusts — a new or changed
`.byn` is refused until you run this command.

**At grant time**, the daemon also displays the effective `[auth]` policy
and `[exec] actions` from the file so you can confirm what you're
approving.

**64KB cap:** `.byn` files larger than 65536 bytes are refused at both
grant time and exec.

**Malformed `.byn`:** invalid TOML is rejected at grant time with a parse
error; the file is not recorded in the trust store.

- `--password-stdin` — read the password from stdin (for scripts), e.g.
  `printf '%s' "$PW" | byn trust --password-stdin ./.byn`.
- `--paths "a,b,c"` — comma-separated list of paths to trust at once.
- `--recursive DIR` — trust every `.byn` under DIR.

### `[auth]` table — per-scope per-action authorization policy

A `.byn` may carry an `[auth]` table that overrides the session gate for
operations in this file's scope:

| Key | Value | Effect |
|---|---|---|
| `get` / `update` / `delete` / `exec` | `"always"` | Fresh auth required unconditionally, even with an active session |
| `get` / `update` / `delete` / `exec` | `"none"` | Gate skipped entirely for the matched scope |
| (absent) | — | Session gate decides |

`update` covers overwrite-put and rename. `delete` covers delete, env
clear/delete, project delete, vault delete.

**Ad-hoc exec exclusion:** the `[auth] exec` key applies only to
trusted-`.byn` exec (Path ≠ ""). Ad-hoc exec (no `.byn`) is always
subject to the session gate.

**Structural-ops note:** vault-level ops (`vault.delete`, `vault.rename`)
pass an empty Scope (no project/env) to the policy gate. A record scoped
broadly to an entire vault matches and therefore gates those ops.

Policy is MAC-bound at grant time — editing the `.byn` post-trust cannot
change the effective policy without re-trusting.

### `byn trust diff PATH`

Compare the current `.byn` content against the snapshot recorded at
trust time, and print a unified diff.

- **Exit 0** — content and mtime are both identical (still trusted).
- **Exit 1** — content differs OR mtime-only changed (re-trust required
  either way). For mtime-only: prints "content identical; modification
  time changed".
- **Exit 2** — daemon not running.
- **Exit 3** — daemon error (path not trusted, file exceeds 64KB, etc.).

### `byn untrust [PATH]`

Revoke trust (default: `./.byn`). Idempotent. Routed through the daemon.

### `byn trust list [--json]`

Print every trusted path and the first 12 hex chars of its hash.
With `--json`, emit a JSON array of trust records.

See [`.byn` file format](byn-file-format.md) for the discovery
algorithm.

---

## Misc

### `byn version` (also: `--version`, `-v`)

Print the binary version.

### `byn help [command]` (also: `--help`, `-h`)

Print the top-level usage or per-command help. Routed through
`$PAGER` when stdout is a TTY.

---

## Config file (`~/.byn/config`)

Optional TOML file (no extension). A missing file uses built-in
defaults. Unknown keys are rejected with an error. Changes to
`[security]` and `[daemon]` hot-apply via `byn daemon reload` without
restart; `[ui]` changes also hot-apply.

| Key | Default | Effect |
|---|---|---|
| `[ui] enabled` | `true` | Enable/disable the web portal |
| `[ui] port` | `2967` | Port for the local admin portal |
| `[daemon] idle_timeout` | `"15m"` | Auto-relock after inactivity; `"0s"` to disable |
| `[security] session_ttl` | `"12h"` | Absolute session lifetime; `"0s"` = no TTL limit |
| `[security] session_idle` | `"0s"` | Sliding idle window; `"0s"` = inherit `idle_timeout` |

Example:

```toml
[daemon]
idle_timeout = "30m"

[security]
session_ttl  = "12h"
session_idle = "0s"

[ui]
port = 2967
enabled = true
```

---

## Environment variables

### Scope

| Var | Effect |
|---|---|
| `BYN_VAULT` | Default vault (CLI flag wins) |
| `BYN_PROJECT` | Default project |
| `BYN_ENV` | Default env |

### Discovery / trust

| Var | Effect |
|---|---|
| `BYN_NO_DISCOVERY=1` | Skip the `.byn` walk entirely |

### Daemon

| Var | Effect |
|---|---|
| `BYN_DIR` | Override `~/.byn` (used heavily in tests and `make test-integration`) |

### Pager and hint env vars

| Var | Effect |
|---|---|
| `PAGER` | Pager binary for help (default: `less -RFX`, fallback: `more`) |
| `PAGER=cat` | Disable paging |
| `BYN_NO_PAGER=1` | Disable paging (alternative to `PAGER=cat`) |
| `BYN_HINTS=0` | Suppress mutating-op echoes (also off on non-TTY stderr) |
| `NO_COLOR` | Disable ANSI color (community convention; honored) |
| `FORCE_COLOR` | Force ANSI color even when stderr isn't a TTY |

---

## Related

- [Architecture](architecture.md) — IPC ops list + dispatch flow.
- [`.byn` + discovery](byn-file-format.md) — TOFU details.
- [File layout](file-layout.md) — where each env var's effects land
  on disk.
- [Glossary](glossary.md) — `scope`, `AAD`, `TOFU`, `fingerprint`,
  `audit chain`.
- [Troubleshooting](troubleshooting.md) — common errors with each command.
