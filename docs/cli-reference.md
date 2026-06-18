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

Authorize value access (`get` / `put` / `update` / `delete`) for **this
terminal's session only** — **not** a global unlock. It mints a session token
bound to your TTY + UID so subsequent commands in *this* terminal don't
re-prompt; other terminals, scripts, the portal, and background agents each
authenticate separately (one session never grants another). It does **not**
affect `byn exec` — exec is governed by the trusted `.byn` + per-action auth,
independent of unlock/session state. (Internally it also unwraps the vault key
into the daemon's memory, but value access still requires a valid session.)

- Subject to the failed-unlock backoff (`auth-state.json`).
- On success, starts the per-vault idle timer. End this terminal's session with
  `byn lock --session`.

### `byn lock`

Zero the in-memory vault key for `--vault` (or `--all` to lock every
unlocked vault) — this affects **all** sessions. `--session` instead ends
**only this terminal's** session (drops its token) and leaves the vault
unlocked for other callers. Neither affects `byn exec` authorization.

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

## System setup (privilege separation)

These commands provision and migrate the **opt-in** [three-UID privilege
separation](security.md#privilege-separation-the-three-uid-model-opt-in-nu-56)
(daemon as `_byn`, exec children as `_byn-exec`, you as the owner). Both require
root. Privsep is off by default; enable it with `[security] privsep = true` in
the config and restart the daemon. See the [migration guide](migration.md).

### `byn setup [--uninstall [--purge]]`

Provision the full privsep install in one idempotent, root-required step. With no
flags, `byn setup`:

1. Creates the `_byn` and `_byn-exec` service accounts and installs the prebuilt
   privileged spawn helper (`byn-exec-helper`) + its root-owned UID/GID config.
2. Installs and loads the system service that runs the daemon as `_byn` (a
   systemd system unit on Linux, a LaunchDaemon on macOS) — **not** the human
   owner.
3. Relocates any legacy `~/.byn` vault into the fixed system data path, chowned
   to `_byn` (trust + passkeys preserved — same machine); skipped on a fresh
   install.
4. Records the **owner UID** (the human who ran sudo, read from `SUDO_UID`) as
   the single UID the daemon allowlists on its peercred-gated socket.
5. Verifies the post-conditions.

- Must run via **sudo** (`sudo byn setup`) so `SUDO_UID` is set. Running as real
  root (not via sudo) fails rather than recording root as the owner.
- **Idempotent** — re-running on a provisioned host reinstalls the helper +
  service, re-records the owner, and exits 0 (safe on every install and upgrade).
- The prebuilt `byn-exec-helper` must sit beside the `byn` binary.
- Linux uses `systemd-sysusers(8)`; macOS uses `sysadminctl(8)`. Other platforms
  are unsupported.
- Setup **provisions** privsep; it does not **enable** it. Engage it with
  `[security] privsep = true` in the config + a daemon restart. With privsep
  enabled but **not** provisioned, the daemon warns and trusted-`.byn` exec
  **fails closed** — it never silently runs as the owner UID.
- `--uninstall` reverses a previous setup (uninstall the service, remove the
  helper + config + owner record). It **leaves the vault intact** by default. Add
  `--purge` to also delete the system data dir and every secret in it — a
  destructive, irreversible action gated behind a typed `yes` confirmation. The
  vault is **never** removed without `--purge`.

### `byn migrate [--from PATH] [--force]`

Adopt a byn vault tree into the fixed system data path with the correct structure
and ownership (`_byn`, mode 0700). The source is verified **without its
password** — every `vault.db` must open as a well-formed, correctly-versioned
vault whose `wrapped.key`/`meta.json` fingerprint matches and whose audit chain
is intact — before anything is adopted; a malformed, truncated, or tampered
source is rejected and the destination is left untouched. The adopt is atomic and
re-runnable; it never half-migrates.

- Must run as root (it writes the `_byn`-owned system path and chowns the tree).
  The `_byn` account must already exist; if not, run `byn setup` first — migrate
  adopts with the correct ownership, it does not create users.
- **No `--from` (relocate / upgrade path):** moves the legacy `~/.byn` into the
  system path. Same machine, so the trust store and passkey enrollments are
  **kept**, and the old `~/.byn` is removed only **after** the destination is
  fully adopted.
- **`--from PATH` (import):** copies an external vault in (a backup, a mounted
  disk, a synced dir) and **never deletes the source**. An import brings vault
  **data only** — the trust store and passkey enrollments are **dropped** (trust
  is never silently carried across a machine boundary), so afterwards you **must**
  re-trust your `.byn` files with `byn trust` and re-enroll passkeys on this
  machine. A non-empty destination is refused unless `--force` is given.

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
byn exec --no-privsep -- node server.js       # run as YOU + password (debugger can attach)
byn exec --inspect -- node server.js          # privsep + inspector on a free port (attach)
byn exec --inspect=0 -- pnpm dev              # tsx watch / multi-process: each picks a free port
```

#### Execution modes — privsep (default), `--no-privsep`, `--inspect`

How the child runs — and whether it needs a password — depends on the mode:

| Mode | Child runs as | Env hidden from same-UID snooping? | Auth for a trusted `.byn` | Use for |
|------|---------------|------------------------------|---------------------------|---------|
| `byn exec` (default) | `_byn-exec` (privilege-separated), born in your shell's tree | **Yes** | **None** — credential-free, even locked | agents, CI, unattended/autonomous runs |
| `byn exec --no-privsep` | **you** (in-process via `execve`) | No (same UID) | **Master password every run** | interactive step-debugging (launch-mode debuggers) |
| `byn exec --inspect[=TARGET]` | `_byn-exec` (privilege-separated) | **Yes** | None (same as default) | debugging **while** keeping secrets hidden |

- **Default (privsep):** the daemon authorizes the exec and a setuid helper — spawned in *your shell's* process tree — drops the child to the `_byn-exec` service user. The injected secrets are hidden from same-UID snooping (a different UID can't read the child's env — `ps -E` on macOS, `/proc/<pid>/environ` on Linux), and a trusted `.byn` with a matching `[exec]` action runs with **no password** — the autonomous path for agents.
- **`--no-privsep`** exists for **human debugging**. byn `execve`'s into the child **as you**, so a launch-mode debugger (VS Code "launch") can attach — it shares your UID (a debugger **cannot attach across UIDs**, the same kernel rule that hides a privsep child's env, so it can't attach to the `_byn-exec` child directly). The cost: because the child runs as you, its injected env is visible to any same-UID process (`ps -E` on macOS, `/proc/<pid>/environ` on Linux). So this mode **requires the master password on every run**, and a **trusted `.byn` does *not* authorize it** (no autonomous / credential-free path here). That password gate is deliberate — it is the safeguard that stops a **rogue agent or attacker** from using `--no-privsep` to inject your secrets into an owner-UID process they could then read: a human at the keyboard can supply the password, an unattended agent cannot.
- **`--inspect[=PORT]` / `--inspect PORT` / `--inspect-brk`:** keeps privsep **and** enables the Node inspector, so you debug while secrets stay hidden. byn sets `NODE_OPTIONS` and your debugger **attaches** over loopback TCP (UID-agnostic). Port handling:
  - **no PORT** → byn picks the **next free port** (printed), so concurrent debug sessions don't collide.
  - **explicit PORT** (`--inspect 9230` or `--inspect=9230`, also `127.0.0.1:9230`) → used **only if free**; otherwise byn **fails with a clear message** instead of a buried `EADDRINUSE`.
  - **`--inspect=0`** → **each** node process self-allocates a free port — best for multi-process runners (`tsx watch`).
  - `--inspect-brk` breaks on the first line. Configure your editor as an **attach** target.

> Under privsep the `_byn-exec` child also needs filesystem access to your toolchain + tool-state dirs and a writable `TMPDIR` — see [Troubleshooting → Running `byn exec` under privsep](troubleshooting.md#running-byn-exec-under-privsep-toolchain-tmpdir-debugging).

- In **`--no-privsep`** mode the child is `execve`'d in place (same PID as the
  CLI); under **privsep** byn stays as the parent of the setuid helper + child.
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
- **`[exec] writable` — tool-state dirs for the privsep child (optional):**
  extra directories the `_byn-exec` child may read/write (e.g. a package
  manager's global store under a `0700` home dir), granted at `byn trust` time
  on top of a curated default set. Most stacks need nothing here. See
  [byn-file-format.md](byn-file-format.md).
- Every exec attempt — allowed or denied — is audited with the full
  command line. Alias execs are audited as `alias <name> → <resolved command>`.
- **Lock state and exec:** `byn unlock` / sessions do **not** authorize exec. A
  trusted `.byn` runs exec by its own `[exec] actions` + per-action auth: a
  **pinned** command runs autonomously (no unlock, no password — even while
  locked) via its sealed capability; an **unpinned** one prompts for the master
  password. Only **ad-hoc exec** (no `.byn`) requires the vault unlocked.
- Stage 1: `exec.LookPath` to vet the binary
- Stage 2: parent's environ + injected vars (last value wins, so
  vault values shadow shell exports)
- Stage 3: `syscall.Exec`

**Limitations:**
- Values briefly live as Go strings in heap between OpExecFetch and exec
- Shell builtins (`cd`, `source`) can't be exec'd — wrap via
  `bash -c '...'`

### `byn edit` / `byn view` / `byn` (no args)

Open the modal vi-style TUI, with a left rail to navigate the
vault → project → env tree.

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

### `byn audit tail [-n N] [-f] [--json]`

Print the most recent N events from the active vault's audit log
(like `tail(1)`). Default N = 10 (`--lines` is an alias for `-n`);
`-f` follows the log.

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
| `[security] privsep` | (absent → `false`) | Opt into privilege separation (run trusted-`.byn` exec children as `_byn-exec`). Requires `byn setup` first and a **daemon restart** to engage — see [migration guide](migration.md). When enabled but unprovisioned, trusted-`.byn` exec fails closed. |

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

> **No data-root override.** There is no environment variable to repoint byn's
> data root. It is a fixed system path once provisioned (`byn setup`), or
> `~/.byn` when unprovisioned — see [File layout](file-layout.md). (Tests use a
> `byntest`-build-tag-only `BYN_TEST_DIR` seam that is never compiled into a
> release binary.)

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
