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
| `75` | A decision is queued and nobody has answered it yet (`EX_TEMPFAIL`). Not a refusal — retry after `byn approve` |

Use these for scripting:

```sh
byn get DB_URL || case $? in
    2) echo "start the daemon" ;;
    3) echo "unlock the vault" ;;
esac

# An agent that must not block can carry on and retry later:
byn exec -- ./build.sh
case $? in
    0)  ;;                                  # ran
    75) echo "waiting on a human; will retry" ;;
    *)  echo "actually failed" ;;
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

These commands provision [three-UID privilege
separation](security.md#privilege-separation-the-three-uid-model-opt-in-nu-56)
(daemon as `_byn`, exec children as `_byn-exec`, you as the owner). Both require
root.

Privilege separation is engaged by **provisioning**, not by a config flag: once
`byn setup` has run — which the install script and the system packages now do
for you — the daemon runs as `_byn` and trusted-pinned `byn exec` children run
as `_byn-exec`.

`[security] privsep` is the switch. `byn exec` asks the daemon whether privsep
is on and the daemon answers from that key, so a machine can be fully
provisioned — service users, spawn helper, ACLs — and still run every exec child
at the owner's UID because the flag is unset. `byn setup` sets it, and
`byn doctor` reports the state actually in force.

See the [migration guide](migration.md).

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
- Setup **provisions and enables** privsep: it writes
  `[security] privsep = true` and restarts the daemon, leaving an explicit
  setting alone. Before v0.5.5 it provisioned only, so a fully set-up machine
  could still run every exec child at the owner's UID. With privsep
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

- On a terminal byn **prompts for the value and hides what you type**, the way a
  password prompt does. Otherwise the value is read from stdin. Either way it
  never comes from the command line: `byn put NAME VALUE` is rejected, because
  values in argv leak to `ps` and shell history.
- The prompt takes one line. A multi-line secret (a PEM key, a JSON blob) still
  comes from a file or a pipe — reading to EOF at a prompt would leave you typing
  a certificate with no way to say you had finished but Ctrl-D.
- An empty entry at the prompt is refused rather than stored: it is almost always
  a stray Enter. To store an empty value deliberately, pipe one:
  `printf "" | byn put NAME`.
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
- A locked vault accepts `delete`, `get` and `put` with the master password.
  The key is unwrapped for that one operation and zeroed after, so the vault
  stays locked: a password authorizes a value, `byn unlock` authorizes a
  session.

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

### `byn edit` / `byn view`

Opens the modal editor, which lives in a second binary (`byn-tui`) that byn
launches. It is not a separate install: every packaged install bundles it, and
byn keeps it in its own `libexec` directory rather than on your `PATH`, because
it is byn's helper and not a command anybody runs.

byn looks for it in `/usr/local/libexec/byn-tui` first, then beside the running
`byn` — so a source build finds the one it was built with, and an installed byn
is not shadowed by a stray copy earlier on someone's `PATH`.

The one path that cannot bundle it is `go install`, which installs a single main
package per invocation. There, the first `byn edit` offers to fetch the editor
pinned to your byn's own version, and asks before doing so — fetching and
building code is a choice, not something a secrets manager should do quietly.

It is separate for a measured reason. `bubbletea`'s package init asks the
terminal for its background colour and waits up to five seconds for a reply —
unconditionally, in any program that links it. That made every byn command,
including `byn version`, take 5.1 seconds on a controlling terminal that does
not answer: a pty with no emulator behind it, which is what `script`, serial
consoles, CI runners that allocate a tty and some agent harnesses provide. Go
initialises imported packages before the importing one, so byn cannot pre-empt a
dependency's init from its own code; not linking it is the only way not to run
it.

If `byn-tui` is missing, `byn edit` says so and names the fix rather than failing
with a bare exec error.
 / `byn` (no args)

Open the modal vi-style TUI, with a left rail to navigate the
vault → project → env tree.

---

## Diagnostics

### `byn doctor [--json]`

Run a battery of self-checks against every vault on disk:

| Check | What it verifies |
|---|---|
| `daemon` | Daemon responding to status |
| `daemon.sees_caller` | The daemon can resolve the process on the other end; warn if not |
| `daemon.fda` | macOS with privsep only: Full Disk Access. Fails when macOS (TCC) is refusing the daemon a `.byn` you have trusted — see [troubleshooting](troubleshooting.md) |
| `vaults.list` | Vault directories enumerable; warn if none |
| `vault[X].open` | Schema version current + meta.json fingerprint matches |
| `vault[X].audit` | HMAC chain walk reports no broken links |

Severity is `ok` / `warn` / `fail`. Exit code is non-zero if any
`fail`. `--json` emits `[]DoctorCheck{Name, Severity, Detail}`.

### `byn audit tail [-n N] [-f] [--since N] [--before N] [--byn P] [--caller C] [--scope S] [--json]`

Print the most recent N events from the active vault's audit log
(like `tail(1)`). Default N = 10 (`--lines` is an alias for `-n`);
`-f` follows the log. `byn audit view` is the same reader with a larger
default window (`--lines 0` prints the whole log).

Allowed while locked — audit metadata is not secret. Every row is prefixed with
its **`#N` chain index** (the same number `verify`/`reseal` report). The
[**Audit log** guide](audit.md) is the full picture — what's captured and why,
the chain integrity model, reseal, filters, and pagination; this is the flag
reference.

**Filter** (server-side, case-insensitive substring, across the *whole* log so a
match is found even when it predates the recent window): `--byn P` (authorizing
`.byn` path), `--caller C` (caller process/uid), `--scope S` (`project[/env]`).

**Paginate** by the stable `#N` index, never a positional offset (a growing log
would shift an offset): `--since N` streams every event with `#N` above N,
oldest-first — a program tracks the highest `#N` it has processed and re-queries
to consume new events without skips or repeats; `--before N` fetches the page
just below `#N` (pass the smallest `#N` you got to page further back).

Human format: `#N` + timestamp + op + scope + entry name + outcome + caller:

```
#4120  2026-06-02 12:34:56Z  put        default/billing/staging  DB_URL    ok
#4121  2026-06-02 12:35:01Z  vault.lock default                  -         ok
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

A break is often benign (a daemon crash mid-write); see `reseal` below and the
[Audit log guide](audit.md#chain-breaks-and-reseal).

### `byn audit reseal [--reason R] [--yes] [--json]`

Acknowledge a chain break by appending a **signed bridge marker** — the original
hashes are never rewritten, so the gap stays visible and attributable (it records
the break index, observed vs expected heads, a reason, and who/when). Requires
the vault **unlocked** (a deliberate owner action). Interactive by default (shows
the break, prompts for a reason, confirms); `--reason R --yes` runs
non-interactively. Afterwards `verify` and `doctor` read the chain as intact
(with the acknowledged reseal). A marker forged without the chain seed cannot
clear a break. See the [Audit log guide](audit.md#chain-breaks-and-reseal).

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

---

## Approvals

When a `.byn` asks for more authority than it was granted, `byn exec` does not
stop at a password prompt no agent can answer. It queues the decision, prints
its id, and exits `75`. The work resumes on the next attempt once someone has
answered.

### `byn approve [--json]`

Lists what is waiting: the file, what would be granted **in plain words**, how
long it has waited, and how many times it has been re-asked. Entries marked `!`
are the consequential ones — a wildcard, a scope move, write access to a
credential directory, or an `[auth]` gate being relaxed.

```
  45e16b0d2abe  /home/u/proj/.byn
      injects PSQL_CREDENTIALS
      approving grants the .byn what it already asks for — it does not edit
      the file, and nothing runs until it is attempted again
      why: seeding the staging database (said by whoever asked — byn cannot verify it)
      who: claude (pid 4021), no terminal in /home/u/proj
      asked 3m12s ago, retried 2×, needed within 1m48s
```

**Who** is byn's own account, read from the kernel: the agent behind the call,
where it was working, whether anyone was at a terminal. **Why** is the asker's,
passed with `byn exec --reason`, and is shown as the claim it is — byn cannot
check a stated purpose and never lets one affect a decision. A request without
one is allowed and says so.

A caller that is waiting (`byn exec --wait-approval`) also says how long, so the
list can separate "needed within 1m48s" from "no longer waiting". Answering
after that still grants; the entry is marked as having arrived late.

### `byn approve [--password-stdin] ID...`

Grants the request. Takes the master password, exactly as `byn trust` does,
because approving grants authority. It re-grants the `.byn`, so the caller's
next attempt succeeds — recording a decision without applying it would leave
the caller stuck asking forever.

### `byn approve --deny ID...`

Refuses. Needs no password, because refusing grants nothing. This asymmetry is
deliberate: if saying no costs more than saying yes, people learn to say yes.

A request denied repeatedly goes on hold and stops being askable for a while,
so a caller cannot re-ask until someone gives in.

`--deny` does **not** take back a grant already given. Denying an
already-approved request is refused outright and points at `--revoke`: it used
to return quietly and reprint the grant line, so an owner who typed it believed
a command had stopped being runnable when it had not.

### `byn approve --once ID...`

Makes the grant single-use: spent the first time byn authorizes a run with it,
rather than staying live for the rest of the window. One-shot scripts are what
approvals are most often used for, and the alternative is remembering to revoke
afterwards — easy to skip, and invisible when skipped.

Spent on **authorization**, not on the command's exit status. byn hands over the
values and the command's fate is its own, so tying the grant to an exit code
would hold it open across something byn does not watch. `byn exec --dry-run`
goes through a different path and consumes nothing.

### `byn approve --always ID...`

Grants normally even though the asker asked for a single use — the opposite
override to `--once`.

The two exist because a request is a *default*, not a decision. An agent that
knows it needs a command once can say so with `byn exec --once`, and a plain
`byn approve <id>` then honours it: asking narrowly has to be the easy path or
nobody does it. The owner still decides, and can go either way. If both flags
are passed the narrower wins, because an approver who said both did not mean to
widen.

The rule lives in the daemon rather than in any one client, so `byn approve`, a
tap in the portal and a keystroke in the TUI cannot drift into meaning different
things.

An unspent single-use grant lapses after 30 minutes rather than the usual six
hours, unless `--for` names a window. The two answer different questions: an
ordinary grant covers a working session, a one-shot covers a run that is usually
already waiting on it, and six hours of authority for a run that happened in the
first minute is six hours nobody asked for.

### `byn approve --revoke ID...`

Takes back a grant before it lapses. Approving is the moment authority moves,
and there has to be a moment it moves back — a command approved for a one-shot
job otherwise stays runnable for the rest of the window, and "it expires in six
hours" is not an answer to "this must stop being runnable now".

Needs no password, for the same reason `--deny` does not: it can only ever
remove capability, and a revoke you have to go and find a credential for is one
that happens later than it should. Recorded as `approval.revoke`. The grant
itself is zeroed rather than the record relabelled, so the next attempt raises a
fresh request.

### `byn request watch TICKET [--timeout SECONDS] [--human]`

The asker's side of an approval: block until your own request is answered, then
print the outcome as JSON.

```json
{"approval_id":"8ffa7d4f6f54","status":"denied","reason":"deny test",
 "decided_via":"portal","once":false,"granted_until":0}
```

`status` is `approved`, `denied`, `expired`, `cancelled` or `revoked` — or
`pending` with `"timed_out":true` when you stopped waiting first. Exit codes:
`0` approved, `3` denied/expired/cancelled, `75` still pending. **Branch on the
code**: a script that treats "denied" and "not yet" alike will retry a refusal
for ever, which is the loop the approval queue exists to prevent.

The decider's reason reaches the asker here and nowhere else. A refusal without
one leaves an agent guessing between "fix it and ask again" and "stop".

Decisions are published in-process, so the wait ends the moment somebody answers
rather than on a poll interval. Before this, the only way to learn an outcome was
to re-run the whole command every couple of seconds — which can observe exactly
one result, success, because a poller cannot tell "denied" from "not yet".

**The ticket.** It arrives once, in the `watch_ticket` field of the
`approval_pending` response that raised the request. Keep it: no command returns
one for an existing request, and a retry that re-attaches to a request already
waiting is handed nothing. Both halves are deliberate — a way to re-request a
ticket would be a way for anything else on the machine to request yours, and then
answer for you or withdraw your request. byn stores only a SHA-256 of it.

Possession of the ticket is the entire authorization, which is what lets a
privsep exec child — a different uid, no session, no password — learn the outcome
of its own request without any wider access to the queue.

Prefer passing it on stdin over argv where you can: an argument is visible in
`ps` to every process on the machine while the command runs.

### `byn request cancel TICKET`

Withdraw a request you no longer need, so nobody spends attention answering it.

Cancelling is **not** denying. A denial is the owner's judgment and counts toward
the cooldown that stops a fingerprint being re-asked; a cancellation is the asker
changing its mind and leaves no mark on the owner's answer history. A cancel that
races a decision reports the decision — the answer that exists is the one that
counts.

### `byn approve [--for DURATION] [--anyone] ID...`

`--for` sets how long an approved command runs free — default 6h, at most 24h.
A command wanted once for the next ten minutes and one wanted all afternoon are
different grants, and giving both the default makes the first a standing
authority nobody asked for.

`--anyone` widens the grant past the caller that asked for it. By default a
grant belongs to whoever asked, by the same identity that governs values an
agent created: you were asked whether one agent could run one command, and
letting anything else in that directory use the answer would be a wider grant
than the question. Widen it deliberately for a shared build command, or one that
has to outlive the session that asked.

### `byn approve --all [--password-stdin]`

Answers every pending request; one password covers the batch, so clearing a
backlog does not become its own chore.

### `byn runs [-n N] [--json]`

What past executions were given: when, which `.byn` allowed it, the agent behind
it, and which values it received. The question only ever gets asked afterwards —
what did that process actually hold.

Runs store **references**, never copies. A second copy of every value would grow
without bound and would turn the trail into an archive of every secret the
project has ever had, so a credential rotated after a leak would stay
recoverable. Snapshots are stored as differences from the previous one, so a dev
server restarted fifty times costs fifty run records and one snapshot.

Listing needs no credential — byn already lists variable names without one.

### `byn runs show ID [--reveal] [--password-stdin]`

Names the values a run received, marking the ones byn took in unattended.
`--reveal` shows the values themselves: gated exactly as reading a secret is,
recorded as a read, and it warns before it prints.

### `byn runs diff ID`

Answers the question people actually bring here — has any of this been rotated
since? — and prints nothing. Per name: `unchanged`, `changed since`, or `deleted
since`. No credential, and it works while the vault is locked, because the
answer comes from comparing a digest of the stored ciphertext, which needs no
key.

It exists because the safe command has to be the reachable one. While the only
way to check whether a value had changed was the command that prints every
value, checking meant putting live secrets on a terminal.

The three wordings are three different claims. "changed since" means the entry
is still there holding something else. "deleted since" means the entry that run
used is gone — a name deleted and re-created is a new entry, not a new version
of the old one. "could not be read" is about byn, and is not evidence that
anything changed.

### `byn exec --reason "TEXT" -- COMMAND`

Says what the command is for. It travels with a request byn has to queue and is
shown to whoever decides it, labelled as the asker's claim. Also spelled
`--why`, and `BYN_WHY` in the environment does the same for a harness that
builds byn's argv itself.

Passing it on a retry fills in a blank reason on the same pending request; it
never overwrites one already given.

### `byn exec --wait-approval[=DURATION] -- COMMAND`

Blocks until the decision lands instead of returning `75` immediately. Defaults
to two minutes — what is being waited on is a person noticing a request. It
polls rather than holding a connection, so a daemon restart mid-wait costs one
interval rather than the whole wait.

The default remains non-blocking: a caller that must not be interrupted should
not be made to wait by default.

---

## Running processes and their leftovers

### `byn ps`

Lists the `byn exec` processes running now, and the command each one is
executing. It answers what `ps` cannot once privilege separation is on: the
children run as `_byn-exec`, so they are somebody else's processes as far as
your shell is concerned.

One row per job. Under privilege separation that row is the wrapper — the child
beneath it is the same job seen from the inside, and signalling the wrapper takes
the group with it. An exec-user process whose wrapper has died **is** listed: an
orphan still holding injected values is exactly what you came here to find.

### `byn kill [--all] [PID...]`

Sends `SIGTERM` to one or every running `byn exec` process. A privsep child runs
as a different user, so `kill(1)` from your own shell cannot signal it; this
asks the daemon to do it.

A PID that is not a byn exec process is refused rather than signalled, so a typo
cannot stop something unrelated. The signal goes to the whole process group
through the privileged helper, which is what lets `--all` end a job whose child
you could not have signalled yourself.

### `byn repair [DIR]`

Gives you back access to files a privsep exec child created. A build that runs
as `_byn-exec` leaves artifacts owned by `_byn-exec`, and a tool that rewrites
its own state file and chmods it `0600` discards whatever ACL it inherited —
after which one of you can read it and the other cannot.

`byn exec` reconciles the declared `[exec] writable` directories on its way in,
which covers a file locked between runs. It does not cover a service already
up: a token refreshed while a dev server has run for days leaves that child
unable to read it until something restarts. `repair` fixes it in place, without
one, and covers the whole project plus the declared writable directories.

It runs as you, which bounds what it can fix: changing a file's ACL requires
being its owner. Files *you* locked, it repairs; a file the exec child locked
that you can no longer read is the mirror case, and is what it is for.

Defaults to the current directory. Reports what it repaired, and is silent when
there was nothing to do.
