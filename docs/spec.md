# byn — Specification

This file is the **authoritative contract** for byn behavior. Every
guarantee made here MUST hold in production code; tests verify it; any
change here is a breaking change that requires deliberate planning.

Read [docs/architecture.md](architecture.md) for the *how*. This
file is the *what must always be true*.

Conventions:

- **MUST / MUST NOT / SHALL** — load-bearing invariants. Tests cover them.
- **SHOULD** — strong default; deviation requires comment + rationale.
- **MAY** — discretionary.
- Where a guarantee is qualified (a known weakness, a deferred fix),
  the qualification is the contract — don't tighten it without
  shipping the deferred work first.

When making a change:

1. Read the relevant section(s) here first.
2. If the change tightens an invariant, add a test that proves it.
3. If the change loosens an invariant (anti-feature, regression risk),
   explicitly list which contract you're moving and why; update this
   doc as part of the same PR/commit.

---

## 1. Vault layer

### 1.1 Storage

1.1.1. Each vault is a directory `$BYN_DIR/vaults/<name>/` containing
exactly:
- `vault.db` — SQLite STRICT tables, WAL journal, FK enforced
- `wrapped.key` — Argon2id-wrapped vault key (binary header + nonce + ciphertext + tag)
- `meta.json` — `{schema_version, vault_id (UUIDv4), wrapped_key_fingerprint_sha256, created_at}`

1.1.2. File modes MUST be `0600`. Directory mode MUST be `0700`.

1.1.3. `meta.json.wrapped_key_fingerprint_sha256` MUST be the SHA-256
of the actual `wrapped.key` file bytes. Mismatch → vault refuses to
open.

1.1.4. Vault names MUST match `^[a-z][a-z0-9_-]{0,62}$`. Uppercase
input is rejected with an auto-suggest message; CLI MUST NOT silently
lowercase.

### 1.2 Encryption

1.2.1. Vault key is a fresh 32-byte random value from `crypto/rand` at
`init`. It MUST exist on disk only in wrapped form, and in memory only
while the vault is unlocked.

1.2.2. Wrapping primitive: `XChaCha20-Poly1305-Seal(key=Argon2id(password,salt), nonce=24B random, plaintext=vault_key, aad=full_header_bytes)`.

1.2.3. The `aad` for the wrap MUST include every byte of the header
(version + salt + Argon2 params + nonce). Any bit-flip in the header
MUST fail unwrap.

1.2.4. Argon2id parameters: time ∈ [1, 8], memory ∈ [64 MiB, 1 GiB],
threads ∈ [1, 8], key length = 32. Defaults: time=4, memory=256 MiB,
threads=4. Out-of-range parameters in a stored header MUST be rejected
at unwrap.

1.2.5. Row-value encryption: `XChaCha20-Poly1305-Seal(key=vault_key, nonce=24B random, plaintext=value, aad=vault_id ‖ 0x1F ‖ kind ‖ 0x1F ‖ name)`.

1.2.6. AAD components for row encryption MUST be: vault UUID, kind
(`env_var` or `file`), entry name (plaintext). Cutting and pasting a
row from another vault, or onto a different entry, MUST fail
decryption.

1.2.7. Nonces MUST be freshly random per encryption. Counter-based
nonces are forbidden.

### 1.3 Schema

1.3.1. Current schema version: **3**.

1.3.2. Schema includes the tables `meta`, `projects`, `envs`,
`entries`, `entry_versions`, `file_meta` (reserved).

1.3.3. `projects (name UNIQUE)` and `envs (project_id, name UNIQUE)`.

1.3.4. Default project and default env MUST be created at `init`.
Both are named `default`.

1.3.5. `entries.value` is a BLOB containing `nonce(24) ‖ ciphertext ‖ tag(16)`.

1.3.6. FOREIGN KEY constraints MUST be enforced (`PRAGMA foreign_keys=ON`).

1.3.7. `entries.deleted_at` is a soft-delete column. The current CLI
does hard deletes (cascade); soft deletes are reserved for a future
versioning surface.

1.3.8. `entry_versions` is append-only. Future `byn history` /
`revert` / `diff` will read it; today only writes flow in.

---

## 2. Scope hierarchy

### 2.1 Structure

2.1.1. Hierarchy: `vault → project → env → entry`. Exactly four levels.

2.1.2. Each level has a `default` member (vault `default`, project
`default`, env `default`). `default` is a regular member — same CRUD
rules apply with one exception: **deletion of any `default` is
refused** at the CLI layer AND the daemon layer.

### 2.2 Resolution

2.2.1. Resolution precedence (highest first):
1. CLI flag (`--vault`/`--project`/`--env`)
2. Env var (`BYN_VAULT`/`BYN_PROJECT`/`BYN_ENV`)
3. Discovered `.byn` scope (see §6)
4. Daemon default (`default`)

2.2.2. CLI flag MUST work before AND after the subcommand. Conflicting
duplicates (e.g. `--vault a --vault b`) MUST hard-error.

### 2.3 Inheritance

2.3.1. **Env inherits from default env, within the same project, when
an entry is missing.** Other levels (project, vault) do NOT inherit.

2.3.2. `OpList` for `(vault=V, project=P, env=E)` where E ≠ `default`
MUST return both:
- entries from `(V, P, E)` with `Source="scope"`
- entries from `(V, P, default)` that are NOT in `(V, P, E)`, with
  `Source="default"`

2.3.3. `OpGet` MUST honor the same fallback.

2.3.4. `OpPut`, `OpDelete`, `OpRename` operate on the **exact** scope
— no inheritance. Deleting an entry in `staging` does NOT touch
`default`.

---

## 3. IPC

### 3.1 Transport

3.1.1. Socket: `$BYN_DIR/daemon.sock`, mode `0600`.

3.1.2. Connection model: one envelope per connection. The CLI dials,
sends one request, reads one response, closes.

3.1.3. Peer credentials MUST be checked before reading any envelope.
Peer UID ≠ daemon owner UID → connection closed.

3.1.4. macOS uses `LOCAL_PEERCRED` (returns Xucred → UID); Linux uses
`SO_PEERCRED` (returns ucred → UID).

### 3.2 Frame

3.2.1. Wire frame: `length(uint32 BE) ‖ JSON envelope bytes`.

3.2.2. Max frame size: 1 MiB. Larger → reject.

3.2.3. `Envelope.V` MUST equal `ipc.ProtocolVersion` (currently 2).
Version negotiation surface is reserved (Min/Max in `StatusResp`) but
strict equality is enforced today.

3.2.4. JSON decode MUST use `DisallowUnknownFields` on both envelope
read and body decode. (Body decode is on the deferred-hardening list;
envelope already does this.)

### 3.3 Operations

3.3.1. Op string set (current): listed in `ipc.AllOps`. Adding ops is
backwards-compatible; removing or renaming is not.

3.3.2. Every op response MUST be either a typed response body OR a
typed `ErrMsg`. No silent successes; no untyped errors.

3.3.3. Stable error codes (must not change meaning): `unknown_op`,
`bad_request`, `unsupported_version`, `binary_too_old`, `locked`,
`wrong_password`, `rate_limited`, `already_init`, `not_init`,
`vault_not_found`, `vault_exists`, `bad_name`, `not_found`,
`already_exists`, `project_not_found`, `project_exists`,
`env_not_found`, `env_exists`, `internal`.

### 3.4 Existence-oracle defense

3.4.1. `vault.unlock` MUST return `wrong_password` for both:
- the password is genuinely wrong
- the vault does not exist on disk

This prevents an attacker from probing which vault names are present
by timing or response shape.

3.4.2. Successful unlock MAY reveal the vault exists; this is by
design (the user just told us it does).

---

## 4. Daemon

### 4.1 Lifecycle

4.1.1. Single instance per `$BYN_DIR` enforced via
`$BYN_DIR/daemon.pid`. Stale pidfile detected via signal-0 probe;
the daemon MUST reclaim it on restart, not refuse to start.

4.1.2. Multi-vault: the daemon maintains a map of unlocked vaults.
Each entry holds its own SQLite store, audit logger, idle timer, and
last-active timestamp.

4.1.3. Per-vault idle timer locks the vault key after inactivity. The
timeout is `[daemon] idle_timeout` in `$BYN_DIR/config` (Go duration
string; default `15m`); `"0s"` disables auto-relock. Reset on every
successful op. Implemented by the daemon's idle janitor (started at
`daemon start` when the timeout is positive); the janitor zeroes the
in-memory key via the same path as an explicit `vault.lock`.

4.1.4. `daemon stop` sends SIGTERM via pidfile. Shutdown drains
in-flight handlers up to 5 seconds, then exits.

### 4.2 Vault lookups

4.2.1. `openVault(name)` lazily opens the SQLite + audit logger for a
named vault. Locking state is independent — opening doesn't unlock.

4.2.2. Operations on a locked vault MUST return `CodeLocked`, EXCEPT
name/metadata reads that expose no value: `vault.list`, `audit.tail`,
`audit.verify`, `doctor`, project/env list, AND env-var **`list`**. Entry
`list` returns NAMES only and MUST work while locked — this is byn's core
promise: which env-vars exist is always visible, the values never are
(see §9.1). Value writes (`put`) and value reads (`get`) genuinely need the
vault key, so they gate hard on lock and CANNOT proceed while locked — a
write while locked MUST return `CodeLocked` (the UI surfaces "unlock the
vault to add values").

4.2.2.1. **Deletes while locked.** The deletes — env-var `delete`,
project/env `delete`, and `vault.delete` — touch only names/IDs and never
need the vault key. So a locked vault accepts them when the request carries
the correct master `password`: the daemon verifies it against the wrapped
key via `Store.VerifyPassword` (which unwraps then immediately zeroes the
key) and proceeds WITHOUT unlocking the vault. This lets a user remove a
secret/scope/vault they no longer want without exposing the rest of the
vault to a process sniffing daemon memory. A locked delete with no password
returns `CodeLocked` (clients then prompt); a wrong password returns
`CodeWrongPassword` and is rate-limited exactly like unlock (§4.3, shared
limiter). `rename` still requires a full unlock (`requireUnlocked`).
Enforced by `authorizeMutationWhileLocked` in dispatch. The CLI prompts for
the password on `CodeLocked` (or reads it via `--password-stdin`); the
portal's delete confirmation grows a password field when the vault is
locked.

4.2.2.2. **`vault.delete`** refuses the default vault, then (after authz)
emits a `vault.delete` audit event, evicts the in-memory store, and calls
`vault.Destroy`: overwrite `wrapped.key` with random bytes, then remove
`<root>/vaults/<name>/`. The audit log lives at `<root>/audit/<name>/`,
OUTSIDE the vault directory, so the forensic trail of a deleted vault
survives the wipe.

### 4.3 Rate limiter

4.3.1. Failed unlocks update `~/.byn/auth-state.json` with an
exponential backoff. State MUST persist across daemon restarts.

4.3.2. Backoff parameters: base 1s, multiplier 1.8, capped at 30 min.
After N failures the wait is `min(30min, base * multiplier^N)`.

4.3.3. The state file is not currently signed — tampering by an
attacker who can write `~/.byn` is undetected. Hardening designed,
deferred (see [docs/security.md](security.md)).

---

## 5. CLI

### 5.1 Exit codes

5.1.1. **MUST** be stable:
- `0` — success
- `1` — generic error (bad input, runtime failure)
- `2` — daemon unreachable (CLI also prints a recovery hint)
- `3` — daemon returned a typed error (locked, wrong password, not found, etc.)

5.1.2. Scripts SHOULD branch on these codes; the CLI MUST NOT use
other values without updating this contract.

### 5.2 Commands

5.2.1. Every shipped command listed in this section MUST remain
backwards-compatible: same name, same flags, same exit code semantics.

5.2.2. **Lifecycle:** `init`, `unlock`, `lock [--all]`, `passwd`, `daemon {start,stop,restart,reload,status}`, `status`. `lock --all` locks every unlocked vault (daemon `OpVaultLock` with `Name="*"`). `passwd` changes a vault's master password by **re-wrapping** the vault key — unwrap with the current password, wrap under the new one (fresh salt/nonce), rewrite `wrapped.key` + `meta.json` fingerprint. The vault key and ciphertext are never touched, so encrypted data survives and the lock state is preserved; a forgotten password is unrecoverable by design. `passwd` is rate-limited like `unlock`. `daemon restart` = stop (wait for exit) then start (picks up a new binary); degrades to start when nothing is running. `daemon reload` sends SIGHUP to re-read `~/.byn/config` and apply runtime-changeable settings (`idle_timeout`, web portal enable/disable/port) **without** dropping daemon state — open vaults stay unlocked. Data dir, owner UID and binary version are fixed at start (need a restart).

5.2.3. **Structure CRUD:** `vault {list,delete,rename,passwd,init,unlock,lock}`,
`project {create,list,delete,rename}`, `env {create,list,delete,rename}`.
`vault rename OLD NEW` moves `vaults/<old>/` → `vaults/<new>/` and the audit
trail `audit/<old>/` → `audit/<new>/`, updates `meta.json`'s name, refuses
the default vault and an existing destination. Renaming is crypto-safe (the
AEAD AAD binds to `vault_id`, not the name) but evicts the in-memory store,
so the vault is **left locked** afterwards. Like deletes, `vault rename`,
`project/env delete` accept a one-shot password while the vault is locked
(`authorizeMutationWhileLocked`); `project/env rename` still require unlock.

5.2.4. **Env-var data plane:** `put`, `get` (alias `cat`), `list`
(alias `ls`), `delete` (alias `rm`), `rename` (alias `mv`).

5.2.5. **Bulk I/O:** `import [PATH | -] [--format env|yaml|json]
[--dry-run] [--skip-existing | --replace [--yes]]`,
`export [--format env|yaml|json] [--output PATH]`.

5.2.6. **Execution:** `exec -- COMMAND [ARGS...]`.

5.2.7. **Editor / TUI:** `edit`, `view`, bare `byn` (no args).

5.2.8. **Diagnostics:** `doctor [--json]`, `audit {view [--lines N]
[--json], tail [-n N] [-f] [--json], verify [--json]}`. `audit view` is
the snapshot; `audit tail` mirrors `tail(1)` (last N, `-f` follows in
realtime). Both render the caller (§7.1.3) on each row.

5.2.9. **Trust:** `trust [PATH]`, `trust list [--json]`,
`untrust [PATH]`.

5.2.10. **Misc:** `version`, `help [COMMAND]`.

### 5.3 Input safety

5.3.1. `byn put NAME VALUE` MUST be rejected with an error
explaining the security issue. Values come from stdin only.

5.3.2. `byn get NAME` MUST emit the raw value bytes to stdout
without a trailing newline when stdout is not a TTY.

5.3.3. `byn exec` MUST use `syscall.Exec` (replace-in-place), so
the child gets the parent CLI's PID and the values never live in a
shell variable.

5.3.4. Argv-leak refusal MUST extend to any future command that takes
a sensitive value.

### 5.4 Agent mode (`--json`)

5.4.1. When `--json` appears anywhere before `--` in argv, the CLI
enters agent mode.

5.4.2. Agent mode MUST refuse all interactive prompts. Untrusted
`.byn` files MUST hard-fail in agent mode; the user must run
`byn trust PATH` from an interactive terminal first.

5.4.3. `--json` does NOT auto-enable on subcommands that don't
support a JSON output today. The flag is a no-op for those (no error).

### 5.5 Mutating-op hints (`BYN_HINTS`)

5.5.1. After every mutating CLI op (put, delete, rename, project
create, env create, import, export, etc.), a one-line stderr echo MAY
fire. The hint MUST NOT contain secret values — only names + scope.

5.5.2. `BYN_HINTS=0` (or `false`, `off`, `no`) MUST suppress
hints. Non-TTY stderr SHOULD auto-suppress.

### 5.6 Pager

5.6.1. `byn help` output MUST be paged through `$PAGER` (default
`less -RFX`) when stdout is a TTY. `PAGER=cat` and `BYN_NO_PAGER=1`
disable.

---

## 6. `.byn` discovery + TOFU

### 6.1 Discovery

6.1.1. Discovery walks from CWD up through parent directories looking
for a `.byn` file. The first non-empty hit wins.

6.1.2. Stop conditions: hitting `$HOME`, hitting filesystem root, or
hitting an empty `.byn` (per-project escape hatch).

6.1.3. `.byn` is strict TOML. Schema:
```toml
[scope]
vault   = "..."  # optional
project = "..."  # optional
env     = "..."  # optional
```
Unknown top-level keys MUST fail with a clear error pointing at the
key.

6.1.4. Discovery is skipped for management commands: `trust`,
`untrust`, `daemon`, `version`, `help`, `doctor`. Otherwise an
untrusted `.byn` would prevent the user from running
`byn trust` to fix it.

6.1.5. `--no-discovery` flag and `BYN_NO_DISCOVERY=1` env var
opt out for one call / one session.

### 6.2 Trust on First Use

6.2.1. Each first-seen `.byn` triggers a prompt (`trust [y/N]:`)
in interactive terminal mode. Agent mode hard-fails.

6.2.2. Trust record: `(canonical_path, sha256_of_full_contents)`,
written to `~/.byn/trusted_byn.json` (mode 0600).

6.2.3. Canonical path computation: `filepath.EvalSymlinks(path)`.
This MUST be used so `/tmp/x` and `/private/tmp/x` (macOS) match.

6.2.4. On every subsequent invocation: the file is hashed; mismatch
or absent record MUST be treated as untrusted.

6.2.5. Trust file integrity is currently UNIX-perms only. HMAC
signing is designed and deferred (see
internal design notes).

---

## 7. Audit log

### 7.1 Format

7.1.1. Per-vault append-only log under
`$BYN_DIR/audit/<vault>/YYYY-MM.log`. New file each month.

7.1.2. Mode `0600`. NDJSON: one JSON object per line.

7.1.3. Event schema MUST include: `ts` (unix nanos), `vault_id`,
`vault_name`, `project`, `env`, `kind`, `entry_name`, `op`,
`outcome`, `error_code`, `hmac_chain`, AND the caller identity for
forensics: `caller_uid`, `caller_pid`, `caller_comm` (the caller
process's name), `caller_pcomm` (its parent's name — who invoked it),
and `caller_surface` (`socket` for CLI/TUI over the Unix socket,
`portal` for the in-process browser UI). Socket callers' UID/PID come
from `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED`+`LOCAL_PEERPID` (macOS);
process names from `/proc` (Linux) / `sysctl kern.proc` (macOS), and are
best-effort (empty when unavailable). Portal requests record the
daemon-owner UID + daemon PID. Value reads — `get`, and a portal/TUI
reveal (which routes through `get`) — are audited like any other access.

### 7.2 HMAC chain

7.2.1. `hmac_chain_i = HMAC-SHA256(seed, prev_chain ‖ canonical_event_bytes_i)`.

7.2.2. Seed is 32 random bytes, stored in vault's `meta.audit_chain_seed`.
Head (latest chain) stored in `meta.audit_chain_head`.

7.2.3. Both seed and head live in the unencrypted meta table — `audit
tail` and `audit verify` MUST work on a locked vault.

7.2.4. `audit verify` MUST walk the entire log and report the first
broken index (or `-1` for intact). CLI exits 3 on a broken chain.

7.2.5. Plain-text entry names in the log. This is a deliberate
forensics decision — hashing would hide what was accessed. MUST NOT
change without documenting the trade-off.

7.2.6. Crash window: there is a (small) window between writing a line
to disk and updating the DB-stored head where a process crash can
leave the on-disk log ahead of the head. `byn audit verify` would
flag this as broken until a future `doctor` repair mode is shipped.

---

## 8. TUI

### 8.1 Layout

8.1.1. Five tiers based on terminal dimensions:
- **Below-min** (< 40 cols OR < 12 rows): fallback screen, no rail/content
- **Tiny** (40-59 cols): no rail, breadcrumb in top bar, abbreviated dates
- **Medium** (60-89 cols): 20-col rail, abbreviated dates
- **Standard** (90-119 cols): 26-col rail, full dates
- **Large** (120+ cols): 26-col rail + 32-col detail pane

8.1.2. 1-column gutter between adjacent visible panes. Status line
takes 1 row at the bottom, always.

8.1.3. Layout MUST be recomputed on every `WindowSizeMsg`. Resize
MUST not crash or leak panes from a prior frame.

8.1.4. The ENV-VARS list MUST scroll to keep the selected entry visible
when there are more entries than fit the content pane (e.g. after
importing a large `.env`). The list windows around `entryCursor`; the
FILES and RECENT AUDIT sections take fixed space and MUST remain visible
— a long list takes the remaining height and MUST NOT push them
off-screen or be clipped such that the cursor row disappears. When an
entry is expanded (REVEAL value, or INSERT/RENAME editor), the viewport
MUST reserve room for that box so the box AND its hint line stay
on-screen. The rendered content frame MUST NOT exceed the terminal
height — height accounting counts real terminal rows, not multi-line
slice elements — so the always-present status line (§8.1.2) is never
pushed below the viewport.

### 8.2 Focus

8.2.1. Default focus on launch: **rail** (so j/k work immediately).

8.2.2. `Tab` and `Shift+Tab` toggle focus between rail and content.
(Only two focusable panes today; detail pane is read-only.)

### 8.3 Modes

8.3.1. Modes: NORMAL, INSERT, ADD, RENAME, REVEAL, CONFIRM-DELETE,
SCOPE-PICKER, COMMAND, SEARCH, AUDIT, HELP.

8.3.2. Status line MUST always show the current mode label.

8.3.3. Mode transitions MUST be reversible without data loss (ESC
preserves the draft, except for SCOPE/AUDIT/HELP/CONFIRM modes which
have no draft state).

### 8.4 Draft / save (vi semantics)

8.4.1. **Typing in INSERT, ADD, or RENAME mode modifies a local
draft buffer only. The daemon is not contacted.**

8.4.2. `:w` commits the draft (single `OpPut`). Returns to NORMAL.

8.4.3. `:q` from edit context refuses if the draft is dirty.
`unsaved edit — :w to save or :q! to discard` flash.

8.4.4. `:q!` discards the draft unconditionally.

8.4.5. `:wq` is `:w` then leave edit context (NOT `:q` then quit-app).

8.4.6. `q` from NORMAL: quits the TUI ONLY if no dirty draft exists.
Otherwise refuses with the same message as `:q`.

8.4.7. `ESC` from INSERT/ADD/RENAME drops to NORMAL but **keeps**
the draft. Flash explains the next step. The draft is only cleared
on `:w` (success) or `:q!` (discard).

8.4.8. Dirty-draft indicators MUST be visible from NORMAL view:
- `[DRAFT: NAME]` chip in the status line
- `[*]` prefix on the row that has the pending draft

8.4.9. Pressing `i` / `a` / `r` while a dirty draft for a DIFFERENT
entry exists MUST refuse with a clear message. Pressing `i` on the
**same** entry MUST resume the draft (no daemon re-fetch).

8.4.10. `Enter` in INSERT or ADD-value field inserts a literal `\n`
(multi-line values are supported). `Enter` on ADD-name field
advances to the value field. `Enter` in RENAME is ignored
(single-line). `Enter` MUST NOT commit; only `:w` does.

### 8.5 Undo / redo / clipboard

8.5.1. `u` (NORMAL): undo last change in draft. Snapshot-per-keystroke.

8.5.2. `Ctrl+R` (NORMAL): redo.

8.5.3. Undo history capped at 200 snapshots per draft. Oldest dropped first.

8.5.4. `y` (NORMAL, entry selected): yank the entry's value to the
system clipboard. This MUST fire a daemon `OpGet` and emit an audit
event (same auditability as `R` reveal).

8.5.5. `y` (REVEAL): copy the already-revealed value to the
clipboard. No new IPC roundtrip.

8.5.6. `p` (NORMAL): paste clipboard into the currently-open draft
at cursor. Refuses if no draft is open.

8.5.7. `Ctrl+V` (INSERT): paste inline.

### 8.6 Scope picker (`s`)

8.6.1. Centered 3-column modal: vault / project / env.

8.6.2. Moving the vault cursor (column 0) MUST repopulate BOTH the
projects column AND the envs column, using the first/matching
project as parent. (Otherwise Tab→Tab→Enter on a small screen lands
on an empty env list.)

8.6.3. The modal SHOULD try to preserve the user's current project
+ env across a vault change — if matching names exist in the new
vault, they stay selected.

### 8.7 Rail tree

8.7.1. `h` / `l` fold/unfold the focused node. Cursor MUST stay on
the same node — no auto-snap to active scope after the rebuild.

8.7.2. Auto-snap to active scope happens ONLY on initial load (after
envs for the active scope finish loading) and on explicit scope
changes (Enter on env leaf, scope picker apply).

8.7.3. `+ new vault` row is pinned at the bottom of the rail. Pressing
Enter on it currently flashes `vault creation not yet wired in TUI —
use 'byn init'`. This is a deliberate gap, NOT a bug.

8.7.4. **Scope CRUD from the rail — DEFERRED (planned, not built).**
Creating and deleting vaults, projects, and envs from the TUI rail
(and, once it exists, the browser portal) is a planned feature. Today
the only way to add or remove a scope is the CLI (`vault init/delete`,
`project create/delete`, `env create/delete`). The TUI/portal MUST
eventually offer: add vault/project/env, and delete vault/project/env
(with the §2.1.2 refusal-to-delete-`default` rules and a confirm
step). Tracked on the roadmap. Until then,
this is a known gap, NOT a bug.

### 8.8 Inheritance badges

8.8.1. When the active env is non-default, each entry row MUST show
exactly one of three badges:
- `↓` dim cyan — Source=default (daemon-inherited from default env)
- `⤴` bold yellow — Source=scope AND name exists in default env's list
- `✦` bold green — Source=scope AND name does NOT exist in default env

8.8.2. When the active env IS default, the badge column MUST be
hidden.

8.8.3. To distinguish overridden from new, the TUI MUST list the
default env's names via a separate `OpList`. Until that response
arrives, entries display no badge (renderer SHOULD NOT guess).

8.8.4. A one-line legend MUST appear under the ENV-VARS header
whenever the active env is non-default.

### 8.9 Active filter

8.9.1. When `m.entriesFilter != ""`, the active filter MUST be
visible in:
- the ENV-VARS section header (warning color, `(N of M match — ESC to clear)`)
- the status line (persistent chip `filter="..."`)

8.9.2. `ESC` from NORMAL MUST clear an active filter (in addition to
its normal behavior in other modes).

8.9.3. `a` (start add) MUST also clear the filter so the new entry is
visible after commit.

### 8.10 Locked vault

8.10.1. When the current scope's vault is locked, `i`/`a`/`r`/`R`
MUST refuse with a flash naming the vault and pointing at the
recovery command (`byn --vault NAME unlock`).

8.10.2. The ENV-VARS section MUST render `Vault is locked` + the
recovery hint instead of `(no env-vars)`.

8.10.3. `byn --vault X edit` MUST unlock X (not "default") at
bootstrap. Password prompt MUST name the targeted vault.

### 8.11 Audit visibility

8.11.1. The TUI MUST refresh its audit-tail snapshot after every
mutating op (put, delete, rename) AND after every reveal/yank, so
the RECENT AUDIT section reflects current state.

8.11.2. `ga` opens the full-screen AUDIT view. `q` returns. `r`
refreshes. `v` runs an `audit verify`.

---

## 9. Security guarantees

### 9.1 In scope

- Confidentiality of vault values against other local users (UNIX
  perms + peer-UID enforcement).
- Confidentiality of vault values against passive thieves with the
  encrypted DB (Argon2id + AEAD).
- Integrity of the audit log against tampering by anyone who doesn't
  have the seed (HMAC chain + verify).
- Forensic visibility of access patterns (plain-text names + caller
  UID/PID + chained outcomes).
- Refusal to leak values via argv, environment, prompts, shell
  history, or scrollback.
- Protection of agent harnesses against silent `.byn` redirection
  (TOFU + agent-mode hard fail).
- **Reduction and detection of dev-time AI-agent secret leakage** (the
  primary use case): a coding/debugging agent has no plaintext
  `.env`/credential file to read accidentally — values live only in the
  vault — and every value access is recorded in the tamper-evident
  audit log. This is a *reduce-and-detect* guarantee, not prevention;
  see §9.4 for the full model and limits.

### 9.2 Out of scope

- Root on the local machine.
- Attackers who know the master password.
- A **maliciously active** attacker with shell access as the daemon's
  UID (they can replace the binary, trace memory, or read another
  process's `/proc/<pid>/environ`). Note the boundary vs the in-scope
  case (§9.4): byn defends against an agent that *accidentally* reads
  secret files and against *casual* extraction; it does not claim to
  stop a same-UID process that is *actively* hunting for secrets.
- Live-memory attackers attached to the running daemon.
- Network adversaries (byn is local-only today; cloud sync is a
  future spec).
- Coercion ("type your password or else").

### 9.3 Known qualifications (must remain documented)

- `internal/secmem` is wired into the **CLI-side password prompt**
  (`auth.PromptStdinSecure`): the master password is mlock'd from
  prompt input through IPC send + wipe. **NOT YET WIRED:** the
  daemon-side receive (`req.Password` is plain `[]byte` once it
  arrives over the Unix socket), the Argon2id workspace inside
  `crypto.Unwrap`, and the unwrapped vault key in `vault.Store`.
  Documented in [docs/security.md](security.md). The CLI window
  is brief (prompt → IPC send) but real; daemon-side wrapping
  requires changing the `vault.Unlock([]byte)` interface and the
  `crypto/wrap.Unwrap` workspace.
- `~/.byn/trusted_byn.json` and `~/.byn/auth-state.json` are
  protected only by UNIX file permissions. Tampering by an attacker
  who can write `~` is undetected. HMAC signing is designed; see
  internal design notes.
- `vault.unlock` is not currently constant-time across the entire
  decision path. The wrap/unwrap primitive itself uses
  `hmac.Equal`; surrounding code does not.
- `ipc.DecodeBody` does not currently use `DisallowUnknownFields`.
  Envelope decode does. A malicious peer can pad request bodies with
  arbitrary fields without effect today.
- The audit chain has a (small) crash window between log file fsync
  and chain head MetaSet. A repair mode in `byn doctor` is the
  planned mitigation; not yet shipped.

These qualifications ARE part of the contract — they bound what we
promise. Don't tighten them without shipping the corresponding work.

### 9.4 Dev-time AI-agent threat model (reduce-and-detect)

byn's PRIMARY purpose is to keep secrets away from coding/debugging
agents that would otherwise read a plaintext `.env`,
`~/.aws/credentials`, SSH key, or cert off disk and leak it into chat
history, logs, tool output, or a commit — often silently, so the user
may not learn of the leak until later. This threat is real and
externally validated: in-app agent guardrails are unreliable (e.g.
Claude Code `read.deny` rules have repeatedly failed to block `.env`
reads — anthropics/claude-code#24846), so byn MUST NOT depend on the
agent harness enforcing a deny. A survey of prior art found no existing
tool that combines transparent credential injection, keeping plaintext
off the agent's disk, AND a per-access audit trail (full analysis:
internal design notes).

The guarantee is **reduce-and-detect, not prevent.**

Today (env-var injection + audit, shipped):
- There is NO plaintext `.env` for the agent to read accidentally —
  values live only in the vault.
- Every value access (`get`, `exec`, TUI reveal/yank) is recorded in
  the tamper-evident audit log, so a leak is *detectable* after the
  fact.

**Accepted limitation (contract):** env-var values injected into a
child process ARE readable from that child's `/proc/<pid>/environ` by a
same-UID process. byn does not attempt to prevent this — the consuming
process must read them. For env vars the guarantee is *no accidental
file read* + *audited access*, NOT concealment from a determined
same-UID reader.

Intended extension as later phases land (the *target* model — the
sealed-tool/broker/FUSE pieces are NOT yet shipped):
- **Sealed CLI tool** (uses creds, doesn't print them — `aws`/`psql`/
  `ssh`; Phase 3 shims): credential NOT exposed to the agent.
- **Cloud cred used by agent-authored code:** bounded + detected
  (short-lived, scoped, audited) is the ceiling — not concealment.
- **Static secret used by agent-authored code:** detected (audited) only.
- **File / crown-jewel secret:** FUSE + shim path (Phase 5/3) keeps the
  value out of any on-disk file.

Deferred hardening that would raise the bar (NOT committed; revisit
post-launch — see [docs/security.md](security.md) and
internal design notes):
per-operation biometric auth instead of a persistent unlock window;
a fingerprinted exec allowlist; an ephemeral scoped credential broker
(STS via `credential_process`); pairing the PATH-shim with an OS
deny-read layer (Seatbelt/Landlock).

---

## 10. Backward compatibility

### 10.1 Stable surfaces

10.1.1. CLI exit codes (§5.1) — never change meaning.

10.1.2. Command names and aliases that have shipped (§5.2) — never
remove or rename without a major version bump.

10.1.3. IPC error codes (§3.3.3) — never change meaning. New codes
MAY be added.

10.1.4. IPC envelope schema (`V`, `ID`, `Op`, `Req`/`Resp`/`Err`).
Versioned via `ProtocolVersion`; bumping requires explicit
negotiation work.

10.1.5. On-disk file layout (§1.1) — additions MAY happen via schema
migration; removals or renames require migration + version bump.

10.1.6. SQLite schema migrations MUST be forward-only.

### 10.2 Pre-1.0 waiver

Until byn hits 1.0, we MAY break the on-disk vault format with
explicit migration steps. Once 1.0 ships, migrations MUST be
non-destructive (read old, write new, no data lost).

### 10.3 Removing a deferred feature

If we ever decide NOT to ship a deferred feature listed in this
document (e.g., the trust-file MAC), we MUST update the corresponding
qualification in §9.3 explaining why, BEFORE merging the decision.

---

## 11. Process

### 11.1 Tests

11.1.1. Every shipped feature MUST have unit tests. Integration tests
MUST cover daemon-CLI happy path + error paths.

11.1.2. Coverage SHOULD stay above 80% per-package for non-terminal
code. TUI rendering and TTY-only paths are excluded from this floor.

11.1.3. Tests SHIP WITH the code in the same commit. Never after.

11.1.4. Snapshot tests guard TUI layouts at each tier (Tiny, Medium,
Standard, Large, Below-min).

### 11.2 Documentation

11.2.1. Every shipped feature MUST be reflected in:
- `docs/cli-reference.md` (user-facing command reference)
- `cmd/byn/help_text.go` (per-command help blob)
- `man/byn.1` (man page)
- This file, if the feature carries a contract

11.2.2. Phase/slice work MUST appear in the development log with
date + decisions + deferrals.

11.2.3. Long-horizon planning lives in the roadmap. Active session
tracking lives in the task list.

### 11.3 Change discipline

11.3.1. One feature at a time. The default disposition is to finish
the in-flight feature before starting a new one (see
internal design notes).

11.3.2. A commit/PR that adds a contract here MUST also add the test
that proves it.

11.3.3. A commit/PR that loosens a contract here MUST list the
weakening explicitly in the commit message AND update §9.3 / §10
accordingly.

---

## 12. Web portal (browser admin UI)

### 12.1 Transport

12.1.1. The daemon hosts an embedded browser portal when `[ui] enabled`
is true in `$BYN_DIR/config` (default true). It binds **loopback only**
(`127.0.0.1:<port>`), never `0.0.0.0`. The port is `[ui] port` (default
**2967**).

12.1.2. The portal is **plain HTTP** on loopback — no TLS, no
`local.byn.com`, no certificate distribution. `http://localhost` is a
browser-trusted secure context, which is sufficient for the portal and
for future WebAuthn.

12.1.3. A bind failure (e.g. port already in use) MUST disable the
portal without preventing the daemon from serving the CLI/TUI over the
Unix socket.

12.1.4. Every browser request is translated into an in-process IPC
envelope and routed through the **same `dispatch` path** as Unix-socket
clients — identical scope resolution, lock checks, inheritance, and
audit. The portal MUST NOT reimplement vault logic.

### 12.2 Authentication — none (per-vault lock is the gate)

12.2.1. **There is no portal login or session.** Like `byn ls`, the scope
tree (vault/project/env names) and entry names are visible without any
portal password. The *gate for VALUES* is the daemon's per-vault lock
state, enforced by the same `dispatch` path: a value read/write on a
locked vault returns `CodeLocked` (HTTP 423). This mirrors the TUI, which
shows names but renders "Vault is locked" for values (§8.10).

12.2.2. Vault lock state is toggled per-vault from the portal:
`POST /api/unlock {vault,password}` (→ `OpVaultUnlock`) and
`POST /api/lock {vault}` (→ `OpVaultLock`; `vault:"*"` locks all). These only
change daemon lock state; they create no portal session.

12.2.2.1. **The daemon is the source of truth for lock state.** The portal
MUST NOT gate the lock/unlock actions on its own cached belief: the `l`/`u`
hotkeys and the lock/unlock buttons always issue the request (the daemon's
lock is idempotent), so an emergency lock (`l`) fires even if the UI thinks
the vault is already locked, and `l a` locks every vault. To keep the cached
view honest when a vault is locked/unlocked from the CLI or TUI, the portal
**polls `GET /api/status` every ~2s** and re-renders when a lock state
changed (guarded so it never clobbers an in-progress edit/dialog) — without
this the UI could show a "locked" banner over a vault that is actually
unlocked, or refuse a lock it believes redundant.

12.2.2.2. **Changing the master password** from the portal:
`POST /api/vault/passwd {vault, old_password, new_password}` (→
`OpVaultPasswd`). **Renaming**: `POST /api/{project,env,vault}/rename`
(→ `OpProjectRename`/`OpEnvRename`/`OpVaultRename`); the vault-rename body
carries a `password` for the locked case (§5.2.3). Deletes carry a
`password` too (§4.2.2.1).

12.2.3. **CSRF defense is an Origin check** (not a token): a mutating
(non-GET) request whose `Origin` header is present and is not the portal's
own loopback origin (`http://localhost:<port>` / `http://127.0.0.1:<port>`)
MUST be refused (403). A browser always sends `Origin` on a cross-site
POST, so a malicious page cannot drive the portal even without a session.
A request with no `Origin` (a non-browser local client) is allowed — it
could use the Unix socket directly anyway (§12.4). The server MUST NOT
emit `Access-Control-Allow-Origin`, so cross-origin reads stay blocked by
the browser.

12.2.4. `POST /api/vaults {name,password}` creates a vault (`OpVaultInit`)
and unlocks it. The portal MUST NOT take any dependency on a cloud
identity; all auth is local.

### 12.3 Behavior

12.3.1. Value reads via the portal (`POST /api/entry/reveal`) go through
`OpGet` and MUST be audited exactly like a CLI `get` or TUI reveal.

12.3.2. The portal shares the TUI's information architecture — the
`vault → project → env` scope tree and the inheritance badge meanings
(`↓` inherited / `⤴` overrides default / `✦` new in env) — rendered as a
conventional web app (not a terminal mimic).

12.3.3. The portal MUST take no dependency on any cloud identity; auth is
strictly local (password today; passkey later). Full-cloud auth is a
separate, unbuilt design.

### 12.4 Known qualifications (must remain documented)

- Any local process can open a TCP connection to `localhost:<port>` and
  read the scope tree + entry names, and read/write values of any
  **currently-unlocked** vault — there is no portal password. This is by
  design (§12.2.1) and is the same same-UID boundary as the rest of byn
  (§9.2): a same-UID process can already drive the Unix socket. The open
  TCP port is a new *surface* vs the 0600 socket, mitigated by loopback
  binding + the Origin check; values of *locked* vaults remain protected
  by the lock.
- Revealed values cross the loopback connection in cleartext (loopback
  traffic does not leave the machine).
- **WebAuthn / passkey unlock is NOT yet built.** Per-vault unlock uses the
  master password only. Passkey unlock (PRF-based) is a future slice — see
  [`docs/research/webauthn-prf-spike.md`](research/webauthn-prf-spike.md)
  and the roadmap.

---

## Related docs (deeper explanations, not contracts)

- [docs/architecture.md](architecture.md) — system design + IPC flow.
- [docs/security.md](security.md) — full threat model + crypto stack + deferred hardening.
- [docs/cli-reference.md](cli-reference.md) — every command, flag, env var.
- [docs/byn-file-format.md](byn-file-format.md) — discovery + TOFU.
- [docs/file-layout.md](file-layout.md) — what each file on disk contains.
- [docs/tui-design.md](tui-design.md) — TUI design spec.
- [docs/glossary.md](glossary.md) — terminology.
- [docs/troubleshooting.md](troubleshooting.md) — common error states.
