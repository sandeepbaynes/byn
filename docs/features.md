# byn — Features

What is shippable today, organized by user-facing capability. Each
feature names the relevant source files for future reference. Planned,
not-yet-built capabilities are listed under [Roadmap](#roadmap-planned-not-yet-built),
clearly marked.

---

## 1. Secure multi-vault store

- Multiple vaults coexist; each gets its own SQLite database and
  Argon2id-wrapped key under `vaults/<name>/` in the byn data root (see
  [File layout](file-layout.md)). Keep work and personal credentials apart with
  multiple **vaults**, not multiple data dirs.
- Vault key is a random 32 bytes. Wrapped with
  `Argon2id(password, salt) → XChaCha20-Poly1305 AEAD`; the AEAD's AAD
  binds the full header (salt + Argon2 params + version) so any byte
  in the header changes the unwrap result.
- Per-row encryption: `XChaCha20-Poly1305` with random 24-byte nonce,
  AAD = `vault_id || 0x1F || kind || 0x1F || name`. Names are
  plaintext (forensics-friendly); values are ciphertext.
- Schema v4, SQLite STRICT tables, FK enforced. Versioned migrations
  in `internal/vault/schema.go`.

## 2. Project / env scopes inside each vault

- `vault → project → env → entry` four-level path.
- Default project + default env per vault (created on init).
- Non-default envs fall back to default for missing keys
  (inheritance).
- CRUD via `byn {project,env} {list,create,delete,rename}`.

## 3. Daemon + IPC

- Unix socket (`daemon.sock`) at the daemon's runtime path, mode 0600, peer-UID
  enforced.
- Length-prefixed JSON envelopes; per-call connection.
- Multi-vault state map: `map[string]*vaultEntry` with per-vault idle
  timer and rate limiter.
- Status / version negotiation (protocol min/max).

## 4. CLI surface

- Hybrid scope flag pre-parser: `--vault`/`--project`/`--env` work
  before or after the subcommand, conflicting duplicates error, env
  fallbacks `BYN_VAULT`/`BYN_PROJECT`/`BYN_ENV`.
- Env-var ops: `put` (stdin only, never argv), `get`, `list`,
  `delete`, `rename` with `cat`/`ls`/`rm`/`mv` aliases.
- Structure CRUD: vault/project/env list/create/delete/rename.
- Bulk: `import` (`.env`/`.yaml`/`.json` files or stdin),
  `export` (same formats, stdout or `--output`).
- Execution: `byn exec -- COMMAND` injects vault env-vars into the
  child via `syscall.Exec` (no parent process, no inheritance of CLI
  PID). With privsep enabled, a trusted-pinned exec is instead spawned
  daemon-side as `_byn-exec` (see §13).
- Provisioning & migration: `byn setup` (one-sudo privsep install,
  idempotent, `--uninstall`/`--purge`) and `byn migrate` (relocate the
  legacy `~/.byn` into the system path, or import a vault tree with
  `--from`) — see §14 and [Migration & setup](migration.md).
- Modal TUI: `byn`, `byn edit`, `byn view` open the vi-style
  TUI for the default scope.
- AWS-CLI style help: `byn <cmd> {help,--help,-h}` and
  `byn help <cmd>`; man page at `man/byn.1`.

## 5. Agent / JSON mode

- `--json` is accepted by:
  - `byn list`
  - `byn get`
  - `byn status`
  - `byn vault list`, `byn project list`, `byn env list`
- Output: arrays/objects keyed exactly to the matching IPC response
  types — agent harnesses can `JSON.parse` directly.

## 6. Bulk import/export

- Import detects format by extension (`.env`/`.yaml`/`.json`), then
  sniffs `{` for JSON, then errors. `--format` overrides.
- Dotenv parser handles `export`, quoted values with `\n`/`\t`/`\"`
  escapes, single-quoted literals, inline `# comment` stripping.
- YAML/JSON: flat key→scalar maps only; nested data is rejected with
  a clear error.
- `--dry-run` previews keys + byte sizes; `--skip-existing` switches
  semantics from overwrite to add-only.
- `--replace [--yes]` is the destructive variant — wipes every
  existing key in the scope first, then imports. Confirms on a TTY;
  `--yes` is required in non-TTY/agent mode. Mutually exclusive
  with `--skip-existing`. Tests cover all three modes.
- Export emits a sorted dotenv-style document by default; YAML and
  JSON also available. `--output PATH` writes 0600.

## 7. IDE integration docs

- `docs/integrations/vscode.md` — Node/Python/Go launch.json
  recipes, tasks, terminal wiring.
- `docs/integrations/jetbrains.md` — IntelliJ/GoLand/PyCharm/WebStorm,
  External Tools + script-wrapping.
- `docs/integrations/eclipse.md` — External Tools, terminal,
  External Maven/Gradle wrapping.
- `docs/integrations/ai-agents.md` — agent-safe usage patterns:
  what to allow, what to deny, example permission rules, per-project
  scope pinning via `direnv`.

## 8. Audit log (HMAC-chained)

- Per-vault append-only audit log; each entry HMAC'd with the
  previous entry's tag (chain).
- Plain-text names (forensics-friendly).
- `byn audit tail [--lines N] [--json]` — read recent events
  (works while locked).
- `byn audit verify [--json]` — walk the chain end-to-end; exit 3
  with "BROKEN at event #M" on tamper.
- HMAC seed + head persisted in vault meta; daemon resumes cleanly
  across restarts.

## 9. Diagnostics

- `byn doctor [--json]` — daemon-side battery: daemon liveness,
  vaults-on-disk enumeration, per-vault schema + meta.json
  fingerprint, per-vault audit-chain integrity.
- Per-check severity (`ok` / `warn` / `fail`); exit non-zero on any
  fail.
- Mutating-op hints to stderr (`Stored "K" in default/billing/staging.`)
  gated by `BYN_HINTS=0` and non-TTY stderr.

## 10. `.byn` discovery + TOFU trust

- CWD-walk for a `.byn` TOML file (strict parser; unknown keys
  fail). Stops at home dir, filesystem root, or an empty `.byn`
  (per-project escape hatch).
- Trust on First Use: SHA-256 of file contents recorded against the
  canonical path (`filepath.EvalSymlinks`) in
  `~/.byn/trusted_byn.json`.
- **Auth-gated grants (shipped):** `byn trust` ALWAYS requires the master
  password — even when the vault is unlocked — and routes through the
  daemon (which owns the store + verifies the password against the vault
  the `.byn` targets). Discovery is read-only and **never auto-trusts**:
  a new *or changed* `.byn` is refused (both interactive and agent mode)
  until re-approved with `byn trust`. Closes the old `trust [y/N]`
  silent-re-trust path. `--password-stdin` for scripts.
- `byn trust [PATH]`, `byn trust list [--json]`, `byn untrust [PATH]` —
  all routed through the daemon.
- `--no-discovery` flag and `BYN_NO_DISCOVERY=1` opt out.
- Management commands (`trust`, `untrust`, `daemon`, `doctor`,
  `help`, `version`) skip discovery so an untrusted file can't lock
  the user out of fixing it.
- **Deferred (separate slice):** HMAC-signing the trust store so a direct
  write to `trusted_byn.json` (which the password gate can't stop) is
  detected; and a portal "approve" action as an out-of-band channel.

## 11. Responsive bubbletea TUI

- `byn`, `byn edit`, `byn view` open the modal vi-style TUI.
- Five layout tiers driven by `(width, height)`:
  - Below-min (< 40×12): friendly fallback message
  - Tiny (40-59): breadcrumb only, no rail, abbreviated dates
  - Medium (60-89): 20-col rail, abbreviated dates
  - Standard (90-119): 26-col rail, full dates
  - Large (120+): rail + 32-col detail pane with live entry metadata
- SIGWINCH-aware: resize re-lays cleanly with no flicker; cursor
  preserved across tier changes.
- Default focus on the rail so j/k navigate immediately. `Tab` /
  `Shift+Tab` toggle to content.
- **vi-style draft semantics** — typing modifies a local buffer only.
  `:w` commits, `:q` refuses dirty, `:q!` discards, `:wq` saves+leaves.
  ESC preserves the draft. Dirty drafts surfaced as `[DRAFT: NAME]`
  in status line + `[*]` next to the row.
- **Undo / redo** on the draft buffer: `u` undoes, `Ctrl+R` redoes.
  Per-keystroke snapshot, capped at 200 per draft.
- **Clipboard** (cross-platform via `atotto/clipboard`):
  - `y` (NORMAL) yanks selected entry's value (audited `OpGet`)
  - `y` (REVEAL) copies the revealed value
  - `p` (NORMAL) pastes into open draft
  - `Ctrl+V` (INSERT) pastes inline
- **Inheritance badges** in non-default envs:
  - `↓` inherited from default
  - `⤴` overrides default
  - `✦` created in this env only
  - Legend rendered under ENV-VARS header
- **Scope picker** (`s`) — 3-column modal with cascading: vault
  change updates both projects AND envs; tries to preserve current
  project/env names across the switch.
- **Targeted vault bootstrap** — `byn --vault X edit` prompts for
  X's password (not "default") and lands on X with the rail cursor
  pre-positioned to the most specific match (env > project > vault).
- **Locked-vault state** rendered explicitly — `Vault is locked +
  Run 'byn --vault X unlock' from a shell, then return`. Edit
  actions (i/a/r/R) refuse with the same recovery hint.
- **Active filter never hidden** — section header, status-line chip,
  and auto-clear-on-add all surface a running `m.entriesFilter`. ESC
  from NORMAL clears it.
- **Audit visibility** — RECENT AUDIT updates after every mutating
  op + every reveal/yank. `ga` opens the full-screen AUDIT view.
- Snapshot tests guard each tier: TestSnapshots_PerTier,
  TestRender_Tiny_NoRail, etc. ~14 TUI tests total.

## 12. Security primitives

- `internal/secmem`: mlock'd byte buffers for unwrap workspace and
  master-password handling.
- `internal/auth`: golang.org/x/term raw-mode prompt; persistent
  failed-unlock backoff in `auth-state.json`.
- `byn put NAME VALUE` rejected at the CLI — value via stdin only,
  so secrets never enter argv or scrollback.
- **Passkey unlock (Touch ID):** enroll a WebAuthn/PRF passkey from the local
  portal to unlock a vault with Touch ID — a second, KEK-wrapped copy of the
  vault key (`internal/passkey`, `passkey_unlock` table; see `docs/security.md`
  §7). Per-vault, never passkey-only; the master password stays the recovery
  root. Revoke is password-gated and cascades to a hard lockout. macOS Touch ID
  / iCloud Keychain only; non-PRF authenticators degrade to session-only.

## 13. Privilege separation (opt-in, off by default)

- **Three-UID model:** owner (you) ≠ `_byn` (the daemon) ≠ `_byn-exec`
  (exec children of a trusted, *pinned* `.byn` action). The daemon holds
  the vault key as `_byn`, so a same-(owner)-UID **non-root** process can't
  ptrace it; a pinned exec child runs as `_byn-exec`, so that process can't
  read its `/proc/<pid>/environ`.
- **Opt-in this release, off by default** (`[security] privsep = true`,
  provisioned by `byn setup`). When off, byn behaves exactly as before —
  the daemon and exec children run at your UID and the same-UID env-sniff /
  daemon-ptrace holes remain open. Stated plainly so there's no false
  assurance.
- **Honest ceiling:** privsep raises the bar to **root** — it does **not**
  defend against root, `CAP_SYS_PTRACE`, or a root `task_for_pid`. Linux
  adds `PR_SET_DUMPABLE=0`; macOS hardened-runtime only takes effect for a
  Developer ID-signed build. Ad-hoc exec (no pinned `.byn`) still runs at
  your UID even with privsep on.
- **Fail-closed:** privsep enabled but unprovisioned errors ("run `sudo byn
  setup`") — it never silently downgrades to the owner UID.
- Packages: `internal/privsep`, `internal/setup`, `internal/paths`. See
  [Security model → privilege separation](security.md#privilege-separation-the-three-uid-model-opt-in-nu-56).

## 14. Provisioning & migration

- **`byn setup`** — one-sudo provisioning: creates the `_byn` / `_byn-exec`
  service accounts, installs the system service (systemd unit on Linux,
  LaunchDaemon on macOS) + the privileged spawn helper, relocates a legacy
  `~/.byn` into the system data path, and records the owner UID (from
  `SUDO_UID`). Idempotent; `--uninstall` reverses it (vault preserved),
  `--purge` also deletes the data dir.
- **`byn migrate`** — two modes: **relocate** (no `--from`; moves the legacy
  `~/.byn` into the system path on the same machine, **keeps** trust +
  passkeys) and **import** (`--from PATH`; copies an external vault tree,
  never deletes the source, and **drops** the trust store + passkey
  enrollments so you re-trust + re-enroll). The source is verified **without
  its password** and adoption is atomic.
- **Fixed data root, no override:** state lives at `~/.byn` (default) or the
  system path once provisioned. The old data-root environment variable has
  been **removed** — there is no runtime data-root override.
- Packages: `internal/setup`, `internal/migrate`, `internal/paths`. See
  [Migration & setup](migration.md).

## 15. Tests

- Unit tests under `internal/*`. All pass with `-race`.
- Integration suite under `tests/integration/`, gated by build tag
  `integration`. Covers golden path, status, exec, scope CRUD,
  import/export.

---

## Roadmap (planned, not yet built)

Everything below is **planned, not shipped** — listed for honesty, not as a
current capability.

- **Audit & Observability v2** — immutable per-vault-instance log groups (never
  deletable except by removing the DB itself); CLI + web list / filter / search /
  export; **OTLP export** for metrics and logs; daemon debug logs to journald +
  OTLP. Design backlog.
- **`.byn` behavioral anomaly detection** — baseline an action's normal
  action/env patterns and warn on drift, especially for wildcard grants. Design
  backlog.
- **Shims** — PATH-interception shims for `aws` / `gcloud` / `gh` / `ssh` / etc.
  that inject credentials transparently per command. Not built.
- **FUSE-mounted file secrets** — schema + IPC shaped already; not built.
- **Cloud sync** — password-only encryption, delta push to the local daemon, plus
  TTL/lease offline revocation. Not built.
- **Mobile approval app** — phone-as-2FA approver, multi-device, recovery codes.
  Not built.
- **`.byn` workspace manifest** — per-command env allowlists + file
  materialization. Gated on `byn exec` field-testing.
- **Entry versioning CLI** — `byn history` / `revert` / `diff`. Schema +
  `entry_versions` table shipped; IPC ops + CLI surface deferred.
- **Trust-file HMAC hardening** — `trusted_byn.json` integrity-signed with a
  daemon-resident key (the trust store already carries fp-MAC + vk-MAC record
  MACs; this is the additional whole-file hardening).
- **ACLs / per-user sharing** — not built.
