# Release notes

What changed in each byn release — headline changes, upgrade/migration
notes, and any specific instructions. Newest first.

Downloadable binaries and per-release assets live on the
[GitHub releases page](https://github.com/sandeepbaynes/byn/releases).
This page is the curated changelog; the GitHub page is the artifacts.

> byn is pre-1.0. Until 1.0, minor versions may include behavior changes —
> each one is called out under **Upgrade notes** below.

---

## v0.6.2

**Headline:** two ways byn could leave you without a working daemon, both fixed
— and four commands that had shipped without documentation now have it.

### What's new

- **A relocate no longer locks you out of your own daemon.** On macOS the daemon
  socket lives inside the system data dir, which `byn setup` creates `0711` so
  that you — a different UID than `_byn` — can traverse to it. A relocated
  legacy `~/.byn` was renamed over that directory carrying its own `0700`, after
  which the daemon ran, bound its socket, and answered nobody: every command said
  "daemon is not running" while `launchctl` said it was up. The adopt now carries
  the destination's mode across the swap.
- **`byn doctor` checks that you can traverse the data dir**, so the state above
  names itself instead of looking like a dead daemon. `sudo byn doctor --repair`
  restores the mode *before* it touches the service and then re-probes, so a
  daemon that was merely unreachable is left running rather than restarted.
- **`sudo byn restart` on an unprovisioned machine is refused** instead of
  stopping your daemon and then failing to start it as root — which left no
  daemon at all. The refusal happens before anything is stopped. `restart`,
  `reload` and `stop` all behave this way now; `start` always did.
- **`byn ps`, `byn kill`, `byn runs` and `byn repair` are documented** in the man
  page, and `ps`, `kill` and `repair` in the CLI reference.

### Upgrade notes

- **If a `byn` command says the daemon is down while the service is running**,
  you are in the state this release fixes. `sudo byn doctor --repair` heals it;
  the fix means a fresh `sudo byn setup` will not reach it again.
- **`byn ps` and `byn kill` are Linux-only today.** On macOS `ps` lists nothing
  and `kill` reports "no byn exec processes found" even while exec children are
  running — it stops nothing and its exit status does not report the failure. To
  stop a stuck child on macOS, use `sudo kill PID`. This is now stated in both
  the man page and the CLI reference.

---

## v0.6.1

**Headline:** the writable-path reconcile did nothing at all on macOS.

### What's new

- **The per-file exec grant is a platform function.** It shelled out to
  `setfacl` unconditionally; macOS has no `setfacl` — it has `chmod +a`, which
  byn already used everywhere else on that platform. Every invocation failed with
  "command not found", the error was dropped because the pass is deliberately
  best-effort, and the credential lockout it exists to fix stayed unfixed. It
  compiled, it vetted, it passed every test, and it did nothing.
- **A test now asserts the command produced, per platform.** A cross-compile
  catches a platform stub that will not build; nothing catches one that builds
  and is wrong except asserting what it emits.

### Upgrade notes

- No action. If you are on macOS and hit a credential tool locking out your exec
  children, this is the release that fixes it.

---

## v0.6.0

**Headline:** approvals became answerable from every surface — terminal, portal
and TUI — and an agent can now be told the outcome of its own request instead of
retrying blind.

### What's new

- **Agents can watch their own request.** `byn exec` hands back a `watch_ticket`
  with the `approval_pending` refusal; `byn request watch` blocks until the
  request is answered and prints the outcome as JSON — approved, denied, expired,
  cancelled or revoked, with the decider's reason. Until now the only way to
  learn an outcome was to re-run the command every few seconds, and a poller
  cannot tell "denied" from "not yet". `byn request cancel` withdraws a request.
- **The ticket is the capability, issued exactly once** — to the caller that
  raised the request. A retry, or a second agent asking the same thing, coalesces
  onto the existing card and gets no ticket, so one agent cannot acquire
  another's channel by guessing what it would ask for.
- **The TUI can answer approvals.** `g p` opens the queue; `a` grants, `o` grants
  a single use, `d` refuses, `v` revokes, `r` types a reason, `h` shows history.
  The queue is where work stops, and until now answering meant leaving the editor.
- **The portal gained the decisions the terminal already had** — a reason on both
  approve and deny, single-use, revoke, and a view of what has been decided.
- **The portal's approvals page was reachable for the first time.** The route
  existed, the renderer existed, and nothing joined them: navigating there fell
  through to the entries view and drew an empty scope while the badge counted
  requests waiting.
- **`byn approve` is laid out rather than written out** — a fixed label column,
  six documented colour roles, and `--history` as a table. `--json` is unchanged.
- **A stale grant no longer reports itself as corruption.** A capability holds the
  key that opened a row at grant time; a later `byn put` in a child env creates an
  override under a different key, and the AEAD failure looked exactly like real
  ciphertext damage. It now names the variable, says the value is intact, and
  gives the command that fixes it.
- **Shared tool-state files stop locking one identity out.** A tool that rewrites
  its own state file and chmods it `0600` — the AWS CLI does this to its SSO
  cache — discards whatever ACL it inherited. byn reconciles the declared
  `[exec] writable` directories before each privsep exec, and `byn repair` covers
  them too.
- **Trusting a large project no longer takes minutes.** `byn trust --recursive`
  over a monorepo took two to three minutes and runs after every `.byn` edit; the
  recursive `setfacl` only ever needed to run once, since a default ACL is
  inherited at creation. Measured on the same tree, the exec-time pass went from
  13.591s to 0.016s.

### Upgrade notes

- **No migration.** Existing vaults, trust records and grants are unchanged.
- **Scripts that polled `byn exec` to detect approval should move to
  `byn request watch`.** Branch on its exit status: `0` approved, `3` denied,
  expired, cancelled or revoked, `75` still pending. A script that treats
  "denied" and "not yet" alike will retry a refusal for ever.

---

## v0.5.5

**Headline:** installing byn now leaves you isolated — `byn setup` enables
privilege separation and asks for the password itself — plus single-use grants,
revocable grants, and a locked vault that accepts the password it asks for.

### What's new

- **`byn setup` enables privsep, not just provisions it.** It writes
  `[security] privsep = true` and restarts the daemon. Provisioning alone was
  never enough: `byn exec` asks the daemon whether privsep is on and the daemon
  answers from that key, so a machine could have the service user, the spawn
  helper and the ACLs all in place and still run every exec child at the owner's
  UID. An explicit setting is never overwritten, `privsep = false` included.
- **`byn setup` asks for the password itself.** Run without root on a terminal,
  it re-runs itself under sudo instead of telling you to retype the command —
  which after a `go install` would not have worked anyway, since byn lives
  outside sudo's `secure_path`. With no terminal it prints the command rather
  than hanging on a prompt nothing can answer.
- **`byn approve --once`** makes a grant single-use, spent the first time byn
  authorizes a run with it. One-shot scripts are what approvals are mostly used
  for, and the alternative was remembering to revoke afterwards.
- **`byn approve --revoke`** takes a grant back before it lapses, with no
  password: it can only remove capability. `--deny` on an already-approved
  request is now refused loudly instead of returning quietly while reprinting
  the grant line.
- **A locked vault accepts the master password for `get` and `put`.** `get`
  prompted for the password and then refused the read; `put` refused an
  authenticated write while accepting an unauthenticated one. The key is
  unwrapped for that one operation and zeroed after — a password authorizes a
  value, `byn unlock` authorizes a session.
- **Alias exec runs under privilege separation.** `byn exec <alias>` ran the
  child as you, so the ergonomic form was the unprotected one.
- **The approval history is readable.** Expired entries are dated from when they
  lapsed and say when they were asked; long commands collapse to one line in the
  list; and `byn approve` names `--history` whenever there is history behind it.

### Fixed

- Captured row keys bypassed the `.byn`'s own `[exec] env` list — the same
  mistake as the unattended-value bypass, at a second site.
- One undecryptable value aborted an entire exec, so a value the `.byn` never
  declared could stop every value it did.
- A declared name whose value exists but which the grant cannot open was
  reported as having no value, sending you to set it again when the fix is to
  re-trust.
- The portal's error toast collapsed to one word per line.
- `byn doctor` reports when several byn binaries disagree about the version.

### Upgrade notes (from v0.5.4)

- No schema change; vaults, trust records and audit logs are untouched.
- **Privilege separation gets enabled on upgrade** if you have never set
  `[security] privsep` either way — the packages re-run `byn setup`, which now
  writes the key and restarts the daemon. Exec children that ran at your UID
  will start running as `_byn-exec`. Set `privsep = false` first if you do not
  want that; setup will leave it alone.

---

## v0.5.4

**Headline:** `byn doctor` says when a newer byn is installed somewhere nothing
will run it.

### Fixed

- **An upgrade could install a byn that never runs, silently.**
  `go install …@latest` with no `GOBIN` puts the binary in `~/go/bin`, which is
  on no default PATH. So an older byn elsewhere kept answering, and
  `byn version` reported the old number immediately after a successful upgrade.

  Nothing was broken and nothing said anything — the install succeeded, and the
  wrong binary replied. Every observable was individually correct and the
  conclusion you would draw from them was wrong.

  `byn doctor` now lists every byn it can find with the version each reports,
  and fails when they disagree, naming which one PATH actually reaches. Copies
  at the same version pass quietly; a single install says nothing.

### Upgrade notes (from v0.5.3)

- No schema change; vaults, trust records and audit logs are untouched.
- Installing with the Go toolchain, point `GOBIN` at a directory already on your
  PATH, or `byn` will not be the byn you just installed:
  ```sh
  GOBIN=$HOME/.local/bin go install github.com/sandeepbaynes/byn/cmd/byn@latest
  GOBIN=$HOME/.local/bin go install github.com/sandeepbaynes/byn/cmd/byn-exec-helper@latest
  sudo $(which byn) setup
  ```
  `byn doctor` will tell you if you have more than one.

---

## v0.5.3

**Headline:** grants can be taken back, and a `.byn`'s `[exec] env` list is the
whole list.

### Fixed

- **A grant could not be taken back.** Once approved, a command stayed runnable
  until it expired — so a one-shot script approved for a single job sat
  executable for the rest of the window, and an owner who wanted it stopped had
  nothing to run. `byn approve --revoke <id>` takes the grant back. It needs no
  password, for the same reason `--deny` does not: it can only remove
  capability, and a revoke you have to find a credential for is one that happens
  later than it should. Audited as `approval.revoke`.
- **`--deny` on an already-approved request was a silent no-op.** It returned
  the existing record with exit 0 and reprinted the grant line — "approved …
  runs free for 5h53m" — so an owner who typed it to take a grant back believed
  they had, and was wrong about what was still runnable. It is now refused
  outright and names `--revoke`. Repeating the *same* decision stays idempotent:
  two surfaces agreeing is not a conflict.
- **`byn get` asked for the master password and then refused the read.**
  Supplying it authorized the action, but the value still needed the vault key
  in memory, so byn prompted, accepted the right password, and answered "vault
  is locked". A password now reads the value — the key is unwrapped for that one
  read and zeroed immediately after, so the vault stays locked. It authorizes a
  value, not a session: the next read without a credential is refused as before.

  Note the remaining asymmetry: `byn put` on a locked vault still requires
  `byn unlock`, and says so plainly rather than prompting first.
- **Captured row keys bypassed the `.byn`'s own `[exec] env` list.** When a
  `.byn` is trusted, its capability captures a key per variable. The loop that
  injects from those keys intersected against `rec.EnvAllowlist()`, which
  returns nil both for "this is a wildcard grant" and for "EnvGrants is empty" —
  and EnvGrants is not persisted, so it is empty on the ordinary call. A nil
  read as "inject everything" let every name captured at grant time through,
  past the list the file declares.

  This is the same mistake as the unattended-value bypass fixed in v0.5.0, at a
  second site. It is narrower — only names that already existed when the grant
  was made, not anything an agent stored later — and identical in kind. Both
  loops now read the trust record's MAC-bound snapshot, which says what the file
  declares whether or not anything has reconciled it.
- **One undecryptable value aborted the entire exec.** A captured entry that had
  since been re-sealed under another scheme — an unattended write, typically —
  returned a decryption error that failed the whole call. So a value the `.byn`
  never declared could stop every value it did declare from reaching the
  process, and the command did not run at all. Those entries are opened by the
  authored key on a path that has already run by then; the capability loop skips
  them now, and the vault reports "sealed under a different scheme" as its own
  condition rather than as prose inside a generic decryption failure.

### Upgrade notes (from v0.5.2)

- No schema change; vaults, trust records and audit logs are untouched.
- No re-trust needed. Both fixes are in how a capability is read, not in how it
  is written.

---

## v0.5.2

**Headline:** the fix for v0.5.1 — a byn installed outside a system directory
produced a service that could not start.

### Fixed

- **The service could not start when byn lived in a home directory.** v0.5.1
  linked byn into `/usr/local/bin` with a symlink and wrote the service unit
  pointing at wherever byn actually lived — which, for a `go install`, is inside
  your home. The daemon runs as the `_byn` service user, which cannot read
  there, so systemd failed at exec with `Permission denied` and the service
  flapped until it gave up: `sudo byn restart` reported success while
  `byn status` still said the daemon was down.

  byn is now **copied** into `/usr/local/bin` before the service is installed,
  and the unit points at that copy — a real file the service user can read. The
  spawn helper is copied alongside it, since the daemon execs that by absolute
  path too. The trade: a later `go install` needs `byn setup` re-run to take
  effect. The packages already do that on upgrade, and a stale binary is a
  smaller problem than a service that cannot start.
- **`sudo byn …` suggestions were unrunnable from a `go install`.** sudo
  resolves commands against `secure_path`, which never includes `~/go/bin` or
  `~/.local/bin`. So `sudo byn setup` answered `byn: command not found` — and
  the command being recommended was the one that fixes exactly that. byn now
  prints the absolute path whenever it is not somewhere sudo searches.

### Upgrade notes (from v0.5.1)

- No schema change; vaults, trust records and audit logs are untouched.
- If v0.5.1 left you with a service that will not start, re-running setup is the
  whole fix — it replaces the symlink with a copy and rewrites the unit:
  ```sh
  sudo $(which byn) setup
  ```

---

## v0.5.1

**Headline:** installing byn now installs byn — the packages and the install
script provision privilege separation while they are already elevated, instead
of leaving it to a second command nobody ran.

### What's new

- **Installs provision privilege separation.** The deb/rpm/apk packages and
  `install.sh` run `byn setup` as part of installing, which is why installing or
  upgrading now asks for your password. Privsep is what keeps an exec child's
  secrets out of your own `ps`; leaving it to a separate step meant every
  install was half an install. Upgrades re-run setup deliberately (the service
  unit and spawn helper change between releases); removal tears it down and
  never touches the vault; and an upgrade is told apart from a removal so it
  does not stop the daemon mid-flight. Provisioning failing never fails the
  install — byn still runs, and `byn doctor` says what is missing.
- **`byn setup` puts byn on the system PATH.** `go install` places binaries in
  `~/go/bin`, which is on no default PATH and outside sudo's `secure_path` — so
  the install produced a working binary that could be run as neither `byn` nor
  `sudo byn`. Setup, the first moment byn has root, links it into
  `/usr/local/bin`. A symlink, so a later `go install` is picked up without
  re-running setup.

### Fixed

- **byn could not be started on a machine it had been uninstalled from.**
  Provisioning was judged by whether the `_byn` accounts existed, and
  `byn uninstall` keeps those while removing the service, the helper and the
  owner record. byn therefore called such a machine provisioned, refused to run
  a daemon as you, and pointed at `sudo byn restart` for a unit that had been
  removed — a dead end reachable by following the documented uninstall. The
  three states are now told apart: nothing installed (`byn start`), service
  installed (`sudo byn restart`), and a data directory with no service
  (`sudo byn setup`).
- **`go install` produced a binary reporting version 0.0.1.** The version is
  stamped by the linker at release time and `go install` applies no such flags.
  byn now falls back to the module version Go embeds in the binary; a stamped
  build still wins, and a build from a working tree reports its commit and
  whether the tree was edited.

### Upgrade notes (from v0.5.0)

- No schema change. Vaults, trust records and audit logs are untouched.
- If you installed v0.5.0 with `go install`, install both binaries onto a
  directory already on your PATH and let setup finish the job:
  ```sh
  GOBIN=$HOME/.local/bin go install github.com/sandeepbaynes/byn/cmd/byn@latest
  GOBIN=$HOME/.local/bin go install github.com/sandeepbaynes/byn/cmd/byn-exec-helper@latest
  sudo byn setup
  ```
- Package users get provisioning automatically on upgrade; the password prompt
  during `apt`/`dnf` is expected.

---

## v0.5.0

**Headline:** byn stops needing a person in the middle of an agent's work — an
agent can create a secret, use it and keep working, without a human at a
terminal and without the vault being left open.

### What's new

- **`byn put` no longer needs an unlocked vault.** A scope has a second key,
  derived from the vault key and sealed into a trusted `.byn`'s capability under
  the machine key, so a locked daemon can store what a caller creates and give it
  back. It opens nothing that was already there. The honest cost: such a value is
  protected by that machine as well as by your master password — strictly less
  exposure than leaving the whole vault open.
- **A caller may read, replace and delete the values it created**, without a
  credential, for as long as its session lives and nobody else has written them.
  Another writer ends it at that moment and the ordinary rules resume. See
  `byn help unattended`.
- **A command the `.byn` does not pin raises a decision** — an id and exit 75 —
  instead of dead-ending at a password prompt no agent can answer. Approval cards
  say who asked and why, what approving actually does (it grants; it runs
  nothing), and how long the asker will wait. Grants are bound to the caller that
  asked; `byn approve --anyone` widens one deliberately, `--for` sets its window.
- **`byn runs`** records every command byn authorised: when, which `.byn` allowed
  it, the agent behind it, and which values it received — by reference, never a
  copy, stored as diffs. **`byn runs diff ID`** answers "has any of this been
  rotated since?" without printing a single value, needs no credential, and works
  while the vault is locked.
- **Values an agent invented are never hidden** — in the audit log, in
  `byn list --long`, in `byn doctor`, on the launch line, and on the run record.
  A project can refuse them with `[exec] agent_put = false` or by name with
  `agent_put_deny`.

### Upgrade notes (from v0.4.x)

Full procedure, rollback, and the behavior changes a script may notice:
**[Upgrading byn](upgrading.md#v04x--v050)**. In short:

- **`sudo byn setup` is required** for privsep installs — the systemd unit
  changed. The old one had `ProtectProc=invisible`, which hid your processes from
  the daemon, so the audit log recorded no caller name and the daemon could not
  tell which agent stored a value. Both failed silently; `byn doctor` now reports
  `daemon.sees_caller`.
- **Vault schema v4 → v8**, migrating on first open. Additive only, no secret is
  rewritten, and byn writes a verified `vault.db.v<N>.bak` snapshot beside the
  vault before it starts. Note that upgrading is a one-way door: an older byn
  refuses to open a newer vault, so that snapshot is your rollback.
- **Re-trust each project** to enable locked-vault writes there. Optional and
  self-healing — any write with the vault open re-seals the grant.
- **Two audit events changed shape**: an uncredentialed write is `put.unattended`
  rather than `put`, and raising an approval is `pending` rather than `denied`.
- **`byn delete --json` reports a refusal as exit 3**, not 1, matching every
  other command. Branch on the `--json` `status` field, not the exit code.

---

## v0.4.1

**Headline:** Linux/Fedora compatibility, macOS FDA status in `byn status`, and a cleaner portal config-auth flow.

### What's new

- **Linux/Fedora compatibility.** Four privsep setup fixes: `printf '%b'` in the
  provisioner so sysusers.d and the systemd unit are correctly multi-line (not
  one-liners with literal `\n`); `StateDirectoryMode=0711` so the CLI can
  traverse `/var/lib/byn` (was silently reporting "not running" after provisioning
  due to `EACCES`); `AF_INET`/`AF_INET6` in `RestrictAddressFamilies` so the web
  portal is reachable; `byn migrate` no longer errors with "no byn state
  artifacts" when run before `sudo byn setup` on a fresh install.
- **macOS Full Disk Access indicator.** On macOS with privsep active (daemon runs
  as `_byn`), `byn status` now shows an `fda:` line — `granted` when the daemon
  has Full Disk Access, or `NOT GRANTED` with a direct pointer to System Settings
  when it doesn't. Without FDA the daemon silently fails to read `.byn` files in
  `~/Documents`, `~/Desktop`, `~/Downloads`, or iCloud Drive; this makes that
  visible immediately. The line is absent on Linux or when privsep is off.
- **Portal config-auth error message.** Submitting an invalid or expired sudo
  token when saving settings now shows *"Invalid or expired token. Run
  `byn config-auth` in your terminal and try again."* instead of the raw
  `config_auth_required` error code. Cancelling the token dialog now silently
  restores the save button rather than showing an error.
- **`make uninstall` target.** Stops the daemon, reverses the privsep setup, and
  removes installed binaries (vault is preserved). Default install dir changed to
  `/usr/local/bin` (was `~/.local/bin` fallback).

### Upgrade notes (from v0.4.0)

- **No config or schema changes.** Existing vaults, audit logs, and privsep
  setups work as-is.
- **Linux privsep users:** if you provisioned before this release,
  `sudo byn doctor --repair` will apply the `StateDirectoryMode` and unit-file
  fixes; or re-run `sudo byn setup` (idempotent).
- **macOS privsep + Full Disk Access:** after upgrading, `byn status` will show
  `fda: NOT GRANTED` until you grant Full Disk Access to byn in
  System Settings → Privacy & Security → Full Disk Access, then `sudo byn restart`.

---

## v0.4.0

**Headline:** the audit log grows up — it self-heals after a crash, repairs
deliberately, and is fully readable (event numbers, server-side search, and
pagination that's reliable on a growing log) — plus a self-healing daemon
lifecycle that can't be bricked by `sudo`.

### What's new

- **The audit log is now a first-class, documented feature.** New
  [**Audit log** guide](audit.md) covers why the tamper-evident HMAC chain
  exists, what's recorded, the threat model, and every way to use it.
- **Self-healing audit chain + `byn audit reseal`.** A daemon crash/SIGTERM
  mid-write used to leave a permanent "chain broken at #N". Now the logger
  **reconciles its chain head from disk on restart**, so a clean crash repairs
  itself. For an existing break, `byn audit reseal` appends a **signed bridge
  marker** that *acknowledges* the gap (records the break, a reason, and
  who/when) **without rewriting any historical hash** — so a benign gap and a
  real tamper stay distinguishable. `byn doctor` then reads the chain as intact
  (with the acknowledged reseal).
- **Event numbers, search, and reliable pagination.** Every audit row (CLI,
  TUI, web) is prefixed with its **`#N` chain index** — the same number `verify`
  and `reseal` report. Filter the whole log **server-side** with
  `--byn` / `--caller` / `--scope` (also `/` in the TUI and the portal's filter
  bar). Paginate by the **stable `#N` index, never a positional offset** (which a
  growing log would shift): `--since N` streams new events for a program to
  consume; `--before N` pages back. The portal gets a **Load older** button; the
  TUI gets `]`/`[` page navigation. `byn audit view --lines 0` now streams the
  entire log instead of failing on a large dump.
- **Self-healing daemon lifecycle (privsep).** `byn` now refuses to run owner
  commands as `sudo`/root with a clear message instead of a cryptic peer error;
  `byn setup` and the service (re)load are race-free and idempotent (no more
  "Bootstrap failed: 5"); `byn doctor` runs even when the daemon is **down** and
  `sudo byn doctor --repair` heals provisioning/ownership/launchd state; and
  `start`/`stop`/`restart` are privsep-aware (the daemon is the `_byn` service).
  `BYN_ALLOW_ROOT=1` is the escape hatch for root-only containers.
- **Portal polish.** Persistent, stackable error toasts (close to dismiss);
  the studio/settings editor surfaces the full config (incl. `[security]`) and
  `[exec] writable`; the file pickers start from your home, not the daemon's;
  and macOS Full-Disk-Access read denials now surface an actionable error.

### Upgrade notes (from v0.3.1)

- **No config or schema changes.** Existing vaults and audit logs are read as-is.
- **Audit pagination changed shape, for the better.** A program that consumed
  the log by positional offset should switch to **`--since <max #N seen>`** —
  it's reliable as the log grows. Interactive use is unchanged (`tail`, `view`,
  `-f` follow all still show the most recent events).
- **A pre-existing audit break** (from forced restarts before this release) will
  still show as broken until you acknowledge it once with
  `byn audit reseal` (requires the vault unlocked). New crashes self-heal.
- **Privsep is still opt-in** via `[security] privsep` + `sudo byn setup`;
  nothing changes for non-privsep installs.

---

## v0.3.1

**Headline:** privsep `byn exec` now works in protected dirs (macOS `~/Documents`
et al.) by inheriting your shell's access, plus debug modes and automatic
toolchain access for the exec child.

### What's new

- **Terminal-anchored privsep exec.** With `[security] privsep` on, a trusted-`.byn`
  `byn exec` now spawns the child in your shell's process tree (then drops it to
  `_byn-exec`), so on macOS it inherits your shell's Full Disk Access / TCC grant —
  `byn exec` runs in `~/Documents`, `~/Desktop`, iCloud, etc., while the injected env
  stays hidden from same-UID snooping (`ps -E` on macOS, `/proc/<pid>/environ` on
  Linux). Secrets reach the child via a one-time token the privileged helper redeems
  from the daemon; the owner-UID CLI never sees them.
- **Debug modes for `byn exec`** (see [CLI reference](cli-reference.md#execution-modes--privsep-default---no-privsep---inspect)):
  - `--no-privsep` runs the child **as you** (so a launch-mode debugger can attach) and
    **requires the master password every run** — no blind trusted-file run, since the env
    is then visible to any same-UID process (`ps -E` / `/proc/<pid>/environ`).
  - `--inspect[=PORT]` (and `--inspect <PORT>` / `--inspect-brk`) keeps privsep and enables
    the Node inspector for **attach-mode** debugging over loopback TCP; with no port byn
    picks a free one, an explicit busy port fails clearly, and `--inspect=0` lets each
    process self-allocate (e.g. `tsx watch`).
- **Automatic toolchain access for the exec child.** Because the child runs as `_byn-exec`,
  `byn trust` now grants it read/write on a curated set of common tool-state dirs that
  exist (`~/.cache`, `~/.npm`, `~/Library/pnpm`, `~/.cargo`, `~/.rustup`, `~/go`, …), plus
  any extra dirs a `.byn` declares in the new **`[exec] writable`** list (see
  [.byn file format](byn-file-format.md)). The child's `TMPDIR` is normalized to a writable
  location automatically.

### Upgrade notes (from v0.3.0)

- **No config or schema changes.** Privsep is still opt-in via `[security] privsep`,
  still provisioned with `sudo byn setup` — nothing changes unless you have privsep on.
- **macOS Full Disk Access:** for the daemon to read a `.byn` under `~/Documents`/iCloud
  it still needs FDA (re-grant after a rebuild while unsigned). The exec **child** no
  longer needs its own FDA — it inherits the shell's. See [Troubleshooting](troubleshooting.md#running-byn-exec-under-privsep-toolchain-tmpdir-debugging).

---

## v0.3.0

**Headline:** opt-in privilege separation, a fixed system data root with
first-class provisioning/migration, and a generated docs site.

### What's new

- **Opt-in privilege separation (NU-5/6).** The daemon can run as a
  dedicated `_byn` service user, and trusted-pinned `byn exec` children
  drop to a separate `_byn-exec` user — a three-UID model (you ≠ `_byn` ≠
  `_byn-exec`) so a same-UID process can no longer ptrace the daemon or
  read an injected child's environ without root. **Off by default.**
  Provision with `sudo byn setup`, then enable with `[security] privsep =
  true` and restart the daemon. Honest ceiling: it raises the bar to root,
  it does not defend against root.
- **Fixed per-OS system data root + provisioning.** `byn setup` provisions
  the service users, installs the privileged spawn helper and the system
  service, and relocates a legacy `~/.byn` into the system path
  (`/Library/Application Support/byn` on macOS, `/var/lib/byn` on Linux).
  `byn migrate` relocates an existing `~/.byn` or imports an external
  vault. See [Migration & setup](migration.md).
- **Generated docs site.** The docs now publish to GitHub Pages from the
  markdown via `make site`; added the **[field notes](field-notes/)**
  (threat briefings) and **[why not containers](why-not-containers.md)**.

### Upgrade notes (from v0.2.0)

- **Schema migrates automatically.** The vault schema moves from v3 to v4
  on first open — no action needed; it is applied in place.
- **The data-root override environment variable was removed.** If you
  relied on it to point byn at a non-default directory, it is now ignored:
  byn uses `~/.byn` by default, or the system path once provisioned. Move
  your data with `byn migrate` if needed.
- **Privilege separation is opt-in — nothing changes unless you turn it
  on.** Existing installs keep running exactly as before at your own UID.
  To adopt privsep: `sudo byn setup` (one sudo prompt, idempotent), then
  set `[security] privsep = true`. Reverse with `sudo byn setup
  --uninstall` (add `--purge` to also delete the relocated vault).

---

## v0.2.0

**Headline:** no universal unlock (NU-1…NU-3) and the browser portal `.byn`
studio.

### What's new

- **No universal unlock (per-terminal sessions).** An unlocked vault no
  longer grants every same-UID process access. Each terminal, TUI, or
  portal session authenticates independently; sensitive operations require
  a live session or fresh authorization even while the vault is unlocked.
- **Browser portal `.byn` studio** for viewing/editing scopes and entries,
  with passkey / Touch ID unlock (WebAuthn PRF).

### Upgrade notes (from v0.1.0)

- **`byn unlock` is now per-terminal.** Unlocking in terminal A does not
  unlock for terminal B or background scripts — run `byn unlock` once per
  terminal, or supply `--password-stdin` in scripts. See the NU-3 section
  of the [Security model](security.md).
- **The `[security] per_action_auth` config key was removed.** If your
  `~/.byn/config` contains it, delete it — the strict parser rejects the
  whole config otherwise, and the daemon will refuse to start.

---

## v0.1.0

Early development release: the encrypted multi-vault store, the
daemon ↔ thin-CLI architecture over a Unix socket, the
`vault → project → env` scope hierarchy, and core env-var CRUD + `byn
exec` injection.

---

## v0.0.1

First public release.
