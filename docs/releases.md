# Release notes

What changed in each byn release — headline changes, upgrade/migration
notes, and any specific instructions. Newest first.

Downloadable binaries and per-release assets live on the
[GitHub releases page](https://github.com/sandeepbaynes/byn/releases).
This page is the curated changelog; the GitHub page is the artifacts.

> byn is pre-1.0. Until 1.0, minor versions may include behavior changes —
> each one is called out under **Upgrade notes** below.

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
  stays hidden from your own `ps -E`. Secrets reach the child via a one-time token the
  privileged helper redeems from the daemon; the owner-UID CLI never sees them.
- **Debug modes for `byn exec`** (see [CLI reference](cli-reference.md#execution-modes--privsep-default---no-privsep---inspect)):
  - `--no-privsep` runs the child **as you** (so a launch-mode debugger can attach) and
    **requires the master password every run** — no blind trusted-file run, since the env
    is then visible to your `ps -E`.
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
