# Release notes

What changed in each byn release — headline changes, upgrade/migration
notes, and any specific instructions. Newest first.

Downloadable binaries and per-release assets live on the
[GitHub releases page](https://github.com/sandeepbaynes/byn/releases).
This page is the curated changelog; the GitHub page is the artifacts.

> byn is pre-1.0. Until 1.0, minor versions may include behavior changes —
> each one is called out under **Upgrade notes** below.

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
