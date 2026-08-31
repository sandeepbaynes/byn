# Upgrading byn

How to move from one version of byn to the next without losing anything, and
how to go back if you need to.

For what changed in each release, see [release notes](releases.md). For first
time privsep provisioning and moving a legacy `~/.byn` to its provisioned home,
see the [migration & setup guide](migration.md) — that is a different job from
this one.

---

## The short version

```sh
# 1. Replace the binary (whichever way you installed it)
sudo dnf upgrade byn        # or: apt upgrade byn / apk upgrade byn
brew upgrade byn            # Homebrew
sudo make install           # from source

# 2. Re-run setup if you use privilege separation. Idempotent, and the
#    systemd unit or LaunchDaemon can change between releases.
sudo byn setup

# 3. Restart the daemon so the new binary is actually the one running
sudo byn restart

# 4. Check what you are running, and that your vaults opened
byn version
byn status
byn doctor
```

Your vault upgrades itself the first time the new daemon opens it. There is no
migration command to run for it.

---

## Before you upgrade: this is a one-way door

A newer byn opens an older vault and upgrades it. **An older byn refuses to open
a newer vault** — it stops rather than guessing, with:

```
vault: unknown schema version: on-disk version 8 > supported 6 (downgrade?)
```

That is deliberate: an old binary that tried to read a newer vault would be
reading a format it does not know, and the failure mode for that is corruption
rather than an error message. So downgrading is not a matter of reinstalling the
old version — you need the pre-upgrade vault back.

**byn takes that backup for you.** Before the first migration step runs, it
writes a verified snapshot next to the vault:

```
<vault dir>/vault.db.v<schema version it is upgrading from>.bak
```

So a v0.4.x vault, which is schema v4, leaves `vault.db.v4.bak` behind.

Three details worth knowing, because they are what makes it a backup rather than
a copy of a file:

- It is written with SQLite's own `VACUUM INTO`, not `cp`. Copying a live SQLite
  database mid-checkpoint can produce a torn file that looks fine until the day
  you need it.
- byn reopens the snapshot and runs `PRAGMA integrity_check` on it **before**
  touching the original. A backup nobody checked is not a backup.
- It is mode `0600`, and it contains your secrets in exactly the same encrypted
  form the vault does. Do not copy it somewhere less protected than the vault
  itself. Delete it once you are confident in the upgrade.

If you would rather take your own snapshot as well, stop the daemon first and
copy the whole vault directory. A stopped daemon has no open WAL.

### Where the files are

| Install | Vault directory |
|---|---|
| Privilege separation (`byn setup` run) | `/var/lib/byn/vaults/<vault>/` |
| Legacy / no privsep | `~/.byn/vaults/<vault>/` |

Under privilege separation these are owned by the `_byn` service user, so you
need `sudo` to list or copy them. That is the point of privsep, not a problem to
work around.

---

## Verifying the upgrade

```sh
byn version     # the version you meant to install
byn status      # daemon running, and its version
byn doctor      # every vault opened, schema ok, audit chain intact
```

`byn doctor` is the one that matters. It opens each vault — which is when
migration happens — and reports the schema and the audit chain per vault:

```
[  OK   ] vault[default].open      schema + fingerprint ok
[  OK   ] vault[default].audit     245 events, chain intact
```

**Check the uptime in `byn status`.** If it shows hours when you restarted a
moment ago, the restart did not take and you are testing the old daemon against
the new CLI. This is worth stating because it has caught us: the symptom is a
new feature appearing to be missing, and the cause is that the code implementing
it is not running. `byn status` says so whenever the running daemon is not the byn
you have installed:

```
stale:    the daemon is running 0.4.1-73-g25345aa but this byn is 0.5.0 — restart
          to pick up the installed one:
          sudo byn restart
```

---

## Rolling back

```sh
sudo byn stop

# Restore the snapshot byn took before migrating, per vault.
# The number is the schema version you came FROM — v0.4.x vaults are v4, so
# the file is vault.db.v4.bak. Check with: sudo ls /var/lib/byn/vaults/default/
sudo cp /var/lib/byn/vaults/default/vault.db.v4.bak \
        /var/lib/byn/vaults/default/vault.db
sudo chown _byn:_byn /var/lib/byn/vaults/default/vault.db
sudo chmod 600 /var/lib/byn/vaults/default/vault.db

# Reinstall the previous byn, then
sudo byn setup      # the old version's unit
sudo byn start
byn doctor
```

Anything written after the upgrade is not in that snapshot — it is a picture of
the vault at the moment before migration. Values you stored since, and audit
events recorded since, are in the newer file. If those matter, keep the newer
`vault.db` somewhere safe before overwriting it, rather than discarding it.

### If a migration is interrupted

Nothing needs doing beyond opening the vault again — `byn doctor` will do it.
Each step records its own version as it completes, so a migration that stops
half way resumes from where it stopped rather than restarting or double
applying. The snapshot is taken once and is not overwritten by a second attempt.

---

## v0.4.x → v0.5.0

The full list is in the [release notes](releases.md#v050) and
[CHANGELOG](../CHANGELOG.md). This is the operational part.

### Steps

1. **Replace the binary.**
2. **`sudo byn setup`.** Required, not optional, if you use privilege
   separation. The systemd unit changed: the old one had
   `ProtectProc=invisible`, which hid your processes from the daemon, so the
   audit log recorded no caller name for anything done over the socket and the
   daemon could not tell which agent stored a value. Both failed silently.
   `byn doctor` now reports `daemon.sees_caller`.
3. **`sudo byn restart`.**
4. **Re-trust each project** (`byn trust`, or whatever your repo wraps it in) if
   you want `byn put` to work on a *locked* vault there straight away.

Step 4 is the only one you can skip indefinitely. Grants made by an older byn
carry no key byn may write with, and only the locked path needs one — creating a
value on an unlocked vault was never gated and still is not. You can also just
use byn: storing any value in that scope with the vault open re-seals the grant,
including an ordinary `put` of your own. Either way it is logged as
`trust.authored_key`.

### The vault

Schema v4 → v8, in one open. Every step is additive — new tables and columns —
and no secret is rewritten: existing entries keep the scheme they were written
under and stay readable. v5 adds the per-entry ordering columns, v6 the exec-run
tables, v7 the agent's name on a run record, v8 which of a run's values were
stored unattended.

### Changes a script or an agent may notice

- **A command the `.byn` does not pin no longer dead-ends.** It raises a
  decision and exits **75** with an approval id, where it used to fail at a
  password prompt no agent could answer. A caller that treats any non-zero exit
  as fatal will now stop on something that is waiting for a human rather than
  broken. `byn exec --wait-approval` blocks instead, if that suits the caller
  better.
- **`byn delete --json` reports a refusal as exit 3**, not 1. Every other
  command already used 3 for a refusal, and 1 is what byn uses for bad usage —
  so a caller branching on the code was previously told its arguments were wrong
  when it had been refused authorization. Branch on the `--json` `status` field
  rather than the exit code: it separates `not_found` from `auth_required`.
- **Two audit events changed shape.** A write with no credential behind it is
  logged as `put.unattended` rather than `put`, and raising an approval is
  `pending` rather than `denied` — nothing was refused by asking, and the two
  were indistinguishable before. Anything parsing the audit log needs to know
  both.
- **New verbs**, none of which change existing behavior: `byn runs`,
  `byn runs diff`, `byn approve --for` / `--anyone`, `byn exec --reason`
  (also `--why`, or `BYN_WHY` in the environment for harnesses that cannot add
  a flag).

### What happens if you skip a step

Everything fails closed. Skipping `byn setup` leaves the old unit running, so
caller attribution stays blank and `byn doctor` says so. Skipping the re-trust
leaves locked-vault writes unavailable in that project, and byn says which
project and why when a caller tries. Nothing silently does the wrong thing, and
no feature half-works — it stays dormant until the step that enables it is run.
