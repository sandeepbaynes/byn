# Migration & setup guide

How byn provisions privilege separation, moves your vault to its new home, and
what changes when you upgrade. This covers the **opt-in** three-UID model — see
[Security model → privilege separation](security.md#privilege-separation-the-three-uid-model-opt-in-nu-56)
for the threat reasoning and the honest ceiling.

> **Privsep is opt-in this release and off by default.** Nothing here happens
> until you choose to enable it (`[security] privsep = true`) and run
> `byn setup`. If you do nothing, byn keeps running exactly as before: the daemon
> at your own UID, state under `~/.byn`.

---

## TL;DR

```sh
# 1. Provision the service accounts + system service (one sudo prompt).
sudo byn setup

# 2. Turn privsep on in the config and restart the daemon.
#    Add `privsep = true` under [security] in the byn config, then:
byn daemon stop && byn daemon start
```

`byn setup` is idempotent and safe to re-run on every install and upgrade. If you
had a legacy `~/.byn`, setup relocates it for you (step 3 below) and keeps your
trust + passkeys, because it is the same machine.

---

## One sudo, on purpose

Privilege separation needs root **once**: creating the `_byn` and `_byn-exec`
service accounts and installing a system service (a systemd system unit on Linux,
a LaunchDaemon on macOS) cannot happen without it. `byn setup` is the single
command that does this. There is no way to make the elevation disappear — the
design makes it happen at the right moment, behind one `sudo`, rather than as a
scattered manual chore.

Run setup **via sudo**, not as real root:

```sh
sudo byn setup
```

`byn setup` reads `SUDO_UID` to learn **who the owner is** — the human who ran
sudo. That UID is recorded as the single identity the daemon allowlists on its
peercred-gated socket. Running as real root (e.g. a root shell, no sudo) **fails
on purpose**, rather than recording root as the owner.

What `byn setup` does, in order:

1. Creates the `_byn` and `_byn-exec` service accounts and installs the prebuilt
   privileged spawn helper (`byn-exec-helper`) + its root-owned config.
2. Installs and loads the system service that runs the daemon as `_byn` — **not**
   you.
3. Relocates any legacy `~/.byn` into the fixed system data path (see below),
   chowned to `_byn`. Skipped on a fresh install.
4. Records your owner UID (from `SUDO_UID`).
5. Verifies the result.

It **provisions** privsep; it does not **enable** it. Engage it with
`[security] privsep = true` in the config and a **daemon restart**. With privsep
enabled but **not** provisioned, the daemon warns and trusted-`.byn` exec **fails
closed** — it never silently falls back to running as your UID. (`byn exec
--no-privsep` is a per-call escape hatch — not a setup-time opt-out — that forces
the legacy in-process path for a single exec, running that child at your UID
instead of `_byn-exec`, so the same-UID ptrace / env-read weaknesses apply for
that command.)

To reverse setup: `sudo byn setup --uninstall` removes the service, helper, and
owner record but **leaves your vault intact**. Add `--purge` to also delete the
system data dir and every secret in it — destructive, irreversible, and gated
behind a typed `yes` confirmation. The vault is **never** removed without
`--purge`.

---

## Where your data lives now

| State | Provisioned (privsep on) | Unprovisioned (default) |
|---|---|---|
| Data root (Linux) | `/var/lib/byn`, owned `_byn`, `0700` | `~/.byn`, owned by you, `0700` |
| Data root (macOS) | `/Library/Application Support/byn`, owned `_byn`, `0700` | `~/.byn`, owned by you, `0700` |
| Socket | owner-traversable runtime path (so you can connect) | `<data root>/daemon.sock` |

The directory layout *inside* the root (`vaults/<name>/`, `audit/`,
`trusted_byn.json`, `config`, …) is identical either way — only the location and
owning UID change. See [File layout](file-layout.md) for the full tree.

---

## `byn migrate` — relocate vs import

`byn setup` calls migrate for you on upgrade, but you can run it directly. There
are two modes, and the difference matters for your trust + passkeys.

`byn migrate` always **verifies the source without its password** before adopting
anything: every `vault.db` must open as a well-formed, correctly-versioned vault
whose `wrapped.key`/`meta.json` fingerprint matches and whose audit chain is
intact. A malformed, truncated, or tampered source is **rejected** and the
destination is left untouched. The adopt is atomic and re-runnable — it never
half-migrates. It never *unlocks* the vault; the ciphertext stays gated by its
own password.

Both modes require root and an existing `_byn` account (run `byn setup` first —
migrate adopts with the correct ownership; it does not create users).

### Relocate (the legacy upgrade) — keeps trust + passkeys

```sh
sudo byn migrate          # no --from
```

Moves the legacy `~/.byn` into the system path. Because this is the **same
machine**, your trust store and passkey enrollments are **kept**. The old
`~/.byn` is removed only **after** the destination is fully adopted.

### Import (from anywhere) — drops trust + passkeys

```sh
sudo byn migrate --from /path/to/some/byn-vault          # add --force to overwrite
```

Copies an external vault tree in (a backup, a mounted disk, a synced dir) and
**never deletes the source**. A non-empty destination is refused unless you pass
`--force`.

An import brings vault **data only**. It **drops the trust store and passkey
enrollments**. Afterwards you **must**:

- re-trust your `.byn` files with `byn trust`, and
- re-enroll your passkeys on this machine.

**Why trust + passkeys are dropped on import.** Trust is never silently carried
across a machine boundary. A `.byn` trust fingerprint binds the **machine
identity and the file's path** — so a trust record carried in from another
machine would fail verification here anyway. Dropping it is both the safe choice
(you don't unknowingly adopt grants or unlock credentials someone else chose) and
the consistent one. Same-machine *relocate* keeps them precisely because the
machine and paths are unchanged.

---

## Upgrade note: the data-root override is gone

The environment variable that older byn versions used to repoint the data root
has been **removed**. A runtime-settable data root meant every code path had to
defend against a repointed or poisoned directory, and a process that could set
the env of a `byn` invocation could aim it at a vault it controlled — attack
surface byn no longer carries.

What this means for you:

- **The data root is fixed.** It is the per-OS system path once provisioned
  (`byn setup`), or `~/.byn` when unprovisioned. There is no override.
- **"Work vs personal" is multiple vaults, not multiple dirs.** byn has always
  been multi-vault — use `byn init <name>` / `byn vault …` and scope your work
  with vaults (and projects/envs), all served by the one daemon. The
  multiple-data-dirs pattern is gone, not deferred.
- **Scripts that set the old data-root variable should drop it.** A production
  `byn` ignores it. (The test suite isolates a tempdir via a `byntest`-build-tag
  seam that is never compiled into a release binary, so it is not a runtime
  surface. It is for byn's own tests, not for use.)

---

## Related

- [CLI reference](cli-reference.md) — `byn setup`, `byn migrate`, every flag.
- [Security model](security.md) — the three-UID model + the honest ceiling.
- [File layout](file-layout.md) — the data-root tree and modes.
- `man byn` — the authoritative command reference (`byn-setup(1)`,
  `byn-migrate(1)`).
