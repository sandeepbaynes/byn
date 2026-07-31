# Agent field notes: using byn v1 as a non-interactive agent

Recorded 2026-07-30 by driving byn from a non-TTY shell against a throwaway
`agenttest` vault, byn 0.4.1-5-g992da8e, privsep on, Fedora 44.

The point of this log is that everything below was hit *while trying to do
ordinary work*, not while hunting for bugs.

## Status

Items 4–8 are **fixed** in commit `8b9efa5`; each is marked inline below.
Items 1–3 and the build-artifact trap are architectural and are what byn v2
exists to solve — see the plan.

**Verifying the fixes needs the new binary installed**, because the action
resolution runs daemon-side:

```sh
sudo make install && sudo systemctl restart byn.service
cd testbed && printf '%s' "$(cat TEST-VAULT-PASSWORD)" | byn trust --password-stdin .
byn exec -- ./build.sh      # must run; before the fix: "command not pinned"
```

`testbed/.byn` deliberately pins only relative paths, so it fails against an
old daemon and passes against a fixed one.

## Blockers that stop an agent dead

### 1. One `.byn` edit blocks every command in the project
Adding a variable to `[exec] env` did not just block that variable — every
previously-working command in the project began failing with "has CHANGED
since you trusted it". The dev loop stops entirely until a human types the
master password. For an agent this is unrecoverable: it cannot answer the
prompt, and it cannot proceed without it.

### 2. `touch .byn` alone invalidates trust
Content byte-identical, only mtime changed → same total block. byn's own diff
says `content identical; modification time changed (touch?)`. Every
`git checkout` / branch switch rewrites mtimes, so ordinary VCS operations
brick trusted exec.

### 3. No TTY means no session, so writes fail even after a successful unlock
`byn unlock --password-stdin` succeeds, the vault reports `unlocked`, and
`put` still fails with "run `byn unlock` to start a session". Sessions are
TTY-bound; an agent never gets one. Every write needs `--password-stdin`
re-authentication, so the agent must hold the master password to work at all
— which is exactly the credential the design does not want ambient.

## Bugs (not just friction)

### 4. Flags placed after positional args are swallowed as positionals — FIXED
- `byn trust . --password-stdin` → tries to trust a file literally named
  `--password-stdin`.
- `byn put NAME --password-stdin` → treats `--password-stdin` as the secret
  *value* and aborts with "That value is now in your shell history."

**The second form is byn's own documented example** (`byn help put`:
`{ echo "$BYN_PW"; printf 'new-val'; } | byn put key --password-stdin`).
Following the manual verbatim fails, and the error blames the user for a
security mistake they did not make. Flags must precede positionals.

### 5. Relative-path `[exec] actions` silently never match under privsep — FIXED
`.byn` pinned `./build.sh`; `byn exec -- ./build.sh` was refused with
"command not pinned". `cmd/byn/cmd_exec.go:551` rewrites `childArgv[0]` to an
absolute path before the daemon matches actions, so the pattern the user
wrote can never match. Only after adding the absolute path did it run. The
docs' own examples are relative-looking, and nothing warns at trust time that
a pinned action is unmatchable.

### 6. Alias exec silently bypasses privsep — WARNS NOW (full fix deferred to v2)
`byn exec build` (alias → `./build.sh`) ran as **uid 1000**, the real user.
The identical script via `byn exec -- <abs>/build.sh` ran as **uid 962**
(`_byn-exec`). Aliases take the legacy in-process path
(`cmd/byn/cmd_exec.go:206`, "Direct exec only for v1"). So the more ergonomic
form is the unprotected one, with no warning — and because relative-path
actions fail to match (#5), aliases are exactly what a frustrated user
reaches for.

### 7. The remediation command byn prints rejects the argument style byn accepts — FIXED
The error says to run `byn trust diff <path>`. `byn trust diff .` answers
"is not trusted" and suggests `byn trust <dir>` — while `byn trust .` accepts
a directory fine. Only `byn trust diff ./.byn` works.

### 8. `byn vault init help` requires a terminal — FIXED
Asking for help fails with `auth: not a terminal`. Documentation should never
need authentication.

## The build-artifact trap, reproduced in two commands

`byn exec -- ./build.sh` created `.next/` and `node_modules/.vite/` owned by
`_byn-exec`. As the invoking user: `rm -rf .next` → **Permission denied**. The
agent cannot clean its own build output, cannot sudo, and `byn doctor --repair`
needs root.

The only escape is the workaround this project already knows: write a
`clean.sh`, pin it in `[exec] actions`, re-trust (master password), and run
the delete *through* byn as `_byn-exec`. That is four steps and a human
password prompt to delete a cache directory.

## What actually works well (do not regress these in v2)

- **Locked-vault exec.** With the vault fully locked, trusted exec still
  injected secrets and ran. Post-restart autonomy already works.
- **Value updates need no re-trust.** Changing `TESTBED_DB_URL` propagated to
  the next exec with the vault locked and no re-trust. The belief that value
  edits force re-trusting is wrong — the real trigger is a `.byn` *policy*
  change (or the now-fixed default-env inheritance bug).
- **Secrets never touch argv.** `put` refuses command-line values outright.
- **The trust diff itself is good** — it shows a real semantic diff and
  correctly identifies the touch-only case. It is just not wired into
  anything that could act on it automatically.

## What this says about the v2 plan

Confirms, with direct evidence:
- Trust must key on *policy content*, not bytes+mtime (#1, #2).
- Approvals must be non-blocking and out-of-band (#1, #3) — the agent needs a
  path that is not "hold the master password".
- Files created by the exec identity must be owned by the user (build trap).
- Degradation and bypass must be loud (#6): the ergonomic path silently
  dropped the entire security property.

Adds requirements the plan did not have:
- **Validate pinned actions at trust time.** If a pattern can never match
  because of path resolution, say so while the human is already present.
- **Fix flag parsing before anything else** (#4) — the documented
  non-interactive path is broken, which alone explains a lot of agent pain.
- **Aliases must not be a security downgrade** — same enforcement on every
  exec route, or refuse the route.
