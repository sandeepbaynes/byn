# Troubleshooting

Common error states and how to recover from them.

If something here is wrong or out of date, the source of truth is
`internal/daemon/dispatch.go` (the per-op error codes) and
`internal/vault/store.go` (sentinel errors).

---

## "daemon is not running" (exit 2)

```
$ byn list
Error: daemon is not running
Try: byn daemon start
```

The CLI couldn't reach `~/.byn/daemon.sock`. Either the daemon
hasn't been started or it crashed.

**Fix:**

```sh
byn daemon start
```

**If it won't start:**

- Check `~/.byn/daemon.log` for the previous run's exit reason.
- Look for a stale pidfile: `cat ~/.byn/daemon.pid` then
  `ps -p <PID>`. The daemon detects stale pidfiles automatically
  (signal-0 probe), but if `daemon.sock` is a stranded file from a
  crash, `rm ~/.byn/daemon.sock` and retry.
- On macOS, `sun_path` is 104 bytes — the daemon's socket path must fit within
  it. byn's fixed data-root paths are chosen to fit; this only bites if you point
  a test build at a long directory via the `BYN_TEST_DIR` seam.

---

## "vault is locked" (exit 3)

```
$ byn get DB_URL
Error: vault is locked [locked]; byn unlock
```

The daemon is up; the vault key isn't in memory.

**Fix:**

```sh
byn unlock
```

If you wanted to do something that *doesn't* need the value (list
keys, delete by name, rename), you can — those are allowed while
locked.

---

## "wrong password" (exit 3)

```
$ byn unlock
Error: could not unlock vault [wrong_password]; verify password and retry
```

The Argon2id unwrap produced bytes that failed the AEAD auth tag.
Either you mistyped, or your `wrapped.key` is corrupted/swapped.

**Fix:**

- Re-try the password.
- If it persists, run `byn doctor`. If `vault[X].open` fails with a
  fingerprint mismatch, restore `wrapped.key` from backup.
- If you've genuinely forgotten the password: there is **no
  recovery**. The vault key is unrecoverable. `rm -rf ~/.byn/vaults/<name>`
  and re-init.

This message is the same whether the password is wrong or the vault
doesn't exist — by design (existence-oracle defense).

---

## "rate limited" (exit 3)

```
$ byn unlock
Error: too many failed attempts; retry after 5m [rate_limited]
```

The persistent failed-unlock backoff is active. State lives in
`~/.byn/auth-state.json`. Restarting the daemon doesn't reset it.

**Fix:** wait.

If you genuinely need to reset (e.g., you mistyped 6 times and don't
want to wait): `rm ~/.byn/auth-state.json`. Note that an attacker
who can do this also has write access to `~/.byn/`, which is its
own larger problem.

---

## "audit chain BROKEN at event #N" (exit 3)

```
$ byn audit verify
FAIL: audit chain BROKEN at event #42 (of 117)
  someone or something modified or truncated the log on disk
  inspect ~/.byn/audit/<vault>/*.log and treat the vault as compromised
```

The on-disk audit log has been tampered with or truncated.

**What this means:** at event #42, the recorded `hmac_chain` doesn't
match the expected chain. Could be:

- An attacker modifying or deleting log entries to cover their tracks
- A botched manual edit
- Disk corruption (rare)

**Fix:**

1. Stop the daemon: `byn daemon stop`.
2. Copy the log files for forensics: `cp -a ~/.byn/audit/ /safe/backup/`.
3. Inspect the logs manually around event #42.
4. Treat the vault as compromised: rotate secrets, re-issue tokens
   that lived in it.
5. After rotation, you can recover by deleting the log files (the
   daemon will re-seed). **You lose history.** Tampering already
   destroyed it.

---

## "untrusted .byn"

```
$ byn list
Error: /Users/you/proj/.byn: untrusted .byn; run `byn trust /Users/you/proj/.byn` to allow it
```

The CLI walked up from CWD, found a `.byn`, and either:

- Hasn't seen it before, AND stdin isn't a TTY (so it can't prompt)
- Has seen it before, but the SHA-256 has changed (tampering or edit)
- You're in agent mode (`--json` set) which never prompts

**Fix:**

If you want this scope:
```sh
byn trust /Users/you/proj/.byn
```

If you don't, but you're trying to run something:
```sh
byn --no-discovery <your command>
```

If you opened the file, edited it, and re-trust it:
```sh
byn trust /Users/you/proj/.byn   # re-records the new hash
```

See [`.byn` file format](byn-file-format.md) for the full TOFU
model.

---

## "name already exists"

```
$ echo new | byn put DB_URL --create-only
Error: secret already exists [already_exists]
```

`--create-only` refuses to overwrite. Without `--create-only`, `put`
overwrites silently.

**Fix:** drop `--create-only`, or delete the existing entry first.

---

## "fingerprint mismatch" (during `doctor` or open)

The wrapped key's fingerprint stored in `meta.json` doesn't match
the actual `wrapped.key` file's hash.

**What this means:** someone (or some process) replaced the wrapped
key with a different one. The replacement could be:

- An attacker swapping in a wrapped key they control
- A botched restore that copied only `wrapped.key` but not
  `meta.json`
- Accidental overwrite

**Fix:**

- If you restored from backup: also restore `meta.json` from the same
  backup.
- If you swapped vaults: copy the matching `meta.json`.
- If you're not sure: treat as compromised.

---

## `byn` not found after running `make build`

The binary is at `bin/byn`, not on PATH.

**Fix one of:**

```sh
# Symlink for convenience
sudo ln -sf "$(pwd)/bin/byn" /usr/local/bin/byn

# Or copy
sudo cp bin/byn /usr/local/bin/byn

# Or add to PATH for this shell
export PATH="$(pwd)/bin:$PATH"
```

Then `hash -r` (or open a new shell) so zsh picks up the new path.

---

## TOML parse error in `.byn`

```
$ byn list
Error: /Users/you/proj/.byn: parse: ...
```

The strict parser fails on:
- Syntax errors (unbalanced quotes, missing `]`, etc.)
- **Unknown keys** at the top level or inside `[scope]`
- Anything that's not exactly `[scope] { vault?, project?, env? }`

**Fix:** match the format in
[`.byn` file format](byn-file-format.md). Common gotchas:

- Outer keys (other than `[scope]`) are not allowed yet.
- Empty `.byn` is not a parse error — it's a stop marker.
- `vault = ""` is the same as omitting `vault` entirely.

---

## Daemon won't stop

`byn daemon stop` should be instant. If it hangs:

1. Check `daemon.log` for a stuck shutdown.
2. As a last resort: `kill $(cat ~/.byn/daemon.pid)`. SIGTERM
   triggers the same shutdown path. Use `kill -9` only if SIGTERM
   has been ignored for a minute+.

---

## `byn exec -- COMMAND` runs the wrong command

```
$ byn exec --vault foo -- python app.py    # WRONG — flags after `--` only
$ byn exec -- python app.py --vault foo    # OK — scope from session
```

The `--` separator is critical. **Anything before `--`** belongs to
`byn`; **anything after `--`** is the child's argv.

Common mistakes:
- Forgetting `--`: byn eats the child's flags
- Mixing flags in the child position: `byn exec python --vault foo`
  fails — there's no `--`

---

## Hints aren't showing

```
$ echo s | byn put X
$
```

Hints are suppressed when:
- `BYN_HINTS=0` is set (and `false`/`off`/`no`)
- stderr isn't a TTY (piped, redirected, captured)

Force them by un-redirecting stderr or unsetting the variable:

```sh
unset BYN_HINTS
echo s | byn put X
# → Stored "X" in default/default/default.
```

---

## Audit log file modes unexpectedly permissive

The daemon creates audit files mode 0600. If you see anything else,
something outside byn widened them. Run:

```sh
chmod -R go-rwx ~/.byn/
```

…and audit *how* they got widened (bad umask in shell init, a `cp`
from another machine, etc.).

---

## Related

- [CLI reference](cli-reference.md) — every error code by command.
- [Security model](security.md) — why we use existence-oracle
  responses for `wrong_password` / `not_init`.
- [File layout](file-layout.md) — every file's intended mode +
  recovery procedure.

---

## "operation not permitted" reading a `.byn` — macOS Full Disk Access (TCC)

```
$ byn trust .
  x .../.byn: open .../.byn: operation not permitted
```

or, surfaced through the daemon:

```
Error: open .../.byn: the byn daemon was denied by macOS privacy
protection (TCC). Grant Full Disk Access ...
```

**Cause.** Under privilege separation the daemon runs as the `_byn` service
user via launchd. macOS **TCC** (Transparency, Consent & Control) blocks any
process from reading files in protected folders — **`~/Documents`,
`~/Desktop`, `~/Downloads`, iCloud Drive**, and removable/network volumes —
unless it has **Full Disk Access**. **TCC overrides POSIX permissions and
ACLs**, so this is not something `chmod`/`setfacl` can fix. Your CLI reads the
file fine (it inherits Terminal's access); the daemon, a separate user, does
not. The tell is the errno: **`operation not permitted`** (EPERM = TCC) versus
**`permission denied`** (EACCES = ordinary permissions).

### Option A — keep projects out of the protected folders (recommended, free)

The simplest fix needs no Full Disk Access and no code signing: keep
byn-managed projects **outside** `~/Documents`, `~/Desktop`, `~/Downloads` and
iCloud Drive. Anything under e.g. `~/code`, `~/dev`, `~/src`, `/opt`,
`/Users/Shared` is not TCC-protected, and the daemon reads it normally.

```sh
mkdir -p ~/code
mv ~/Documents/my-project ~/code/my-project
cd ~/code/my-project
byn trust .
```

A symlink does **not** help — TCC checks the real path. Move the real directory.

### Option B — grant the daemon Full Disk Access

Keep projects where they are and authorize the daemon once.

1. Confirm the daemon binary path (the LaunchDaemon's program):
   ```sh
   grep -A1 ProgramArguments /Library/LaunchDaemons/com.sandeepbaynes.byn.plist
   # usually /usr/local/bin/byn
   ```
2. Open **System Settings → Privacy & Security → Full Disk Access**:
   ```sh
   open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
   ```
3. Click **+**. In the file picker press **⌘⇧G**, type `/usr/local/bin/byn`,
   press Return, then **Open**. Toggle the new **byn** entry **on**.
4. Restart the daemon so it picks up the grant:
   ```sh
   sudo launchctl kickstart -k system/com.sandeepbaynes.byn
   ```
5. Verify (no password needed) against any already-trusted `.byn`:
   ```sh
   byn trust diff /path/to/a/trusted/.byn
   # success (a diff or "no changes") = the daemon can read it
   ```

### Make the Full Disk Access grant survive reinstalls (optional, free)

byn ships **ad-hoc signed** (Go's default), so TCC ties the grant to that exact
build — after `make install` of a new build you must re-grant. To make it
persist, sign the binary with a **stable identity**. A **free** Apple ID is
enough; you do **not** need the paid Developer Program for your own machine.

1. Add your Apple ID in **Xcode → Settings → Accounts** (creates a free
   "Personal Team" and an **Apple Development** certificate in your login
   keychain). Xcode or the Command Line Tools must be installed.
2. Find the signing identity:
   ```sh
   security find-identity -v -p codesigning
   # e.g. "Apple Development: you@example.com (TEAMID1234)"
   ```
3. Install **and sign in one step** (the Makefile signs when `CODESIGN_IDENTITY`
   is set, using stable identifiers so the grant persists):
   ```sh
   sudo make install CODESIGN_IDENTITY="Apple Development: you@example.com (TEAMID1234)"
   ```
   Or sign an already-installed binary by hand (keep the `--identifier` constant
   across rebuilds — TCC keys on identifier + identity):
   ```sh
   sudo codesign --force --identifier com.sandeepbaynes.byn \
     --sign "Apple Development: you@example.com (TEAMID1234)" /usr/local/bin/byn
   sudo codesign --force --identifier com.sandeepbaynes.byn-exec-helper \
     --sign "Apple Development: you@example.com (TEAMID1234)" /usr/local/bin/byn-exec-helper
   ```
4. Re-add `/usr/local/bin/byn` to Full Disk Access **once** (the identity changed
   from ad-hoc), then restart the daemon. Every later reinstall signed with the
   same identity keeps the grant.

### Distributing byn to other Macs (your team)

A free Apple ID development certificate works on **your** machine but is not
valid on other people's Macs — Gatekeeper blocks it and FDA can't be attributed.
To ship byn to a team you need the **paid Apple Developer Program** ($99/yr) for
a **Developer ID Application** certificate plus **notarization**, after which the
binary runs cleanly and Full Disk Access can be pre-granted fleet-wide via an MDM
PPPC configuration profile. Until then, tell your team to use **Option A** —
projects outside the protected folders — which needs no signing at all.

---

## Running `byn exec` under privsep (toolchain, TMPDIR, debugging)

By default `byn exec` runs the child as the `_byn-exec` service user, so the
injected secrets are hidden from your own `ps -E`. Because the child is a
**different UID** than you, it needs filesystem access to what your toolchain
reads and writes — `byn trust` grants that for the *project*, but not for tools
installed in your home. Symptoms and fixes:

### `Permission denied` (EACCES) running a tool — toolchain not reachable

```
sandbox-exec: execvp() of '.../.nvm/.../bin/pnpm' failed: Permission denied
```

This is **POSIX**, not TCC (`Permission denied`/EACCES, not `Operation not
permitted`/EPERM). The `_byn-exec` child can't traverse/read the dir the tool
lives in. `byn trust` already grants `_byn-exec` *traverse* on your home and the
project, so a world-readable toolchain (e.g. nvm's `~/.nvm`, mode `0755`) works
for free. If the toolchain or its state is in a **`0700`** dir (common on macOS,
e.g. `~/Library`), grant the child access there once:

```sh
# Example: pnpm keeps state under macOS's 0700 ~/Library
chmod +a "_byn-exec allow execute,search" ~/Library
chmod +a "_byn-exec allow read,write,execute,delete,add_file,add_subdirectory,file_inherit,directory_inherit" ~/Library/pnpm
```

`execute,search` is *traverse only* (not list/read) — the child passes through to
the dir you grant, it can't enumerate the parent. This is the same kind of ACE
`byn trust` adds for your project; re-running `byn trust .` re-applies the project
+ home-traverse ACEs if they get cleared.

> **Why this is safe:** running a tool as `_byn-exec` is *more* confined than the
> baseline — normally `make dev` runs it as **you**, with full home access.
> Privsep's value is hiding the injected secrets from same-user snooping, not
> sandboxing the toolchain. Granting `_byn-exec` read access to your dev
> environment is therefore not a new exposure.

### `EACCES … mkdir '/var/folders/…/T/…'` — `TMPDIR`

Your `$TMPDIR` points at a uid-private folder (`0700`) the child can't write. byn
**auto-normalizes** `TMPDIR`/`TMP`/`TEMP` for the child to a writable location, so
this is handled automatically on a current build. On an older build, prefix the
run with `TMPDIR=/tmp`.

### Debugging — the debugger can't attach to a privsep child

A debugger running as **you** cannot attach to a **different-UID** (`_byn-exec`)
process: macOS/Linux restrict `ptrace`/`task_for_pid` to the same UID. That's the
*same* rule that hides the env from your `ps -E`. Two ways to debug:

- **`byn exec --no-privsep -- …`** runs the child **as you**, so a launch-mode
  debugger (VS Code "launch") attaches normally. Secrets are still injected, but
  the env is visible to your own `ps -E`, so this mode **requires the master
  password every run** (no blind trusted-file run). Best for interactive
  step-debugging — you're at the machine, so a password per run is fine.
- **`byn exec --inspect[=PORT] -- …`** (or `--inspect PORT`) keeps privsep (env
  hidden) and enables the Node inspector. Your editor **attaches** over loopback
  TCP (UID-agnostic). With no PORT byn picks the next free port (printed); an
  explicit PORT is used only if free, otherwise byn fails clearly (not a buried
  `EADDRINUSE`); `--inspect=0` lets each node self-allocate (for multi-process
  runners like `tsx watch`). Configure the editor as an **attach** target, not launch.

See `byn exec help` for the full mode comparison.
