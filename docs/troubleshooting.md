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
