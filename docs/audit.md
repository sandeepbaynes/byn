# Audit log

Every byn vault keeps an **append-only, tamper-evident audit log**: a record of
every operation that touched it — secrets read, written, deleted, every `exec`
credential injection (allowed *or* denied), every lock/unlock, every config
change. The log is the answer to *"what happened, when, and who did it?"* after
the fact, and — because it is cryptographically chained — it also answers *"has
anyone quietly altered that record?"*

This page explains why the log exists, how its integrity guarantee works, and
how to read, search, paginate, and (when a crash leaves a gap) repair it.

---

## Why it exists

A secrets vault is only trustworthy if its history is trustworthy. Three goals:

1. **Forensics.** If a credential leaks, you need to know which process read it,
   from which terminal/portal, under which `.byn`, and when. byn records the
   caller's UID, PID, process name, and parent process for every event.
2. **Accountability for `exec`.** The whole point of the shim/`exec` model is
   that byn — not the agent — injects credentials. Each injection is logged with
   the exact command line and the authorizing `.byn` file, so a `.byn`-driven run
   is fully traceable.
3. **Tamper evidence.** An attacker who gains file access could try to *erase*
   their tracks by editing or truncating the log. byn makes that detectable: the
   log is an HMAC hash-chain, so any deletion, reordering, or edit breaks
   verification at the first altered event.

The log is **metadata, not secrets** — it stores entry *names*, scopes, ops,
and outcomes, never secret *values*. So reading it does not require the vault to
be unlocked.

---

## What's recorded

One JSON line per event, under `<data-dir>/audit/<vault>/YYYY-MM.log` (rolled
monthly, mode `0600`). Each event carries:

| Field | Meaning |
|---|---|
| `#N` (index) | the event's **global chain position** (0-based), shown as `#N` |
| `ts` | timestamp (UTC) |
| `op` | the operation — `put`, `get`, `delete`, `exec`, `vault.lock`, … |
| `outcome` | `ok` / `denied` / `not_found` / `error` |
| scope | `project[/env]` the op touched |
| entry / command | the entry name, or — for an `exec` injection — the command line |
| `byn_path` | the authorizing `.byn` file for an `exec` injection |
| caller | surface (`socket` = CLI/TUI, `portal` = browser), process name, pid, uid, parent process |

The `#N` index is the same number `verify` and `reseal` report and the same
number you paginate by — so a break "at event #681" lines up exactly with the
`#681` row in the log.

---

## How the tamper evidence works

Each event stores an `hmac_chain` value:

```
hmac_chain(N) = HMAC-SHA256(seed, hmac_chain(N-1) || event_bytes(N))
```

Because every entry depends on the one before it, the chain has the properties
you want from tamper evidence:

- **Insert a forged event** → its (and every later) HMAC no longer matches.
- **Delete or reorder an event** → the next event references a previous hash the
  verifier can't reproduce → a break at that point.
- **Truncate the file** → the in-DB chain head points at a value not on disk.

Run a full re-walk any time:

```sh
byn audit verify            # exit 0 "chain intact — N events verified"
                            # exit 3 "BROKEN at event #M" if any link fails
```

`byn doctor` runs the same check per vault (`vault[X].audit`).

### Threat model — what the chain does and does not protect

The chain **seed lives in the vault's *unencrypted* meta table** (which is why
`verify`/`tail` work while locked). The consequence is important to state plainly:

- The log protects against tampering by anyone **without raw file access** —
  e.g. detecting after-the-fact corruption, or a confined process that can only
  talk to the daemon.
- Anyone with **file access and the seed** could rewrite the whole log. So the
  audit log's integrity floor is *file-system access control*, **not** the master
  password. (If you need a stronger guarantee, that is the lever to change:
  moving the seed under the vault key.)

---

## Chain breaks and `reseal`

A break does **not** always mean tampering. The most common cause is benign: a
daemon **crash or SIGTERM mid-write**. byn writes the on-disk log line first,
then advances the chain head; a process kill in that window leaves the head one
entry behind, so the *next* event after restart chains from a stale head and
verification breaks at exactly that point.

byn handles this in two layers:

1. **Self-healing on restart.** When the audit logger starts, it reconciles its
   chain head against the last on-disk line. A clean crash now repairs itself —
   the next event chains correctly, no break is created.
2. **Deliberate `reseal` for an existing break.** If a break already exists (e.g.
   from before the self-heal, or after many forced restarts), the owner can
   **acknowledge** it without erasing anything:

   ```sh
   byn unlock                  # reseal is a deliberate, unlocked owner action
   byn audit reseal            # shows the break, asks for a reason, confirms
   ```

   This appends a **signed bridge marker** — it records the break index, the
   observed vs expected heads, a free-text reason, and who/when. The original
   hashes are **never rewritten**, so the discontinuity stays visible and
   attributable; `verify` and `doctor` then read the chain as *intact (with an
   acknowledged reseal)*. A marker forged without the seed cannot clear a break.
   For scripting: `byn audit reseal --reason "daemon restart" --yes`.

The design choice — *bridge marker, not re-chain* — is deliberate: rewriting the
hashes forward would make a benign gap and a real tamper indistinguishable. The
marker keeps every acknowledged gap honest.

---

## Reading the log

```sh
byn audit tail              # last 10 events (like tail(1)); -n N for more
byn audit tail -f           # follow new events live (Ctrl-C to stop)
byn audit view --lines 0    # the WHOLE log, oldest-first
```

Each row is prefixed with its `#N` index and ends with the caller, e.g.:

```
#681   2026-06-02 12:34:56Z  get   monorepo/prod  DB_URL   ok   socket:byn(pid 9123, uid 501)←node
```

`--json` emits a single JSON array (NDJSON when following with `-f`), so
`byn audit tail --json | jq …` works like every other `--json` command.

---

## Searching: filter by `.byn`, caller, or scope

Filters run **server-side across the whole log**, so a match is found even when
it predates the recent window:

```sh
byn audit view --scope monorepo/prod      # only events in that project/env
byn audit view --byn ~/code/app/.byn      # only injections authorized by a .byn
byn audit view --caller node              # only events whose caller matches
```

All three are case-insensitive substring matches and combine (AND). The same
filters exist in the TUI (`/`) and the web portal's filter bar.

---

## Pagination: by stable index, never by offset

A long-lived vault can hold tens of thousands of events — more than fits in a
single IPC response. byn pages the log, and it pages by the **stable `#N` chain
index**, not a positional offset.

This matters because the log **grows**. A positional offset ("skip the last 200")
shifts every time a new event is appended, so paging by offset can silently skip
or repeat rows. A `#N` index is **immutable** — event #681 is always #681 — so a
cursor keyed on it stays correct as the log grows underneath you.

**Forward — consume new events (for programs/automation):**

```sh
byn audit view --since 8100 --json
```

Returns every event with `#N` greater than `8100`, oldest-first. A consumer
tracks the highest `#N` it has processed and re-queries `--since <that>` to pick
up only what's new — never missing or double-counting an event, even while the
log is actively being written.

**Backward — browse older history:**

```sh
byn audit view --before 200        # the page of events just below #200
```

Pass the smallest `#N` you received as the next `--before` to page further back.
`--lines 0` does this automatically to assemble the entire log.

**In the apps:**

- **TUI** (`byn` → `ga` for the full audit view): `]` / PageDown freezes on an
  older page (pausing the live refresh); `[` / PageUp returns to the live newest.
  The footer shows `live` vs `frozen below #N`.
- **Web portal** (Audit): a **Load older** button pages back through the whole
  log; the filter bar narrows server-side.

---

## See also

- [CLI reference → audit](cli-reference.md#byn-audit-tail--n-n--f---json) — every flag.
- [Security model](security.md) — where the audit log sits in byn's threat model.
- [File layout](file-layout.md) — where the log lives on disk.
